use crate::constants::*;
use crate::external::mongo::{create_index_mongodb_custom, create_index_mongodb_partition, get_symmetric_keys};
use crate::external::mq::{QUEUE_SYMMETRIC_GETKEYS, init_symmetric_queues};
use crate::flow::maintenance::validate_ticker;
use crate::maitredescles_commun::{ErreurPermissionRechiffrage, ErrorPermissionRefusee};
use crate::maitredescles_rechiffrage::HandlerCleRechiffrage;
use crate::models::{ErrorMessage, KeyDecryptionRefused};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Timelike;
use millegrilles_common_rust::common_messages::{ReponseRequeteDechiffrageV2, RequeteDechiffrage, ResponseRequestDechiffrageV2Cle};
use millegrilles_common_rust::constantes::DELEGATION_GLOBALE_PROPRIETAIRE;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::error::Error::ErrorResponse;
use millegrilles_common_rust::futures::StreamExt;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoImpl, MongoDaoTyped};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::tokio::task::JoinSet;
use millegrilles_common_rust::tracing::{debug, error, info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::{MessageInboundValidator, MessageValidated};
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::impls::rabbitmq_consumer::DeliveryInfo;
use millegrilles_common_rust::v3::impls::security_service::SecurityServiceImpl;
use millegrilles_common_rust::v3::{ConfigService, PkiService};
use std::sync::Arc;

#[async_trait]
pub trait MaitreDesClesSymmetricService {}

pub struct MaitreDesClesSymmetricServiceImpl {
    _config: Arc<dyn ConfigService>,
    _outgoing: Arc<MessageOutboundFacade>,
    mongo: Arc<MongoDaoImpl>,
    decryption: Arc<HandlerCleRechiffrage>,
}

impl MaitreDesClesSymmetricServiceImpl {
    pub fn new(
        config: Arc<dyn ConfigService>,
        outgoing: Arc<MessageOutboundFacade>,
        mongo: Arc<MongoDaoImpl>,
        decryption: Arc<HandlerCleRechiffrage>,
    ) -> Self {
        Self { _config: config, _outgoing: outgoing, mongo, decryption }
    }

    pub async fn configure(&self, mq: &MessagingServiceImpl, config: &ConfigServiceDbImpl) -> Result<(), CommonError> {
        init_symmetric_queues(mq)?;
        create_index_mongodb_custom(self.mongo.as_ref(), config.config.as_ref(), NOM_COLLECTION_SYMMETRIQUE_CLES).await?;
        create_index_mongodb_partition(self.mongo.as_ref(), config.config.as_ref()).await?;
        Ok(())
    }

    pub fn start(self: Arc<Self>, join_set: &mut JoinSet<()>, incoming: Arc<MessageInboundValidator>) -> Result<(), CommonError> {

        // Ticker jobs
        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_ticker_thread(incoming_clone).await});

        // Symmetric queues
        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_getkeys_thread(incoming_clone).await});

        // todo!()
        Ok(())
    }

    async fn process_ticker_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/symmetric/job_ticker", DOMAINE_NOM).as_str()
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    let mongo = self.mongo.as_ref();
                    if let Err(e) = ticker_job_symmetric(mongo, message).await {
                        error!("Ticker job symmetric failed: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Error processing ticker message: {}", e);
                }
            }
        }
    }

    async fn process_getkeys_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_SYMMETRIC_GETKEYS).as_str()
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    let mongo = self.mongo.as_ref();
                    if let Err(e) = ticker_job_symmetric(mongo, message).await {
                        error!("process_getkeys_thread failed: {}", e);
                    }
                }
                Err(e) => {
                    warn!("process_getkeys_thread Error processing  message: {}", e);
                }
            }
        }
    }

}

impl MaitreDesClesSymmetricService for MaitreDesClesSymmetricServiceImpl {
}

async fn ticker_job_symmetric<M>(mongo: &M, trigger: MessageValidated) -> Result<(), CommonError>
where M: MongoDaoTyped
{
    // Ensure this is an authorized module
    if let Err(e) = validate_ticker(&trigger).await {
        error!("Invalid ticker message, rejecting: {}", e);
        return Ok(());
    }

    let trigger_value: MessageCedule = trigger.message.deserialize()?;

    let hour = trigger_value.get_date().hour();
    let minute = trigger_value.get_date().minute();

    debug!("ticker_job_symmetric for h:{} m:{}",hour,minute);

    Ok(())
}

async fn get_keys<M>(
    pki: &dyn PkiService,
    outbound: &MessageOutboundFacade,
    decryption: &HandlerCleRechiffrage,
    mongo: &M,
    message: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let request: RequeteDechiffrage = match message.message.deserialize() {
        Ok(inner) => inner,
        Err(e) => {
            info!("get_keys Error mapping to RequeteDechiffrage : {:?}", e);
            outbound.respond(
                message.delivery_info,
                ErrorMessage { ok: false, code: None, err: Some("Invalid message format".to_string()) }
            ).await?;
            return Ok(());
        }
    };

    let (cles, certificate) = match decrypt_keys_v2(
        pki,
        outbound,
        mongo,
        decryption,
        request,
        message.delivery_info.clone(),
        message.certificate.clone(),
    ).await {
        Ok(keys) => keys,
        Err(e) => {
            let error_response = ErrorMessage {
                ok: false,
                code: None,
                err: Some(format!("Error: {:?}", e)),
            };
            outbound.respond(message.delivery_info, error_response).await?;
            return Ok(());
        }
    };

    let response = match cles {
        Some(cles) => {
            ReponseRequeteDechiffrageV2 { ok: true, code: 1, cles: Some(cles), err: None }
        },
        None => {
            ReponseRequeteDechiffrageV2 { ok: false, code: 4, cles: None, err: Some("Unknown keys".to_string()) }
        }
    };
    outbound.respond_encrypted(message.delivery_info, response, certificate.as_ref()).await
}

pub async fn decrypt_keys_v2<M>(
    pki: &dyn PkiService,
    outbound: &MessageOutboundFacade,
    mongo: &M,
    decryption: &HandlerCleRechiffrage,
    requete: RequeteDechiffrage,
    delivery_info: DeliveryInfo,
    certificate: Arc<EnveloppeCertificat>
) -> Result<(Option<Vec<ResponseRequestDechiffrageV2Cle>>, Arc<EnveloppeCertificat>), CommonError> where M: MongoDaoTyped {
    let inclure_signature = Some(true) == requete.inclure_signature;

    // Supporter l'ancien format de requete (liste_hachage_bytes) avec le nouveau (cle_ids)
    let cle_ids = match requete.cle_ids.as_ref() {
        Some(inner) => inner,
        None => match requete.liste_hachage_bytes.as_ref() {
            Some(inner) => inner,
            None => Err(CommonError::Str("Aucunes cles demandees pour le rechiffrage"))?
        }
    };

    // Verifier que la requete est autorisee
    let certificat = match check_key_decryption_request(pki, &requete, certificate.clone()).await {
        Ok((certificate, _)) => certificate,
        Err(ErreurPermissionRechiffrage::Refuse(e)) => {
            let error_message = format!("Access denied: {:?}", e);
            let access_denied = KeyDecryptionRefused { ok: false, code: Some(e.code), err: Some(e.err), acces: None };
            outbound.respond(delivery_info, access_denied).await?;
            return Err(CommonError::String(error_message));
        },
        Err(ErreurPermissionRechiffrage::Error(e)) => return Err(e)
    };

    // Recuperer les cles et dechiffrer
    let requete_cle_ids = match requete.cle_ids {
        Some(inner) => inner,
        None => match requete.liste_hachage_bytes {
            Some(inner) => inner,
            None => {
                return Err(CommonError::Str("requete_dechiffrage_v2 requete sans cle_ids ni liste_hachage_bytes"));
            }
        }
    };

    let keys = get_symmetric_keys(
        mongo,
        decryption,
        &requete_cle_ids,
        requete.domaine.as_str(),
        Some(true) == requete.inclure_signature,
    ).await?;

    if keys.is_empty() {
        Ok((None, certificat))
    } else {
        Ok((Some(keys), certificat))
    }

    // let mut cles: Vec<ResponseRequestDechiffrageV2Cle> = Vec::new();
    //
    // let nom_collection = NOM_COLLECTION_SYMMETRIQUE_CLES;
    //
    // let requete_cle_ids = match requete.cle_ids.as_ref() {
    //     Some(inner) => inner,
    //     None => match requete.liste_hachage_bytes.as_ref() {
    //         Some(inner) => inner,
    //         None => {
    //             info!("requete_dechiffrage_v2 requete sans cle_ids ni liste_hachage_bytes");
    //             return Ok(Some(middleware.reponse_err(1, None, Some("Requete sans cle_ids ni liste_hachage_bytes"))?))
    //         }
    //     }
    // };
    //
    // let filtre = doc! {
    //     CHAMP_CLE_ID: {"$in": requete_cle_ids},
    //     // "signature.domaines": {"$in": vec![&requete.domaine]}
    // };
    // // filtre.insert("signature.domaines", doc!{"$in": vec![&requete.domaine]});
    // let collection = middleware.get_collection_typed::<RowClePartition>(nom_collection)?;
    // let mut curseur = collection.find_with_session(filtre, None, session).await?;
    // let domaine: heapless::String<40> = requete.domaine.as_str().try_into()
    //     .map_err(|_| Error::Str("Erreur map domain dans heapless::String<40>"))?;
    //
    // // Compter les cles trouvees separement de la liste. On rejete des cles qui ont un mismatch de domaine
    // // mais elles comptent sur le total trouve.
    // let mut cles_trouvees = 0;
    //
    // while let Some(row) = curseur.next(session).await {
    //     match row {
    //         Ok(inner) => {
    //             cles_trouvees += 1;
    //             if inner.signature.domaines.contains(&domaine) {
    //                 let signature = inner.signature.clone();
    //                 match inner.to_cle_secrete_serialisee(handler_rechiffrage) {
    //                     Ok(inner) => {
    //                         let mut cle: ResponseRequestDechiffrageV2Cle = inner.into();
    //                         if inclure_signature { cle.signature = Some(signature); }
    //                         cles.push(cle);
    //                     },
    //                     Err(e) => {
    //                         warn!("Erreur mapping / dechiffrage cle - SKIP : {:?}", e);
    //                         continue
    //                     }
    //                 }
    //             } else {
    //                 warn!("requete_dechiffrage_v2 Requete de cle rejetee, domaines {:?} ne match pas la cle {}", inner.signature.domaines, inner.cle_id);
    //             }
    //         },
    //         Err(e) => {
    //             warn!("requete_dechiffrage_v2 Erreur mapping cle, SKIP : {:?}", e);
    //             continue
    //         }
    //     }
    // }

    // // Verifier si on a des cles inconnues
    // // En cas de cles inconnues, et si on a plusieurs maitre des cles, faire une requete
    // let nombre_maitre_des_cles = middleware.get_publickeys_chiffrage().len();
    // if cles_trouvees < cle_ids.len() && nombre_maitre_des_cles > 1 {
    //     debug!("requete_dechiffrage_v2 Cles manquantes, on a {} trouvees sur {} demandees", cles.len(), cle_ids.len());
    //
    //     // Identifier les cles manquantes
    //     let mut cles_hashset = HashSet::new();
    //     for item in cle_ids {
    //         cles_hashset.insert(item.as_str());
    //     }
    //     for item in &cles {
    //         if let Some(cle_id) = &item.cle_id {
    //             cles_hashset.remove(cle_id.as_str());
    //         }
    //     }
    //
    //     // Effectuer une requete pour verifier si les cles sont connues d'un autre maitre des cles
    //     let liste_cles: Vec<String> = cles_hashset.iter().map(|m| m.to_string()).collect();
    //     let requete_transfert = RequeteTransfert {
    //         fingerprint,
    //         cle_ids: liste_cles,
    //         toujours_repondre: Some(true),
    //     };
    //     let data_reponse = effectuer_requete_cles_manquantes(
    //         middleware, &requete_transfert).await.unwrap_or_else(|e| {
    //         error!("traiter_batch_synchroniser_cles Erreur requete cles manquantes : {:?}", e);
    //         None
    //     });
    //     if let Some(data_reponse) = data_reponse {
    //         debug!("traiter_batch_synchroniser_cles Recu {}/{} cles suite a requete de cles manquantes",
    //             data_reponse.cles.len(), cles_hashset.len());
    //         for cle in data_reponse.cles {
    //             sauvegarder_cle_transfert(middleware, handler_rechiffrage, &cle, session).await?;
    //         }
    //     }
    // }
    //
    // let reponse = if cles.len() > 0 {
    //     let reponse = ReponseRequeteDechiffrageV2 { ok: true, code: 1, cles: Some(cles), err: None };
    //     middleware.build_reponse_chiffree(reponse, certificat.as_ref())?.0
    // } else {
    //     // On n'a pas trouve de cles
    //     debug!("requete_dechiffrage_v2 Requete {:?} de dechiffrage {:?}, cles inconnues", m.type_message, &cle_ids);
    //
    //     // Retourner cle inconnu a l'usager
    //     let inconnu = json!({"ok": false, "err": "Cles inconnues", "acces": CHAMP_ACCES_CLE_INCONNUE, "code": 4});
    //     let _reponse = ReponseRequeteDechiffrageV2 {
    //         ok: false,
    //         code: 4,
    //         cles: None,
    //         err: Some("Cles inconnues".to_string())
    //     };
    //     middleware.build_reponse(&inconnu)?.0
    // };

}

/// Checks all rules to ensure the key decryption certificate is appropriate
async fn check_key_decryption_request(
    pki: &dyn PkiService,
    requete: &RequeteDechiffrage,
    enveloppe: Arc<EnveloppeCertificat>,
) -> Result<(Arc<EnveloppeCertificat>, bool), ErreurPermissionRechiffrage> {
    debug!("check_key_decryption_request : {:?}", requete);
    let extensions = enveloppe.extensions()?;
    let allowed_domains = extensions.domaines;

    // Find certificate for re-encryption (response)
    let certificate = match requete.certificat_rechiffrage.as_ref() {
        Some(cr) => {
            debug!("check_key_decryption_request Using provided certificate");
            let chain_string = cr.join("\n");
            // Validate provided certificate for current system/now
            pki.validate_pem(chain_string.as_str(), None, None)?
        },
        None => enveloppe.clone()   // Already validated message certificate
    };

    // Verifier si on a une autorisation de dechiffrage global
    let is_admin = if certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        debug!("check_key_decryption_request Admin user certificate - allowed to fetch any keys");
        true
    } else {
        false
    };

    // Reject if not admin and no domains specified
    if !is_admin && allowed_domains.is_none() {
        debug!("check_key_decryption_request Decryption request for {:?} refused", requete.liste_hachage_bytes);
        return Err(ErreurPermissionRechiffrage::Refuse(ErrorPermissionRefusee { code: 0, err: "Autorisation refusee - permission manquante".to_string() }) );
    }

    if let Some(allowed_domains) = allowed_domains {
        // Ensure the that requested domain is in the allowed list
        let mut allowed = false;
        for domain in allowed_domains {
            if requete.domaine.as_str() == domain.as_str() {
                allowed = true;
                break;
            }
        }
        if allowed == false {
            debug!("check_key_decryption_request Decryption request refused, domain is not in the authorised list");
            return Err(ErreurPermissionRechiffrage::Refuse(ErrorPermissionRefusee { code: 0, err: "Autorisation refusee - domaine non autorise".to_string() }) );
        }
    }

    Ok((certificate, is_admin))
}
