use crate::constants::*;
use crate::external::mongo::{create_index_mongodb_custom, create_index_mongodb_partition, get_symmetric_keys};
use crate::external::mq::{emit_certificate, init_symmetric_queues, QUEUE_SYMMETRIC_GETKEYS, QUEUE_SYMMETRIC_CERTIFICATES};
use crate::flow::maintenance::validate_ticker;
use crate::maitredescles_commun::{ErreurPermissionRechiffrage, ErrorPermissionRefusee};
use crate::maitredescles_rechiffrage::HandlerCleRechiffrage;
use crate::models::{ErrorMessage, KeyDecryptionRefused};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::Timelike;
use millegrilles_common_rust::common_messages::{ReponseRequeteDechiffrageV2, RequeteDechiffrage, ResponseRequestDechiffrageV2Cle};
use millegrilles_common_rust::constantes::{Securite, COMMANDE_CERT_MAITREDESCLES, DELEGATION_GLOBALE_PROPRIETAIRE, REQUETE_CERT_MAITREDESCLES};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::futures::StreamExt;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_common_rust::mongo_dao::{MongoDaoImpl, MongoDaoTyped};
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::tokio::task::JoinSet;
use millegrilles_common_rust::tracing::{debug, error, info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::{MessageInboundValidator, MessageValidated};
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::impls::rabbitmq_consumer::DeliveryInfo;
use millegrilles_common_rust::v3::{ConfigService, PkiService};
use std::sync::Arc;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageKind;

#[async_trait]
pub trait MaitreDesClesSymmetricService {}

pub struct MaitreDesClesSymmetricServiceImpl {
    config: Arc<dyn ConfigService>,
    outbound: Arc<MessageOutboundFacade>,
    pki: Arc<dyn PkiService>,
    mongo: Arc<MongoDaoImpl>,
    decryption: Arc<HandlerCleRechiffrage>,
}

impl MaitreDesClesSymmetricServiceImpl {
    pub fn new(
        config: Arc<dyn ConfigService>,
        outbound: Arc<MessageOutboundFacade>,
        pki: Arc<dyn PkiService>,
        mongo: Arc<MongoDaoImpl>,
        decryption: Arc<HandlerCleRechiffrage>,
    ) -> Self {
        Self { config: config, outbound, pki, mongo, decryption }
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
        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_certificate_thread(incoming_clone).await});

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
                    if let Err(e) = ticker_job_symmetric(
                        self.outbound.as_ref(),
                        self.config.as_ref(),
                        self.mongo.as_ref(),
                        self.decryption.as_ref(),
                        message
                    ).await {
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
                    if let Err(e) = get_keys(
                        self.pki.as_ref(),
                        self.outbound.as_ref(),
                        self.decryption.as_ref(),
                        self.mongo.as_ref(),
                        message
                    ).await {
                        error!("process_getkeys_thread failed: {}", e);
                    }
                }
                Err(e) => {
                    warn!("process_getkeys_thread Error processing  message: {}", e);
                }
            }
        }
    }

    async fn process_certificate_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_SYMMETRIC_CERTIFICATES).as_str()
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = process_certificate_message(self.outbound.as_ref(), message).await
                    {
                        error!("Error processing certificate message: {}", e);
                    }
                }
                Err(e) => {
                    warn!("process_getkeys_thread Error processing  message: {}", e);
                }
            }
        }
    }

}

impl MaitreDesClesSymmetricService for MaitreDesClesSymmetricServiceImpl {}

async fn ticker_job_symmetric<M>(
    outbound: &MessageOutboundFacade,
    config: &dyn ConfigService,
    mongo: &M,
    decryption: &HandlerCleRechiffrage,
    trigger: MessageValidated,
) -> Result<(), CommonError>
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

    if minute % 2 == 0 {
        if let Err(e) = emit_certificate(outbound, decryption).await {
            error!("Failed to emit certificate: {}", e);
        }
    }

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

async fn decrypt_keys_v2<M>(
    pki: &dyn PkiService,
    outbound: &MessageOutboundFacade,
    mongo: &M,
    decryption: &HandlerCleRechiffrage,
    requete: RequeteDechiffrage,
    delivery_info: DeliveryInfo,
    certificate: Arc<EnveloppeCertificat>
) -> Result<(Option<Vec<ResponseRequestDechiffrageV2Cle>>, Arc<EnveloppeCertificat>), CommonError> where M: MongoDaoTyped {
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

    // Support old key request format to recover key_ids
    let requested_key_ids = match requete.cle_ids {
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
        &requested_key_ids,
        requete.domaine.as_str(),
        Some(true) == requete.inclure_signature,
    ).await?;

    if keys.is_empty() {
        Ok((None, certificat))
    } else {
        Ok((Some(keys), certificat))
    }
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

/// Tasks to run once on initialisation
pub async fn symmetric_init_tasks(outbound: &MessageOutboundFacade, decryption: &HandlerCleRechiffrage) {
    if let Err(e) = emit_certificate(&outbound, &decryption).await {
        error!("Error on initial emission of certificate : {:?}", e);
    }
}
async fn process_certificate_message(outbound: &MessageOutboundFacade, message: MessageValidated) -> Result<(), CommonError> {
    let routage = match message.message.routage {
        Some(routage) => routage,
        None => return Err(CommonError::Str("Routing information absent from message"))
    };
    let action = match routage.action.as_ref() {
        Some(action) => action.as_str(),
        None => return Err(CommonError::Str("Routing action absent from message"))
    };

    match message.message.kind {
        MessageKind::Evenement => {
            match action {
                REQUETE_CERT_MAITREDESCLES => {
                    let certificate = message.certificate;
                    if certificate.verifier_exchanges(
                        vec![Securite::L4Secure])? &&
                        certificate.verifier_domaines(vec![DOMAINE_NOM.to_string()])?
                    {
                        // A valide KeyMaster certificate that is published. Ignore it for now.
                        debug!("Reception of KeyMaster certificate");
                    } else {
                        debug!("Reception of invalid KeyMaster certificate (bad role or security)");
                    }
                    Ok(())
                },
                _ => Err(CommonError::String(format!("Unsupported event action: {}", action)))
            }
        },
        MessageKind::Requete => {
            match action {
                REQUETE_CERT_MAITREDESCLES => {
                    // This is about getting a KeyMaster certificate (any will do).
                    // We can just reply. The current certificate will be attached, it fits the job.
                    debug!("Replying with KeyMaster certificate");
                    outbound.respond(
                        message.delivery_info,
                        ErrorMessage { ok: true, code: None, err: None }
                    ).await
                },
                _ => Err(CommonError::String(format!("Unsupported request action: {}", action)))
            }
        },
        _ => Err(CommonError::Str("Unsupported message type"))
    }
}
