use crate::constants::*;
use crate::errors::{ErreurPermissionRechiffrage, ErrorPermissionRefusee};
use crate::external::crypto::SymmetricEncryptionHandler;
use crate::external::mongo::*;
use crate::external::mq::*;
use crate::flow::maintenance::validate_ticker;
use crate::maitredescles_commun::{CommandeCleSymmetrique, CommandeRechiffrerBatchChiffree, CommandeRechiffrerBatchDechiffree};
use crate::models::{DocumentCleRechiffrage, ErrorMessage, KeyDecryptionRefused, RowClePartition};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chiffrage_cle::CommandeAjouterCleDomaine;
use millegrilles_common_rust::chrono::Timelike;
use millegrilles_common_rust::common_messages::{ReponseRequeteDechiffrageV2, RequeteDechiffrage, ResponseRequestDechiffrageV2Cle};
use millegrilles_common_rust::constantes::{DELEGATION_GLOBALE_PROPRIETAIRE, REQUETE_CERT_MAITREDESCLES, Securite};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::futures::StreamExt;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::FormatChiffrage;
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::SignatureDomainesVersion;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageKind;
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoImpl, MongoDaoTyped};
use millegrilles_common_rust::tokio::task::JoinSet;
use millegrilles_common_rust::tracing::{debug, error, info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::{MessageInboundValidator, MessageValidated};
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::impls::rabbitmq_consumer::DeliveryInfo;
use millegrilles_common_rust::v3::{ChiffrageService, ConfigService, PkiService};
use millegrilles_common_rust::{serde_json, tokio};
use std::sync::Arc;

#[async_trait]
pub trait MaitreDesClesSymmetricService {}

pub struct MaitreDesClesSymmetricServiceImpl {
    config: Arc<dyn ConfigService>,
    outbound: Arc<MessageOutboundFacade>,
    pki: Arc<dyn PkiService>,
    chiffrage: Arc<dyn ChiffrageService>,
    mongo: Arc<MongoDaoImpl>,
    decryption: Arc<SymmetricEncryptionHandler>,
}

impl MaitreDesClesSymmetricServiceImpl {
    pub fn new(
        config: Arc<dyn ConfigService>,
        outbound: Arc<MessageOutboundFacade>,
        pki: Arc<dyn PkiService>,
        chiffrage: Arc<dyn ChiffrageService>,
        mongo: Arc<MongoDaoImpl>,
        decryption: Arc<SymmetricEncryptionHandler>,
    ) -> Self {
        Self { config: config, outbound, pki, chiffrage, mongo, decryption }
    }

    pub async fn configure(&self, mq: &MessagingServiceImpl, config: &ConfigServiceDbImpl) -> Result<(), CommonError> {
        init_symmetric_queues(config, mq)?;
        create_index_mongodb_symmetric(self.mongo.as_ref(), config.config.as_ref()).await?;
        Ok(())
    }

    pub fn start(self: Arc<Self>, join_set: &mut JoinSet<()>, incoming: Arc<MessageInboundValidator>) -> Result<(), CommonError> {

        // Ticker jobs
        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_ticker_thread(incoming_clone).await});

        // Symmetric queues

        // Get keys queue
        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_getkeys_thread(incoming_clone).await});

        // Certificate reply queue
        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_certificate_thread(incoming_clone).await});

        // Save new key queue
        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_newkeys_thread(incoming_clone).await});

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_instance_commands_thread(incoming_clone).await});

        Ok(())
    }

    async fn process_ticker_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_SYMMETRIC_JOB_TICKER).as_str()
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = ticker_job_symmetric(
                        self.config.as_ref(),
                        self.mongo.as_ref(),
                        self.outbound.as_ref(),
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

    async fn process_newkeys_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_SYMMETRIC_NEWKEYS).as_str()
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = process_newkeys(
                        self.config.as_ref(),
                        self.decryption.as_ref(),
                        self.mongo.as_ref(),
                        message
                    ).await {
                        error!("process_newkeys_thread (sym) Saving key failed: {}", e);
                        // No reply - the CA is the authority to decide if the key is saved or not
                    }
                }
                Err(e) => {
                    error!("process_newkeys_thread (sym) message parsing failed: {}", e);
                }
            }
        }
        debug!("process_newkeys_thread (sym) Closed");
    }

    async fn process_instance_commands_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let fingerprint = self.config.get_configuration_pki()
            .get_enveloppe_privee()
            .fingerprint()
            .expect("fingerprint");
        let streamer = incoming.consume_named_queue(
            format!("{}/{}/{}", DOMAINE_NOM, QUEUE_SYMMETRIC_COMMANDS, fingerprint).as_str()
        ).expect("Consumer streaming init failed");

        tokio::pin!(streamer);

        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    route_instance_command(
                        self.config.as_ref(),
                        self.outbound.as_ref(),
                        self.mongo.as_ref(),
                        self.chiffrage.as_ref(),
                        self.decryption.as_ref(),
                        message
                    ).await;
                }
                Err(e) => {
                    error!("process_newkeys_thread (sym) message parsing failed: {}", e);
                }
            }
        }
        debug!("process_newkeys_thread (sym) Closed");
    }

}

impl MaitreDesClesSymmetricService for MaitreDesClesSymmetricServiceImpl {}

async fn ticker_job_symmetric(
    config: &dyn ConfigService,
    mongo: &MongoDaoImpl,
    outbound: &MessageOutboundFacade,
    decryption: &SymmetricEncryptionHandler,
    trigger: MessageValidated,
) -> Result<(), CommonError> {
    // Ensure this is an authorized module
    if let Err(e) = validate_ticker(&trigger).await {
        error!("Invalid ticker message, rejecting: {}", e);
        return Ok(());
    }

    let trigger_value: MessageCedule = trigger.message.deserialize()?;

    let hour = trigger_value.get_date().hour();
    let minute = trigger_value.get_date().minute();

    debug!("ticker_job_symmetric for h:{} m:{}",hour,minute);

    if ! decryption.is_ready() {
        // Emit request to decrypt symmetric key (admin with master key) every minute
        emit_ca_symmetric_key(config, mongo, outbound).await;
    }

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
    decryption: &SymmetricEncryptionHandler,
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
    decryption: &SymmetricEncryptionHandler,
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
pub async fn symmetric_init_tasks(
    config: &dyn ConfigService,
    mongo: &MongoDaoImpl,
    outbound: &MessageOutboundFacade,
    decryption: &SymmetricEncryptionHandler
) {
    // Try to load decryption key from mongo
    let enveloppe_privee = config.get_configuration_pki().get_enveloppe_privee();

    match prepare_symmetric_key(mongo, enveloppe_privee.as_ref(), decryption).await {
        Ok(()) => {
            if let Err(e) = emit_certificate(&outbound, &decryption).await {
                error!("Error on initial emission of certificate : {:?}", e);
            }
        },
        Err(e) => {
            // An error here usually means there is no symmetric key available for the certificate
            debug!("Error loading symmetric key : {}", e);
            // Emit request to decrypt symmetric key (admin with master key)
            emit_ca_symmetric_key(config, mongo, outbound).await;
        }
    }
}

async fn emit_ca_symmetric_key(config: &dyn ConfigService, mongo: &MongoDaoImpl, outbound: &MessageOutboundFacade) {
    // Fetch the symmetric key to have the CA decrypt it (admin in Coup D'Oeil)
    match get_symmetric_ca_key(mongo).await {
        Ok(Some(ca_key)) => {
            if let Err(e) = emit_local_symmetric_key_decryption_request(
                config,
                outbound,
                ca_key.cle.as_str(),
            ).await {
                error!("Error on emit_local_symmetric_key_decryption_request: {:?}", e);
            }
        },
        Ok(None) => {
            // This must not happen, logic flaw in prepare_symmetric_key
            panic!("prepare_symmetric_key No CA encrypted symmetric key found");
        },
        Err(e) => {
            error!("Error in get_symmetric_ca_key symmetric key : {}", e);
        }
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

async fn process_newkeys(
    config: &dyn ConfigService,
    handler_rechiffrage: &SymmetricEncryptionHandler,
    mongo: &dyn MongoDao,
    wrapper: MessageValidated
) -> Result<(), CommonError> {
    // Parse to validate and check for duplicates
    let command: CommandeAjouterCleDomaine = wrapper.message.deserialize()?;

    // Decrypt the key
    let enveloppe_signature = config.get_configuration_pki().get_enveloppe_privee();
    let cle_secrete = command.get_cle_secrete(enveloppe_signature.as_ref())?;
    let cle_rechiffree = handler_rechiffrage.encrypt(&cle_secrete.0)?;

    // Save the key (volatile data, the redo-log is handled by the CA)
    save_symmetric_key(mongo, command.signature, cle_rechiffree).await?;

    // Do not send response - the CA handles the reply (it is the authority for keys)
    Ok(())
}

async fn route_instance_command(
    config: &dyn ConfigService,
    outbound: &MessageOutboundFacade,
    mongo: &MongoDaoImpl,
    chiffrage: &dyn ChiffrageService,
    decryption: &SymmetricEncryptionHandler,
    message: MessageValidated
) {
    let action = match message.message.routage.as_ref() {
        Some(routage) => match routage.action.as_ref() {
            Some(action) => action.clone(),
            None => {
                // Bad message, no action
                return
            }
        },
        None => {
            // Bad message, no routing
            return
        }
    };

    let result = match action.as_str() {
        COMMANDE_CLE_SYMMETRIQUE => repair_symmetric_key(config, outbound, decryption, mongo, message).await,
        COMMANDE_RECHIFFRER_BATCH => save_key_batch(chiffrage, decryption, outbound, mongo, message).await,
        _ => {
            warn!("process_newkeys_thread Unsupported action type: {}", action);
            return
        }
    };

    if let Err(e) = result {
        error!("process_newkeys_thread Error: {:?}", e);
    }
}

/// This uses a command from Coup D'Oeil to set the symmetric key from a CA re-encrypted version
async fn repair_symmetric_key(
    config: &dyn ConfigService,
    outbound: &MessageOutboundFacade,
    decryption: &SymmetricEncryptionHandler,
    mongo: &dyn MongoDao,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    let private_key = config.get_configuration_pki().get_enveloppe_privee();
    let local_fingerprint = private_key.fingerprint()?;
    let instance_id = private_key.enveloppe_pub.get_common_name()?;

    let command: CommandeCleSymmetrique = wrapper.message.deserialize()?;

    if command.fingerprint != local_fingerprint {
        warn!("repair_symmetric_key Fingerprint mismatch, key rejected");
        outbound.respond(wrapper.delivery_info, ErrorMessage {
            ok: false,
            code: Some(1),
            err: Some("Fingerprint mismatch, key rejected".to_string())
        }).await?;
        return Ok(());
    }

    // This will decrypt and set the key in memory - if it fails, the key is wrong
    if let Err(e) = decryption.set_key(command.cle.as_str()) {
        warn!("repair_symmetric_key Key rejected by decryption engine : {:?}", e);
        outbound.respond(wrapper.delivery_info, ErrorMessage {
            ok: false,
            code: Some(2),
            err: Some("key mismatch, rejected by decryption engine".to_string())
        }).await?;
        return Ok(())
    }

    // The key is good, save it.
    let mut keys = Vec::new();
    keys.push(DocumentCleRechiffrage {
        type_: KEY_LOCAL.to_string(),
        instance_id: instance_id.to_string(),
        fingerprint: Some(local_fingerprint.clone()),
        cle: command.cle,
    });

    if let Err(e) = save_symmetric_keys(mongo, None, keys).await {
        error!("repair_symmetric_key Error saving key: {:?}", e);
        outbound.respond(wrapper.delivery_info, ErrorMessage {
            ok: false,
            code: Some(500),
            err: Some(format!("Generic error: {:?}", e))
        }).await?;
        return Ok(())
    }

    // Respond ok
    outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await?;

    Ok(())
}

async fn save_key_batch(
    chiffrage: &dyn ChiffrageService,
    decryption: &SymmetricEncryptionHandler,
    outbound: &MessageOutboundFacade,
    mongo: &dyn MongoDao,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    let command: CommandeRechiffrerBatchChiffree = wrapper.message.deserialize()?;
    let decrypted_batch: CommandeRechiffrerBatchDechiffree = serde_json::from_value(
        chiffrage.decrypt_document(command.cles)?
    )?;

    // Map keys to database struct
    let mut key_ids = Vec::with_capacity(decrypted_batch.cles.len());
    let mut keys = Vec::with_capacity(decrypted_batch.cles.len());
    for (_key_id, key) in decrypted_batch.cles {
        // Encrypt key
        let (key_id, cle_rechiffree) = key.rechiffrer_cle(decryption)?;

        key_ids.push(key_id.clone());

        let mut row = RowClePartition {
            cle_id: key_id,
            signature: key.signature.clone(),
            cle_symmetrique: Some(cle_rechiffree.cle),
            nonce_symmetrique: Some(cle_rechiffree.nonce),
            // Deprecated fields
            format: None,
            iv: None,
            tag: None,
            header: None,
            // The batch was decrypted from the CA list of keys
            // confirmation_ca: Some(true),
        };

        // Copy deprecated values when applicable
        match key.signature.version {
            SignatureDomainesVersion::NonSigne => {
                // set_on_insert.insert(CHAMP_HACHAGE_BYTES, cle.signature.signature.as_str());
                if let Some(format) = key.format {
                    if let Ok(value) = FormatChiffrage::try_from(format.as_str()) {
                        row.format = Some(value);
                    }
                }
                if let Some(header) = key.header {
                    row.header = Some(header);
                }
            },
            _ => ()
        }

        keys.push(row);
    }

    // Save the keys
    save_symmetric_batch(mongo, keys).await?;
    // Set the key flags to decipherable
    set_ca_batch_decipherable(mongo, key_ids).await?;

    // let routage_event = RoutageMessageAction::builder(
    //     DOMAINE_NOM, EVENEMENT_CLE_RECUE_PARTITION, vec![Securite::L4Secure]
    // ).build();
    //     middleware.emettre_evenement(routage_event, &event_contenu).await?;

    outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
}
