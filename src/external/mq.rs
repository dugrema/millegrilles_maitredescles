use crate::constants::*;
use crate::external::crypto::SymmetricEncryptionHandler;
use crate::models::{ErrorMessage, SymmetricKeyDecryptionRequest};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::rabbitmq_dao::ConfigRoutingExchange;
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::tracing::debug;
use millegrilles_common_rust::v3::ConfigService;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::models::ConfigQueueV3;

pub const QUEUE_CA_NEWKEYS: &str = "ca/newkeys";
pub const QUEUE_CA_BACKUP: &str = "ca/backup";
pub const QUEUE_CA_TICKER: &str = "ca/job_ticker";
pub const QUEUE_CA_REQUESTS: &str = "ca/requests";
pub const QUEUE_SYMMETRIC_NEWKEYS: &str = "symmetric/newkeys";
pub const QUEUE_SYMMETRIC_GETKEYS: &str = "symmetric/get_keys";
pub const QUEUE_SYMMETRIC_CERTIFICATES: &str = "symmetric/certificates";
pub const QUEUE_SYMMETRIC_JOB_TICKER: &str = "symmetric/job_ticker";
pub const QUEUE_SYMMETRIC_COMMANDS: &str = "symmetric/commands";

pub fn init_ca_queues(mq: &MessagingServiceImpl) -> Result<(), CommonError> {

    // Configure the queues and add to messaging service (will spawn consumer threads)
    mq.add_named_queue(
        ConfigQueueV3 {
            queue_name: Some(format!("{}/{}", DOMAINE_NOM, QUEUE_CA_TICKER)),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: "evenement.ceduleur.ping".to_string(), exchange: Securite::L1Public }
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: true,
        })?;

    mq.add_named_queue(ConfigQueueV3 {
        queue_name: Some(format!("{}/{}", DOMAINE_NOM, QUEUE_CA_BACKUP)),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.getNombreTransactions", DOMAINE_NOM), exchange: Securite::L2Prive },
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_DECLENCHER_BACKUP), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: COMMANDE_GLOBAL_DECLENCHER_BACKUP.to_string(), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_REGENERER), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: true,
    })?;


    mq.add_named_queue(ConfigQueueV3 {
        queue_name: Some(format!("{}/{}", DOMAINE_NOM, QUEUE_CA_REQUESTS)),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_CLES_NON_DECHIFFRABLES_V2), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_COMPTER_CLES_NON_DECHIFFRABLES), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_SYNCHRONISER_CLES), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: false,
    })?;

    mq.add_named_queue(ConfigQueueV3 {
        queue_name: Some(format!("{}/ca/events", DOMAINE_NOM)),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, EVENEMENT_CLE_RECUE_PARTITION), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: true,
    })?;

    mq.add_named_queue(ConfigQueueV3 {
        queue_name: Some(format!("{}/ca/commands", DOMAINE_NOM)),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_CONFIRMER_CLES_SUR_CA), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_RESET_NON_DECHIFFRABLE), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_TRANSFERT_CLE_CA), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_TRANSFERT_CLE), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: false,
    })?;

    mq.add_named_queue(ConfigQueueV3 {
        queue_name: Some(format!("{}/{}", DOMAINE_NOM, QUEUE_CA_NEWKEYS)),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_AJOUTER_CLE_DOMAINES), exchange: Securite::L1Public },
        ],
        ttl: Some(900_000), // These are keys to save - give 15 minutes to come back and save
        durable: true,
        autodelete: false,
    })?;

    Ok(())
}

pub fn init_symmetric_queues(config: &dyn ConfigService, mq: &MessagingServiceImpl) -> Result<(), CommonError> {

    let fingerprint_pk = config.get_configuration_pki().get_enveloppe_privee().fingerprint()?;

    // Configure the queues and add to messaging service (will spawn consumer threads)
    mq.add_named_queue(
        ConfigQueueV3 {
            queue_name: Some(format!("{}/{}", DOMAINE_NOM, QUEUE_SYMMETRIC_JOB_TICKER)),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: "evenement.ceduleur.ping".to_string(), exchange: Securite::L1Public }
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: true,
        })?;

    mq.add_named_queue(ConfigQueueV3 {
        queue_name: Some(format!("{}/{}", DOMAINE_NOM, QUEUE_SYMMETRIC_CERTIFICATES)),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_CERT_MAITREDESCLES), exchange: Securite::L1Public },
            ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, REQUETE_CERT_MAITREDESCLES), exchange: Securite::L1Public },

        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: true,
    })?;

    mq.add_named_queue(ConfigQueueV3 {
        queue_name: Some(format!("{}/{}", DOMAINE_NOM, QUEUE_SYMMETRIC_NEWKEYS)),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_AJOUTER_CLE_DOMAINES), exchange: Securite::L1Public },
        ],
        ttl: Some(900_000),
        durable: true,
        autodelete: false,
    })?;

    mq.add_named_queue(ConfigQueueV3 {
        queue_name: Some(format!("{}/{}", DOMAINE_NOM, QUEUE_SYMMETRIC_GETKEYS)),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: false,
    })?;

    mq.add_named_queue(ConfigQueueV3 {
        queue_name: Some(format!("{}/{}/{}", DOMAINE_NOM, QUEUE_SYMMETRIC_COMMANDS, fingerprint_pk)),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_RECHIFFRER_BATCH), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, fingerprint_pk, COMMANDE_CLE_SYMMETRIQUE), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, fingerprint_pk, COMMAND_CERTIFICATE_ROTATION), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: true,
    })?;

    mq.add_named_queue(ConfigQueueV3 {
        queue_name: Some(format!("{}/symmetric/decrypt", DOMAINE_NOM)),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, MAITREDESCLES_REQUETE_DECHIFFRAGE_MESSAGE), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: false,
    })?;

    Ok(())
}

pub async fn emit_certificate(outbound: &MessageOutboundFacade, decryption: &SymmetricEncryptionHandler) -> Result<(), CommonError> {
    if ! decryption.is_ready() {
        debug!("Not emitting certificate - not ready to encrypt/decrypt");
        return Ok(())
    }

    let routing = RoutageMessageAction::builder(
        DOMAINE_NOM, REQUETE_CERT_MAITREDESCLES, vec![Securite::L1Public]
    )
        // .correlation_id(COMMANDE_CERT_MAITREDESCLES)
        .build();
    outbound.emit_event(routing, ErrorMessage { ok: true, code: None, err: None}).await
}

/// Emits a request indicating the local symmetric key decryption is not available.
/// The admin can use the master key to re-encrypt the symmetric key for this certificate.
pub async fn emit_local_symmetric_key_decryption_request(
    config: &dyn ConfigService,
    outbound: &MessageOutboundFacade,
    encrypted_symmetric_key_for_ca: &str
) -> Result<(), CommonError> {
    let private_key = config.get_configuration_pki().get_enveloppe_privee();
    let instance_id = private_key.enveloppe_pub.get_common_name()?;

    debug!("Request symmetric key for instance_id : {}", instance_id);

    let request = SymmetricKeyDecryptionRequest {
        cle_symmetrique_ca: encrypted_symmetric_key_for_ca.to_string()
    };

    let routing = RoutageMessageAction::builder(
        DOMAINE_NOM, EVENEMENT_DEMANDE_CLE_SYMMETRIQUE, vec![Securite::L3Protege])
        // .correlation_id(EVENEMENT_DEMANDE_CLE_SYMMETRIQUE)
        .build();

    outbound.emit_event(routing, serde_json::to_value(request)?).await
}
