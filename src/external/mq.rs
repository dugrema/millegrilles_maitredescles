use crate::constants::{DOMAINE_NOM, QUEUE_TTL_DEFAULT};
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange};
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;

pub fn init_ca_queues(mq: &MessagingServiceImpl) -> Result<(), CommonError> {

    // Configure the queues and add to messaging service (will spawn consumer threads)
    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/ca_job_ticker", DOMAINE_NOM),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: "evenement.ceduleur.ping".to_string(), exchange: Securite::L1Public }
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(ConfigQueue {
        nom_queue: format!("{}/backup", DOMAINE_NOM),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.getNombreTransactions", DOMAINE_NOM), exchange: Securite::L2Prive },
            ConfigRoutingExchange { routing_key: format!("commande.{}.declencherBackup", DOMAINE_NOM), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("commande.{}.regenerer", DOMAINE_NOM), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: false,
    })?;

    Ok(())
}

pub fn init_symmetric_queues(mq: &MessagingServiceImpl) -> Result<(), CommonError> {

    // Configure the queues and add to messaging service (will spawn consumer threads)
    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/symmetric_job_ticker", DOMAINE_NOM),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: "evenement.ceduleur.ping".to_string(), exchange: Securite::L1Public }
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(ConfigQueue {
        nom_queue: format!("{}/certificates", DOMAINE_NOM),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.certMaitreDesCles", DOMAINE_NOM), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("evenement.{}.certMaitreDesCles", DOMAINE_NOM), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: false,
        autodelete: false,
    })?;

    Ok(())
}
