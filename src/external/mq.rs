use crate::constants::*;
use crate::external::crypto::SymmetricEncryptionHandler;
use crate::models::{ErrorMessage, SymmetricKeyDecryptionRequest};
use millegrilles_common_rust::constantes::{COMMANDE_AJOUTER_CLE_DOMAINES, COMMANDE_CERT_MAITREDESCLES, COMMANDE_TRANSFERT_CLE, COMMANDE_TRANSFERT_CLE_CA, MAITREDESCLES_REQUETE_DECHIFFRAGE_MESSAGE, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, REQUETE_CERT_MAITREDESCLES, Securite};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange};
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tracing::debug;
use millegrilles_common_rust::v3::ConfigService;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;

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
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_CA_TICKER),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: "evenement.ceduleur.ping".to_string(), exchange: Securite::L1Public }
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: true,
        })?;

    mq.add_named_queue(ConfigQueue {
        nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_CA_BACKUP),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.getNombreTransactions", DOMAINE_NOM), exchange: Securite::L2Prive },
            ConfigRoutingExchange { routing_key: format!("commande.{}.declencherBackup", DOMAINE_NOM), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("commande.{}.regenerer", DOMAINE_NOM), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: true,
    })?;


    mq.add_named_queue(ConfigQueue {
        nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_CA_REQUESTS),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_CLES_NON_DECHIFFRABLES_V2), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_COMPTER_CLES_NON_DECHIFFRABLES), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_SYNCHRONISER_CLES), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: false,
    })?;

    mq.add_named_queue(ConfigQueue {
        nom_queue: format!("{}/ca/events", DOMAINE_NOM),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, EVENEMENT_CLE_RECUE_PARTITION), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: true,
    })?;

    mq.add_named_queue(ConfigQueue {
        nom_queue: format!("{}/ca/commands", DOMAINE_NOM),
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

    mq.add_named_queue(ConfigQueue {
        nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_CA_NEWKEYS),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_AJOUTER_CLE_DOMAINES), exchange: Securite::L1Public },
        ],
        ttl: Some(900_000), // These are keys to save - give 15 minutes to come back and save
        durable: true,
        autodelete: false,
    })?;

    //     // RK 3.protege et 4.secure
    //     let requetes_protegees: Vec<&str> = vec![
    //         // REQUETE_CLES_NON_DECHIFFRABLES,
    //         REQUETE_CLES_NON_DECHIFFRABLES_V2,
    //         REQUETE_COMPTER_CLES_NON_DECHIFFRABLES,
    //         REQUETE_SYNCHRONISER_CLES,
    //     ];

    //     let evenements_proteges: Vec<&str> = vec![
    //         EVENEMENT_CLES_MANQUANTES_PARTITION,
    //         EVENEMENT_CLE_RECUE_PARTITION,
    //     ];
    //
    //     let commandes_protegees: Vec<&str> = vec![
    //         COMMANDE_CONFIRMER_CLES_SUR_CA,
    //         COMMANDE_RESET_NON_DECHIFFRABLE,
    //     ];
    //     rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_TRANSFERT_CLE_CA), exchange: Securite::L3Protege});
    //
    //     // Capturer les commandes "sauver cle" sur tous les exchanges pour toutes les partitions
    //     // Va creer la transaction locale CA si approprie
    //         rk_sauvegarder_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.*.{}", DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE), exchange: sec });
    //
    //     // Nouvelle methode de sauvegarde de cle
    //     rk_sauvegarder_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_AJOUTER_CLE_DOMAINES), exchange: Securite::L1Public });
    //     rk_sauvegarder_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_TRANSFERT_CLE), exchange: Securite::L3Protege });
    //
    //     for sec in [Securite::L3Protege, Securite::L4Secure] {
    //         // Conserver sauver cle pour
    //         rk_sauvegarder_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.*.{}", DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE), exchange: sec.clone() });
    //
    //         // Capturer commande sauvegarder cle CA sur 3.protege et 4.secure
    //         rk_sauvegarder_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE), exchange: sec });
    //     }

    Ok(())
}

pub fn init_symmetric_queues(config: &dyn ConfigService, mq: &MessagingServiceImpl) -> Result<(), CommonError> {

    let fingerprint_pk = config.get_configuration_pki().get_enveloppe_privee().fingerprint()?;

    // Configure the queues and add to messaging service (will spawn consumer threads)
    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_SYMMETRIC_JOB_TICKER),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: "evenement.ceduleur.ping".to_string(), exchange: Securite::L1Public }
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: true,
        })?;

    mq.add_named_queue(ConfigQueue {
        nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_SYMMETRIC_CERTIFICATES),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_CERT_MAITREDESCLES), exchange: Securite::L1Public },
            ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, REQUETE_CERT_MAITREDESCLES), exchange: Securite::L1Public },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: true,
    })?;

    mq.add_named_queue(ConfigQueue {
        nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_SYMMETRIC_NEWKEYS),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_AJOUTER_CLE_DOMAINES), exchange: Securite::L1Public },
        ],
        ttl: Some(900_000),
        durable: true,
        autodelete: false,
    })?;

    mq.add_named_queue(ConfigQueue {
        nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_SYMMETRIC_GETKEYS),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: false,
    })?;

    mq.add_named_queue(ConfigQueue {
        nom_queue: format!("{}/{}/{}", DOMAINE_NOM, QUEUE_SYMMETRIC_COMMANDS, fingerprint_pk),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, fingerprint_pk, COMMANDE_CLE_SYMMETRIQUE), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: true,
    })?;

    mq.add_named_queue(ConfigQueue {
        nom_queue: format!("{}/symmetric/decrypt", DOMAINE_NOM),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, MAITREDESCLES_REQUETE_DECHIFFRAGE_MESSAGE), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: false,
    })?;

    // let mut rk_dechiffrage = Vec::new();
    //     let mut rk_commande_cle = Vec::new();
    //     let mut rk_volatils = Vec::new();
    //
    //     let dechiffrer = if let Ok(_v) = std::env::var("DESACTIVER_DECHIFFRAGE") {
    //         info!("Desactiver rechiffrage public/prive/protege");
    //         false
    //     } else {
    //         true
    //     };
    //
    //     let fingerprint = manager.handler_rechiffrage.fingerprint()?;
    //
    //     let mut queues = Vec::new();
    //
    //     let nom_partition = fingerprint.as_str();
    //
    //     let commandes: Vec<&str> = vec![
    //         COMMANDE_SAUVEGARDER_CLE,
    //     ];
    //
    //     for sec in [Securite::L1Public, Securite::L2Prive, Securite::L3Protege] {
    //
    //         if dechiffrer {
    //             rk_dechiffrage.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_DECHIFFRAGE), exchange: sec.clone() });
    //             rk_dechiffrage.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_VERIFIER_PREUVE), exchange: sec.clone() });
    //         }
    //         rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_CERTIFICAT_MAITREDESCLES), exchange: sec.clone() });
    //
    //         // Commande volatile
    //         rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_CERT_MAITREDESCLES), exchange: sec.clone() });
    //
    //         // Commande sauvegarder cles
    //         for commande in &commandes {
    //             rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.*.{}", DOMAINE_NOM, commande), exchange: sec.clone() });
    //         }
    //     }
    //
    //     if dechiffrer {
    //         rk_dechiffrage.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2), exchange: Securite::L3Protege });
    //         rk_dechiffrage.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, MAITREDESCLES_REQUETE_DECHIFFRAGE_MESSAGE), exchange: Securite::L3Protege });
    //     }
    //     rk_dechiffrage.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_TRANSFERT_CLES), exchange: Securite::L3Protege });
    //     rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_CERTIFICAT_MAITREDESCLES), exchange: Securite::L1Public });
    //
    //     // Commande volatile
    //     rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_CERT_MAITREDESCLES), exchange: Securite::L3Protege });
    //
    //     // Sauvegarde cleDomaine sur exchange public
    //     rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_AJOUTER_CLE_DOMAINES), exchange: Securite::L1Public });
    //     rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_TRANSFERT_CLE), exchange: Securite::L3Protege });
    //
    //     // Commande sauvegarder cle 4.secure pour redistribution des cles
    //     // rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE), exchange: Securite::L4Secure });
    //     rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_TRANSFERT_CLE), exchange: Securite::L4Secure });
    //
    //     // rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.*.{}", DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE), exchange: Securite::L4Secure });
    //     // rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, nom_partition, COMMANDE_TRANSFERT_CLE), exchange: Securite::L4Secure });
    //
    //     // Rotation des cles
    //     rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, nom_partition, COMMANDE_ROTATION_CERTIFICAT), exchange: Securite::L3Protege });
    //     rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMAND_QUERY_REPAIR_SYMMETRIC_KEY), exchange: Securite::L3Protege });
    //
    //     // Requetes de dechiffrage/preuve re-emise sur le bus 4.secure lorsque la cle est inconnue
    //     rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_DECHIFFRAGE), exchange: Securite::L4Secure });
    //     rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_VERIFIER_PREUVE), exchange: Securite::L4Secure });
    //     rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION), exchange: Securite::L3Protege });
    //
    //     rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION), exchange: Securite::L3Protege });
    //     rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, EVENEMENT_CLES_RECHIFFRAGE), exchange: Securite::L4Secure });
    //     // rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, nom_partition, COMMANDE_DECHIFFRER_CLE), exchange: Securite::L4Secure });
    //
    //     let commandes_protegees = vec![
    //         COMMANDE_RECHIFFRER_BATCH,
    //         COMMANDE_VERIFIER_CLE_SYMMETRIQUE,
    //     ];
    //     for commande in commandes_protegees {
    //         rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, commande), exchange: Securite::L3Protege });
    //     }
    //
    //     // Queue de messages dechiffrage - taches partagees entre toutes les partitions
    //     if dechiffrer {
    //         queues.push(QueueType::ExchangeQueue(
    //             ConfigQueue {
    //                 nom_queue: NOM_Q_DECHIFFRAGE.into(),
    //                 routing_keys: rk_dechiffrage,
    //                 ttl: DEFAULT_Q_TTL.into(),
    //                 durable: true,
    //                 autodelete: false,
    //             }
    //         ));
    //     }
    //
    //     // Queue commande de sauvegarde de cle, recovery
    //     if let Some(nom_queue) = manager.get_q_sauvegarder_cle()? {
    //         queues.push(QueueType::ExchangeQueue(
    //             ConfigQueue {
    //                 nom_queue,
    //                 routing_keys: rk_commande_cle,
    //                 ttl: None,
    //                 durable: true,
    //                 autodelete: true,
    //             }
    //         ));
    //     }
    //
    //     // Queue volatils
    //     if let Some(nom_queue) = manager.get_q_volatils()? {
    //         queues.push(QueueType::ExchangeQueue(
    //             ConfigQueue {
    //                 nom_queue,
    //                 routing_keys: rk_volatils,
    //                 ttl: DEFAULT_Q_TTL.into(),
    //                 durable: true,
    //                 autodelete: true,
    //             }
    //         ));
    //     }
    //
    //     // Queue de triggers
    //     queues.push(QueueType::Triggers(format!("MaitreDesCles.{}", fingerprint.as_str()), Securite::L3Protege));
    //
    //     Ok(queues)

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
