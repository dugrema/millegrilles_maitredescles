use std::alloc::handle_alloc_error;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter, Write};
use std::fs::read_dir;
use std::str::from_utf8;
use std::sync::{Arc, Mutex};

use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::base64::{engine::general_purpose::STANDARD_NO_PAD as base64_nopad, Engine as _};
use millegrilles_common_rust::multibase::Base;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage_cle::{CleChiffrageCache, CommandeAjouterCleDomaine, CommandeSauvegarderCle};
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::common_messages::{ReponseRequeteDechiffrageV2, RequeteDechiffrage, RequeteDechiffrageMessage};
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::futures_util::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::hachages::hacher_bytes;
use millegrilles_common_rust::messages_generiques::{CommandeCleRechiffree, CommandeDechiffrerCle, MessageCedule};
use millegrilles_common_rust::middleware::{Middleware, sauvegarder_traiter_transaction_serializable, sauvegarder_transaction};
use millegrilles_common_rust::mongo_dao::{ChampIndex, convertir_bson_deserializable, convertir_to_bson, IndexOptions, MongoDao, verifier_erreur_duplication_mongo};
use millegrilles_common_rust::mongodb::{Collection, Cursor};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions, FindOptions, Hint, InsertOneOptions, UpdateOptions};
use millegrilles_common_rust::{get_domaine_action, millegrilles_cryptographie, multibase, serde_json};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::{CleChiffrageHandler, CleDechiffrage, CleSecreteSerialisee};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::millegrilles_cryptographie::x509::{EnveloppeCertificat, EnveloppePrivee};
use millegrilles_common_rust::multihash::Code;
use millegrilles_common_rust::openssl::pkey::{PKey, Private};
use millegrilles_common_rust::openssl::rsa::Rsa;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, NamedQueue, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio::fs::File as File_tokio;
use millegrilles_common_rust::tokio::{io::AsyncReadExt, spawn};
use millegrilles_common_rust::tokio::time::{Duration as Duration_tokio, sleep};
use millegrilles_common_rust::tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{EtatTransaction, marquer_transaction, TraiterTransaction, Transaction};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::millegrilles_cryptographie::{deser_message_buffer, heapless};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::FormatChiffrage;
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::{SignatureDomaines, SignatureDomainesVersion};
use millegrilles_common_rust::millegrilles_cryptographie::x25519::{chiffrer_asymmetrique_ed25519, CleSecreteX25519, dechiffrer_asymmetrique_ed25519};
use crate::maitredescles_ca::{GestionnaireMaitreDesClesCa, NOM_COLLECTION_CLES};

use crate::maitredescles_commun::*;
use crate::maitredescles_rechiffrage::{CleInterneChiffree, HandlerCleRechiffrage};
use crate::messages::{MessageReponseChiffree, RequeteVerifierPreuve};

const REQUETE_CERTIFICAT_MAITREDESCLES: &str = COMMANDE_CERT_MAITREDESCLES;

const COMMANDE_RECHIFFRER_BATCH: &str = "rechiffrerBatch";

const INDEX_RECHIFFRAGE_PK: &str = "fingerprint_pk";
const INDEX_CONFIRMATION_CA: &str = "confirmation_ca";

const CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";
const CHAMP_CONFIRMATION_CA: &str = "confirmation_ca";

pub struct GestionnaireMaitreDesClesPartition {
    pub handler_rechiffrage: Arc<HandlerCleRechiffrage>,
    pub ressources: Mutex<Option<Arc<GestionnaireRessources>>>,
}

impl Debug for GestionnaireMaitreDesClesPartition {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.handler_rechiffrage.fingerprint() {
            Ok(fingerprint) => f.write_str(format!("GestionnaireMaitreDesClesPartition {}", fingerprint).as_str()),
            Err(_) => f.write_str("GestionnaireMaitreDesClesPartition Erreur calcul fingerprint")
        }
    }
}

impl Clone for GestionnaireMaitreDesClesPartition {
    fn clone(&self) -> Self {
        Self {
            handler_rechiffrage: self.handler_rechiffrage.clone(),
            ressources: Mutex::new(self.ressources.lock().expect("lock").clone())
        }
    }
}

impl GestionnaireMaitreDesClesPartition {

    pub fn new(handler_rechiffrage: HandlerCleRechiffrage) -> Self {
        Self { handler_rechiffrage: Arc::new(handler_rechiffrage), ressources: Mutex::new(None) }
    }

    /// Retourne une version tronquee du nom de partition
    /// Utilise pour nommer certaines ressources (e.g. collections Mongo)
    pub fn get_partition_tronquee(&self) -> Result<Option<String>, Error> {
        let fingerprint = self.handler_rechiffrage.fingerprint()?;
        Ok(Some(String::from(&fingerprint[35..])))
    }

    fn get_q_sauvegarder_cle(&self) -> Result<Option<String>, Error> {
        let fingerprint = self.handler_rechiffrage.fingerprint()?;
        Ok(Some(format!("MaitreDesCles/{}/sauvegarder", fingerprint)))
    }

    fn get_collection_cles(&self) -> Result<Option<String>, Error> {
        match self.get_partition_tronquee()? {
            Some(p) => Ok(Some("MaitreDesCles/cles".to_string())),
            None => Ok(None)
        }
    }

    /// Verifie si le CA a des cles qui ne sont pas connues localement
    pub async fn synchroniser_cles<M>(&self, middleware: &M) -> Result<(), Error>
        where M: GenerateurMessages + MongoDao + CleChiffrageHandler
    {
        synchroniser_cles(middleware, self).await?;
        Ok(())
    }

    /// S'assure que le CA a toutes les cles presentes dans la partition
    pub async fn confirmer_cles_ca<M>(&self, middleware: &M, reset_flag: Option<bool>) -> Result<(), Error>
        where M: GenerateurMessages + MongoDao + CleChiffrageHandler
    {
        confirmer_cles_ca(middleware, self, reset_flag).await?;
        Ok(())
    }

    pub async fn emettre_certificat_maitredescles<M>(&self, middleware: &M, m: Option<MessageValide>) -> Result<(), Error>
        where M: GenerateurMessages + MongoDao
    {
        if self.handler_rechiffrage.is_ready() {
            emettre_certificat_maitredescles(middleware, m).await
        } else {
            Ok(())
        }
    }

    /// Preparer les Qs une fois le certificat pret
    fn preparer_queues_rechiffrage(&self) -> Result<Vec<QueueType>, Error> {
        let mut rk_dechiffrage = Vec::new();
        let mut rk_commande_cle = Vec::new();
        let mut rk_volatils = Vec::new();

        let dechiffrer = if let Ok(v) = std::env::var("DESACTIVER_DECHIFFRAGE") {
            info!("Desactiver rechiffrage public/prive/protege");
            false
        } else {
            true
        };

        let fingerprint = self.handler_rechiffrage.fingerprint()?;

        let mut queues = Vec::new();

        let nom_partition = fingerprint.as_str();

        let commandes: Vec<&str> = vec![
            COMMANDE_SAUVEGARDER_CLE,
        ];

        for sec in [Securite::L1Public, Securite::L2Prive, Securite::L3Protege] {

            if dechiffrer {
                rk_dechiffrage.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_DECHIFFRAGE), exchange: sec.clone() });
                rk_dechiffrage.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_VERIFIER_PREUVE), exchange: sec.clone() });
            }
            rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_CERTIFICAT_MAITREDESCLES), exchange: sec.clone() });

            // Commande volatile
            rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_CERT_MAITREDESCLES), exchange: sec.clone() });

            // Commande sauvegarder cles
            for commande in &commandes {
                rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.*.{}", DOMAINE_NOM, commande), exchange: sec.clone() });
            }
        }

        if dechiffrer {
            rk_dechiffrage.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2), exchange: Securite::L3Protege });
            rk_dechiffrage.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, MAITREDESCLES_REQUETE_DECHIFFRAGE_MESSAGE), exchange: Securite::L3Protege });
        }
        rk_dechiffrage.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_TRANSFERT_CLES), exchange: Securite::L3Protege });
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_CERTIFICAT_MAITREDESCLES), exchange: Securite::L1Public });

        // Commande volatile
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_CERT_MAITREDESCLES), exchange: Securite::L3Protege });

        // Sauvegarde cleDomaine sur exchange public
        rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_AJOUTER_CLE_DOMAINES), exchange: Securite::L1Public });
        rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_TRANSFERT_CLE), exchange: Securite::L3Protege });

        // Commande sauvegarder cle 4.secure pour redistribution des cles
        // rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE), exchange: Securite::L4Secure });
        rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_TRANSFERT_CLE), exchange: Securite::L4Secure });

        // rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.*.{}", DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE), exchange: Securite::L4Secure });
        // rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, nom_partition, COMMANDE_TRANSFERT_CLE), exchange: Securite::L4Secure });

        // Rotation des cles
        rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, nom_partition, COMMANDE_ROTATION_CERTIFICAT), exchange: Securite::L3Protege });

        // Requetes de dechiffrage/preuve re-emise sur le bus 4.secure lorsque la cle est inconnue
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_DECHIFFRAGE), exchange: Securite::L4Secure });
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_VERIFIER_PREUVE), exchange: Securite::L4Secure });
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION), exchange: Securite::L3Protege });

        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION), exchange: Securite::L3Protege });
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, EVENEMENT_CLES_RECHIFFRAGE), exchange: Securite::L4Secure });
        // rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, nom_partition, COMMANDE_DECHIFFRER_CLE), exchange: Securite::L4Secure });

        let commandes_protegees = vec![
            COMMANDE_RECHIFFRER_BATCH,
            COMMANDE_VERIFIER_CLE_SYMMETRIQUE,
        ];
        for commande in commandes_protegees {
            rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, commande), exchange: Securite::L3Protege });
        }

        // Queue de messages dechiffrage - taches partagees entre toutes les partitions
        if dechiffrer {
            queues.push(QueueType::ExchangeQueue(
                ConfigQueue {
                    nom_queue: NOM_Q_DECHIFFRAGE.into(),
                    routing_keys: rk_dechiffrage,
                    ttl: DEFAULT_Q_TTL.into(),
                    durable: false,
                    autodelete: false,
                }
            ));
        }

        // Queue commande de sauvegarde de cle
        if let Some(nom_queue) = self.get_q_sauvegarder_cle()? {
            queues.push(QueueType::ExchangeQueue(
                ConfigQueue {
                    nom_queue,
                    routing_keys: rk_commande_cle,
                    ttl: None,
                    durable: false,
                    autodelete: true,
                }
            ));
        }

        // Queue volatils
        if let Some(nom_queue) = self.get_q_volatils()? {
            queues.push(QueueType::ExchangeQueue(
                ConfigQueue {
                    nom_queue,
                    routing_keys: rk_volatils,
                    ttl: DEFAULT_Q_TTL.into(),
                    durable: false,
                    autodelete: true,
                }
            ));
        }

        // Queue de triggers
        queues.push(QueueType::Triggers(format!("MaitreDesCles.{}", fingerprint.as_str()), Securite::L3Protege));

        Ok(queues)
    }


}

#[async_trait]
impl TraiterTransaction for GestionnaireMaitreDesClesPartition {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction, self).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireMaitreDesClesPartition {
    fn get_nom_domaine(&self) -> String { String::from(DOMAINE_NOM) }

    fn get_partition(&self) -> Result<Option<String>, Error> {
        Ok(Some(self.handler_rechiffrage.fingerprint()?))
    }

    fn get_collection_transactions(&self) -> Option<String> {
        // Aucunes transactions pour un maitre des cles autre que CA
        None
    }

    fn get_collections_documents(&self) -> Result<Vec<String>, Error> {
        // Utiliser le nom de la partition tronquee - evite que les noms de collections deviennent
        // trop long (cause un probleme lors de la creation d'index, max 127 chars sur path)
        match self.get_partition_tronquee()? {
            Some(p) => Ok(vec![format!("MaitreDesCles/{}/cles", p)]),
            None => Ok(vec![])
        }
    }

    fn get_q_transactions(&self) -> Result<Option<String>, Error> {
        let fingerprint = self.handler_rechiffrage.fingerprint()?;
        Ok(Some(format!("MaitreDesCles/{}/transactions", fingerprint)))
    }

    fn get_q_volatils(&self) -> Result<Option<String>, Error> {
        let fingerprint = self.handler_rechiffrage.fingerprint()?;
        Ok(Some(format!("MaitreDesCles/{}/volatils", fingerprint)))
    }

    fn get_q_triggers(&self) -> Result<Option<String>, Error> {
        let fingerprint = self.handler_rechiffrage.fingerprint()?;
        Ok(Some(format!("MaitreDesCles/{}/triggers", fingerprint)))
    }

    fn preparer_queues(&self) -> Result<Vec<QueueType>, Error> {
        let mut queues = match self.handler_rechiffrage.is_ready() {
            true => self.preparer_queues_rechiffrage()?,
            false => Vec::new()
        };

        // Ajouter Q reception cle symmetriques rechiffrees
        let fingerprint = self.handler_rechiffrage.fingerprint()?;
        let nom_queue_cle_config = format!("MaitreDesCles/{}/config", fingerprint);

        let mut rks = Vec::new();
        rks.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, fingerprint, COMMANDE_CLE_SYMMETRIQUE), exchange: Securite::L3Protege });

        // Queue volatils
        queues.push(QueueType::ExchangeQueue(
            ConfigQueue {
                nom_queue: nom_queue_cle_config.into(),
                routing_keys: rks,
                ttl: DEFAULT_Q_TTL.into(),
                durable: false,
                autodelete: true,
            }
        ));

        Ok(queues)
    }

    async fn preparer_database<M>(&self, middleware: &M) -> Result<(), Error>
        where M: Middleware + 'static
    {
        if let Some(nom_collection_cles) = self.get_collection_cles()? {
            debug!("preparer_database Ajouter index pour collection {}", nom_collection_cles);
            preparer_index_mongodb_custom(middleware, nom_collection_cles.as_str(), false).await?;
            preparer_index_mongodb_partition(middleware, self).await?;
        } else {
            debug!("preparer_database Aucun fingerprint / partition");
        }
        Ok(())
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error> where M: Middleware + 'static {
        consommer_requete(middleware, message, self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error> where M: Middleware + 'static {
        consommer_commande(middleware, message, self).await
    }

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error> where M: Middleware + 'static {
        consommer_transaction(middleware, message, self).await
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error> where M: Middleware + 'static {
        consommer_evenement(middleware, self, message).await
    }

    async fn entretien<M>(self: &'static Self, middleware: Arc<M>) where M: Middleware + 'static {
        let mut q_preparation_completee = false;
        loop {
            if !self.handler_rechiffrage.is_ready() || q_preparation_completee == false {

                if q_preparation_completee == true {
                    panic!("handler rechiffrage is_ready() == false et q_preparation_completee == true");
                }

                info!("entretien_rechiffreur Aucun certificat configure, on demande de generer un certificat volatil");
                let resultat = match preparer_rechiffreur_mongo(
                    middleware.as_ref(), self.handler_rechiffrage.as_ref()).await {
                    Ok(()) => {
                        debug!("entretien.Certificat pret, activer Qs et synchroniser cles");
                        true
                    },
                    Err(e) => {
                        error!("entretien_rechiffreur Erreur generation certificat volatil : {:?}", e);
                        false
                    }
                };

                if resultat {
                    // Preparer la collection avec index
                    self.preparer_database(middleware.as_ref()).await.expect("preparer_database");

                    let queues = self.preparer_queues_rechiffrage().expect("queues");
                    for queue in queues {

                        let queue_name = match &queue {
                            QueueType::ExchangeQueue(q) => q.nom_queue.clone(),
                            QueueType::ReplyQueue(_) => { continue },
                            QueueType::Triggers(d,s) => format!("{}.{:?}", d, s)
                        };

                        // Creer thread de traitement
                        let (tx, rx) = mpsc::channel::<TypeMessage>(1);
                        let mut futures_consumer = FuturesUnordered::new();
                        futures_consumer.push(spawn(self.consommer_messages(middleware.clone(), rx)));

                        // Ajouter nouvelle queue
                        let named_queue = NamedQueue::new(queue, tx, Some(1), Some(futures_consumer));
                        middleware.ajouter_named_queue(queue_name, named_queue);
                    }

                    q_preparation_completee = true;
                }
            }

            debug!("Cycle entretien {}", DOMAINE_NOM);
            middleware.entretien_validateur().await;

            // Sleep cycle
            sleep(Duration_tokio::new(30, 0)).await;
        }
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule) -> Result<(), Error> where M: Middleware + 'static {
        traiter_cedule(middleware, trigger).await
    }

    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction, self).await
    }
}

pub async fn preparer_index_mongodb_partition<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition) -> Result<(), Error>
    where M: MongoDao + ConfigMessages
{
    if let Some(collection_cles) = gestionnaire.get_collection_cles()? {

        // Index confirmation ca (table cles)
        let options_confirmation_ca = IndexOptions {
            nom_index: Some(String::from(INDEX_CONFIRMATION_CA)),
            unique: false
        };
        let champs_index_confirmation_ca = vec!(
            ChampIndex { nom_champ: String::from(CHAMP_CONFIRMATION_CA), direction: 1 },
        );
        middleware.create_index(
            middleware,
            collection_cles.as_str(),
            champs_index_confirmation_ca,
            Some(options_confirmation_ca)
        ).await?;

    }

    // Index confirmation ca (table cles)
    let options_configuration = IndexOptions {
        nom_index: Some(String::from("pk")),
        unique: true
    };
    let champs_index_configuration = vec!(
        ChampIndex { nom_champ: String::from("type"), direction: 1 },
        ChampIndex { nom_champ: String::from("instance_id"), direction: 1 },
        ChampIndex { nom_champ: String::from("fingerprint"), direction: 1 },
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_CONFIGURATION,
        champs_index_configuration,
        Some(options_configuration)
    ).await?;

    Ok(())
}

async fn consommer_requete<M>(middleware: &M, message: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler + CleChiffrageCache + ConfigMessages
{
    debug!("Consommer requete {:?}", message.type_message);

    let user_id = message.certificat.get_user_id()?;
    let role_prive = message.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    if role_prive == true && user_id.is_some() {
        // OK
    } else if message.certificat.verifier_exchanges(vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])? {
        // Autorisation : On accepte les requetes de tous les echanges
    } else if message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Delegation globale
    } else {
        Err(Error::Str("Autorisation requete invalide, acces refuse"))?
    }

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.
    let (domaine, action) = get_domaine_action!(message.type_message);

    match domaine.as_str() {
        DOMAINE_NOM => {
            match action.as_str() {
                REQUETE_CERTIFICAT_MAITREDESCLES => requete_certificat_maitredescles(middleware, message).await,
                REQUETE_DECHIFFRAGE => requete_dechiffrage(middleware, message, gestionnaire).await,
                REQUETE_DECHIFFRAGE_V2 => requete_dechiffrage_v2(middleware, message, gestionnaire).await,
                MAITREDESCLES_REQUETE_DECHIFFRAGE_MESSAGE => requete_dechiffrage_message(middleware, message, gestionnaire).await,
                REQUETE_VERIFIER_PREUVE => requete_verifier_preuve(middleware, message, gestionnaire).await,
                REQUETE_TRANSFERT_CLES => requete_transfert_cles(middleware, message, gestionnaire).await,
                EVENEMENT_CLES_MANQUANTES_PARTITION => evenement_cle_manquante(middleware, message, gestionnaire).await,
                _ => {
                    error!("Message requete/action inconnue : '{}'. Message dropped.", action);
                    Ok(None)
                },
            }
        },
        _ => {
            error!("Message requete/domaine inconnu : '{}'. Message dropped.", domaine);
            Ok(None)
        },
    }
}

async fn requete_certificat_maitredescles<M>(middleware: &M, m: MessageValide)
                                             -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("emettre_certificat_maitredescles: {:?}", &m.type_message);
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let chaine_pem = enveloppe_privee.enveloppe_pub.chaine_pem()?;

    let reponse = json!({ "certificat": chaine_pem });

    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

async fn consommer_transaction<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    Err(format!("maitredescles_ca.consommer_transaction: Aucun type de transactions n'est supporte par partition. Recu : {:?}", m.type_message))?
}

async fn consommer_evenement<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler + CleChiffrageCache + ConfigMessages
{
    debug!("consommer_evenement Consommer evenement : {:?}", &m.type_message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
        true => Ok(()),
        false => Err(format!("consommer_evenement: Evenement invalide (pas 3.protege ou 4.secure)")),
    }?;

    let (_, action) = get_domaine_action!(m.type_message);

    match action.as_str() {
        EVENEMENT_CLES_MANQUANTES_PARTITION => evenement_cle_manquante(middleware, m, gestionnaire).await,
        EVENEMENT_CLES_RECHIFFRAGE => evenement_cle_rechiffrage(middleware, m, gestionnaire).await,
        _ => Err(format!("consommer_evenement: Mauvais type d'action pour un evenement : {}", action))?,
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + CleChiffrageHandler + ValidateurX509
{
    debug!("consommer_commande {:?}", m.type_message);

    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    let (_, action) = get_domaine_action!(m.type_message);

    if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        match action.as_str() {
            // Commandes standard
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire).await,
            COMMANDE_AJOUTER_CLE_DOMAINES => commande_ajouter_cle_domaines(middleware, m, gestionnaire).await,
            COMMANDE_CERT_MAITREDESCLES => {emettre_certificat_maitredescles(middleware, Some(m)).await?; Ok(None)},

            COMMANDE_RECHIFFRER_BATCH => commande_rechiffrer_batch(middleware, m, gestionnaire).await,
            COMMANDE_CLE_SYMMETRIQUE => commande_cle_symmetrique(middleware, m, gestionnaire).await,
            COMMANDE_VERIFIER_CLE_SYMMETRIQUE => commande_verifier_cle_symmetrique(middleware, gestionnaire, &m).await,

            // Commandes inconnues
            _ => Err(format!("maitredescles_partition.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else if role_prive == true && user_id.is_some() {
        match action.as_str() {
            // Commandes standard
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire).await,
            COMMANDE_AJOUTER_CLE_DOMAINES => commande_ajouter_cle_domaines(middleware, m, gestionnaire).await,
            COMMANDE_CERT_MAITREDESCLES => {emettre_certificat_maitredescles(middleware, Some(m)).await?; Ok(None)},
            // Commandes inconnues
            _ => Err(format!("maitredescles_partition.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else if m.certificat.verifier_exchanges(vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])? {
        match action.as_str() {
            // Commandes standard
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire).await,
            COMMANDE_AJOUTER_CLE_DOMAINES => commande_ajouter_cle_domaines(middleware, m, gestionnaire).await,
            COMMANDE_TRANSFERT_CLE => commande_transfert_cle(middleware, m, gestionnaire).await,
            COMMANDE_CERT_MAITREDESCLES => {emettre_certificat_maitredescles(middleware, Some(m)).await?; Ok(None)},
            COMMANDE_ROTATION_CERTIFICAT => commande_rotation_certificat(middleware, m, gestionnaire).await,
            COMMANDE_CLE_SYMMETRIQUE => commande_cle_symmetrique(middleware, m, gestionnaire).await,
            COMMANDE_DECHIFFRER_CLE => commande_dechiffrer_cle(middleware, m, gestionnaire).await,
            // Commandes inconnues
            _ => Err(format!("maitredescles_partition.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else {
        Err(Error::Str("Autorisation commande invalide, acces refuse"))?
    }
}

async fn commande_sauvegarder_cle<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + CleChiffrageHandler
{
    error!("sauvegarder_cle Recu cle ancien format, **REJETE**\n{}", from_utf8(m.message.buffer.as_slice())?);
    Ok(Some(middleware.reponse_err(99, None, Some("Commande sauvegarderCle obsolete et retiree"))?))

    // debug!("commande_sauvegarder_cle Consommer commande : {:?}", & m.type_message);
    // let commande: CommandeSauvegarderCle = deser_message_buffer!(m.message);
    //
    // // let partition_message = m.get_partition();
    // let partition_message = match m.type_message {
    //     TypeMessageOut::Commande(r) => r.partition.clone(),
    //     _ => Err(Error::Str("commande_sauvegarder_cle Mauvais type de message, doit etre commande"))?
    // };
    //
    // // let fingerprint = match gestionnaire.handler_rechiffrage.fingerprint() {
    // //     Some(f) => f,
    // //     None => Err(format!("maitredescles_partition.commande_sauvegarder_cle Gestionnaire sans partition/certificat"))?
    // // };
    // let fingerprint = gestionnaire.handler_rechiffrage.fingerprint()?;
    // let nom_collection_cles = match gestionnaire.get_collection_cles()? {
    //     Some(c) => c,
    //     None => Err(Error::Str("maitredescles_partition.commande_sauvegarder_cle Gestionnaire sans partition/certificat"))?
    // };
    //
    // // let cle = match commande.cles.get(fingerprint.as_str()) {
    // let cle = match commande.cles.get(fingerprint.as_str()) {
    //     Some(cle) => cle.as_str(),
    //     None => {
    //         // La cle locale n'est pas presente. Verifier si le message de sauvegarde etait
    //         // adresse a cette partition.
    //         let reponse = if Some(fingerprint) == partition_message {
    //             let message = format!("maitredescles_partition.commande_sauvegarder_cle: Erreur validation - commande sauvegarder cles ne contient pas la cle CA : {:?}", commande);
    //             warn!("{}", message);
    //             // let reponse_err = json!({"ok": false, "err": message});
    //             // Ok(Some(middleware.formatter_reponse(&reponse_err, None)?))
    //             Ok(Some(middleware.reponse_err(None, None, Some(message.as_str()))?))
    //         } else {
    //             // Rien a faire, message ne concerne pas cette partition
    //             Ok(None)
    //         };
    //         return reponse;
    //     }
    // };
    //
    // sauvegarder_cle(middleware, gestionnaire, &commande, nom_collection_cles).await?;
    //
    // if Some(fingerprint) == partition_message {
    //     // Le message etait adresse a cette partition
    //     Ok(Some(middleware.reponse_ok(None, None)?))
    // } else {
    //     // Cle sauvegardee mais aucune reponse requise
    //     Ok(None)
    // }
}

async fn commande_ajouter_cle_domaines<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
                                          -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + CleChiffrageHandler
{
    debug!("commande_ajouter_cle_domaines Consommer commande : {:?}", &m.type_message);
    let commande: CommandeAjouterCleDomaine = deser_message_buffer!(m.message);

    let enveloppe_signature = middleware.get_enveloppe_signature();

    // Dechiffrer la cle - confirme qu'elle est valide et qu'on peut y acceder.
    let cle_secrete = commande.get_cle_secrete(enveloppe_signature.as_ref())?;

    // Valider la signature des domaines.
    if let Err(e) = commande.verifier_signature(cle_secrete.0) {
        warn!("commande_ajouter_cle_domaines Signature domaines invalide : {:?}", e);
        return Ok(Some(middleware.reponse_err(2, None, Some("Signature domaines invalide"))?))
    }

    if let Err(e) = sauvegarder_cle_domaine(middleware, gestionnaire, commande).await {
        warn!("commande_ajouter_cle_domaines Erreur sauvegarde cle : {:?}", e);
        return Ok(Some(middleware.reponse_err(3, None, Some("Erreur sauvegarde cle"))?))
    }

    // On ne retourne pas de confirmation - les transactions de cles sont sauvegardees et
    // confirmees par le CA.
    Ok(None)
}

async fn commande_transfert_cle<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + CleChiffrageHandler + ValidateurX509
{
    debug!("commande_transfert_cle Consommer commande : {:?}", &m.type_message);
    if !m.certificat.verifier_exchanges(vec![Securite::L3Protege])? ||
        !m.certificat.verifier_roles(vec![RolesCertificats::MaitreDesCles])?
    {
        Err(Error::Str("commande_transfert_cle Exchange/Role non autorise"))?
    }

    let message_ref = m.message.parse()?;
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let commande: CommandeTransfertClesV2 = match message_ref.dechiffrer(enveloppe_privee.as_ref()) {
        Ok(inner) => inner,
        Err(e) => Err(Error::String(format!("commande_transfert_cle  Erreur dechiffrage commande, skip : {:?}", e)))?
    };

    let enveloppe_signature = middleware.get_enveloppe_signature();
    let fingerprint_local = enveloppe_signature.fingerprint()?;
    if commande.fingerprint_emetteur == fingerprint_local {
        debug!("commande_transfert_cle Commande transfert cle emise par local, on l'ignore");
        return Ok(None)
    }

    for cle in commande.cles {
        let cle_id = cle.signature.get_cle_ref()?.to_string();

        // Verifier si on a deja la cle - sinon, creer une nouvelle transaction
        let filtre = doc! { CHAMP_CLE_ID: &cle_id };
        let options = FindOneOptions::builder()
            .hint(Hint::Name("index_cle_id".to_string()))
            .projection(doc!{CHAMP_CLE_ID: 1})
            .build();
        let collection = middleware.get_collection(NOM_COLLECTION_CLES)?;
        let resultat = collection.find_one(filtre, options).await?;

        if resultat.is_none() {
            let cle_secrete_vec = base64_nopad.decode(&cle.cle_secrete_base64)?;

            // Valider la signature
            if let Err(e) = cle.signature.verifier_derivee(cle_secrete_vec.as_slice()) {
                warn!("commande_transfert_cle Signature cle {} invalide, SKIP. {:?}", cle_id, e);
                continue
            }

            let mut cle_secrete = CleSecreteX25519 {0: [0u8;32]};
            cle_secrete.0.copy_from_slice(&cle_secrete_vec[0..32]);
            sauvegarder_cle_secrete(middleware, gestionnaire, cle.signature.clone(), &cle_secrete).await?;
        }
    }

    Ok(None)
}

async fn sauvegarder_cle_domaine<M>(
    middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition,
    commande: CommandeAjouterCleDomaine
)
    -> Result<(), Error>
    where M: GenerateurMessages + MongoDao
{
    let enveloppe_signature = middleware.get_enveloppe_signature();

    // Dechiffrer la cle
    let cle_secrete = commande.get_cle_secrete(enveloppe_signature.as_ref())?;

    sauvegarder_cle_secrete(middleware, gestionnaire, commande.signature, &cle_secrete).await?;

    Ok(())
}

async fn sauvegarder_cle_secrete<M>(
    middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition,
    signature: SignatureDomaines, cle_secrete: &CleSecreteX25519
)
    -> Result<(), Error>
    where M: MongoDao
{
    // Rechiffrer avec le handler de rechiffrage
    let cle_rechiffree = gestionnaire.handler_rechiffrage.chiffrer_cle_secrete(&cle_secrete.0)?;

    let nom_collection_cles = match gestionnaire.get_collection_cles()? {
        Some(c) => c,
        None => Err(Error::Str("maitredescles_partition.commande_sauvegarder_cle Gestionnaire sans partition/certificat"))?
    };
    let collection = middleware.get_collection(nom_collection_cles)?;

    let cle_id = signature.get_cle_ref()?;

    let filtre = doc! {"cle_id": cle_id.as_str()};
    let set_on_insert_ops = doc! {
        "cle_id": cle_id.as_str(),
        "signature": convertir_to_bson(signature)?,
        "cle_symmetrique": cle_rechiffree.cle,
        "nonce_symmetrique": cle_rechiffree.nonce,
        CHAMP_CREATION: Utc::now(),
        "dirty": true,
        "confirmation_ca": false,
    };
    let ops = doc! {
        "$setOnInsert": set_on_insert_ops,
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let options = UpdateOptions::builder().upsert(true).build();
    collection.update_one(filtre, ops, options).await?;
    Ok(())
}

// async fn sauvegarder_cle<M, S>(
//     middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition,
//     commande: &CommandeSauvegarderCle, nom_collection_cles: S
// )
//     -> Result<bool, Error>
//     where M: GenerateurMessages + MongoDao, S: AsRef<str>
// {
//     let nom_collection_cles = nom_collection_cles.as_ref();
//
//     let enveloppe_privee = middleware.get_enveloppe_signature();
//     let fingerprint = enveloppe_privee.fingerprint()?;
//     let cle = match commande.cles.get(fingerprint.as_str()) {
//         Some(cle) => cle.as_str(),
//         None => Err(format!("sauvegarder_cle Cle non disponible pour {}", fingerprint))?
//     };
//
//     // Valider identite, calculer cle_ref
//     let (cle_id, signature, cle_rechiffree) = {
//         let cle_bytes = multibase::decode(cle)?.1;
//         let cle_secrete = dechiffrer_asymmetrique_ed25519(
//             cle_bytes.as_slice(), &middleware.get_enveloppe_signature().cle_privee)?;
//
//         // Chiffrer avec cle symmetrique locale
//         let handler_rechiffrage = gestionnaire.handler_rechiffrage.as_ref();
//         let cle_chiffree = handler_rechiffrage.chiffrer_cle_secrete(&cle_secrete.0[..])?;
//
//         // Creer Signature version 0, le cle_id est le hachage bytes
//         let cle_id = commande.hachage_bytes.clone();
//         let mut domaines = heapless::Vec::new();
//         domaines.push(commande.domaine.as_str().try_into().map_err(|_| Error::Str("sauvegarder_cle Erreur conversion domaine"))?)
//             .map_err(|e| Error::String(format!("sauvegarder_cle Erreur conversion domaine : {:?}", e)))?;
//         let signature = SignatureDomaines {
//             domaines,
//             version: SignatureDomainesVersion::NonSigne,
//             ca: None,
//             signature: cle_id.as_str().try_into().map_err(|_| Error::Str("sauvegarder_cle Erreur conversion signature"))?,  // Utiliser hachage bytes
//         };
//
//         (cle_id, signature, cle_chiffree)
//     };
//
//     let filtre = doc!{"cle_id": &cle_id};
//     let format_str: &str = commande.format.clone().into();
//     let mut set_on_insert_ops = doc!{
//         "cle_id": cle_id,
//         "signature": convertir_to_bson(signature)?,
//         "cle_symmetrique": cle_rechiffree.cle,
//         "nonce_symmetrique": cle_rechiffree.nonce,
//
//         // Champs pour sync
//         CHAMP_CREATION: Utc::now(),
//         "dirty": true,
//         "confirmation_ca": false,
//
//         // Ajouter information de dechiffrage de contenu (vieille approche)
//         "format": format_str,
//         "iv": commande.iv.as_ref(),
//         "tag": commande.tag.as_ref(),
//         "header": commande.header.as_ref(),
//     };
//
//     let ops = doc!{
//         "$setOnInsert": set_on_insert_ops,
//         "$currentDate": {CHAMP_MODIFICATION: true}
//     };
//     let options = UpdateOptions::builder().upsert(true).build();
//     let collection = middleware.get_collection(nom_collection_cles)?;
//
//     let resultat = collection.update_one(filtre, ops, options).await?;
//     debug!("commande_sauvegarder_cle Resultat update : {:?}", resultat);
//     let insere = resultat.upserted_id.is_some();
//
//     Ok(insere)
// }

async fn commande_rotation_certificat<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_rotation_certificat Consommer commande : {:?}", & m.message);
    let commande: CommandeRotationCertificat = deser_message_buffer!(m.message);

    // Verifier que le certificat est pour l'instance locale
    // (note : pas garanti - confusion entre plusieurs certificats locaux possible, e.g. mongo et sqlite)
    let enveloppe_secrete = middleware.get_enveloppe_signature();
    let instance_id = enveloppe_secrete.enveloppe_pub.get_common_name()?;
    let certificat = middleware.charger_enveloppe(
        &commande.certificat, None, None).await?;
    let certificat_instance_id = certificat.get_common_name()?;

    if certificat_instance_id.as_str() == instance_id {
        debug!("commande_rotation_certificat Recu commande de rotation de certificat MaitreDesCles local");
        // let public_keys = certificat.fingerprint_cert_publickeys()?;
        let public_key = &certificat.certificat.public_key()?;
        let cle_secrete_chiffree_local = gestionnaire.handler_rechiffrage.get_cle_symmetrique_chiffree(public_key)?;
        debug!("Cle secrete chiffree pour instance {}:\n local = {}", instance_id, cle_secrete_chiffree_local);
        let cle_locale = doc! {
            "type": "local",
            "instance_id": certificat_instance_id.as_str(),
            "fingerprint": certificat.fingerprint()?,
            "cle": cle_secrete_chiffree_local,
        };

        debug!("commande_rotation_certificat Inserer cle configuration locale {:?}", cle_locale);

        let collection = middleware.get_collection(NOM_COLLECTION_CONFIGURATION)?;
        collection.insert_one(cle_locale, None).await?;

        Ok(Some(middleware.reponse_ok(None, None)?))
    } else {
        debug!("commande_rotation_certificat Recu commande de rotation de certificat MaitreDesCles tiers - skip");
        Ok(None)
    }
}

async fn commande_cle_symmetrique<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_cle_symmetrique Consommer commande : {:?}", & m.message);
    let commande: CommandeCleSymmetrique = deser_message_buffer!(m.message);

    // Verifier que le certificat est pour l'instance locale
    // (note : pas garanti - confusion entre plusieurs certificats locaux possible, e.g. mongo et sqlite)
    let enveloppe_secrete = middleware.get_enveloppe_signature();
    let fingerprint = enveloppe_secrete.fingerprint()?;
    let instance_id = enveloppe_secrete.enveloppe_pub.get_common_name()?;

    if commande.fingerprint.as_str() != fingerprint.as_str() {
        Err(format!("commande_cle_symmetrique Mauvais fingerprint, skip"))?
    }

    // Dechiffrage de la cle, mise en memoire - si echec, on ne peut pas dechiffrer la cle
    gestionnaire.handler_rechiffrage.set_cle_symmetrique(commande.cle.as_str())?;

    let cle_locale = doc! {
        "type": "local",
        "instance_id": instance_id,
        "fingerprint": fingerprint.as_str(),
        "cle": commande.cle.as_str(),
    };

    debug!("commande_cle_symmetrique Inserer cle configuration locale {:?}", commande.cle);

    let collection = middleware.get_collection(NOM_COLLECTION_CONFIGURATION)?;
    collection.insert_one(cle_locale, None).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

/// Commande recue d'un client (e.g. Coup D'Oeil) avec une batch de cles secretes dechiffrees.
/// La commande est chiffree pour tous les MaitreDesComptes (kind:8)
async fn commande_rechiffrer_batch<M>(middleware: &M, mut m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + CleChiffrageHandler
{
    debug!("commande_rechiffrer_batch Message {:?}\n{}", m.type_message, from_utf8(m.message.buffer.as_slice())?);
    let message_ref = m.message.parse()?;
    let correlation_id = match &m.type_message {
        TypeMessageOut::Commande(r) => {
            match r.correlation_id.as_ref() { Some(inner) => inner.clone(), None => message_ref.id.to_owned() }
        },
        _ => Err(Error::Str("commande_rechiffrer_batch Mauvais type de message - doit etre commande"))?
    };

    let enveloppe_privee = middleware.get_enveloppe_signature();
    let commande: CommandeRechiffrerBatch = message_ref.dechiffrer(enveloppe_privee.as_ref())?;

    // let message_chiffre: MessageReponseChiffree = message_ref.contenu()?.deserialize()?;
    // let message_dechiffre = message_chiffre.dechiffrer(middleware)?;
    // let commande: CommandeRechiffrerBatch = serde_json::from_slice(&message_dechiffre.data_dechiffre[..])?;

    let fingerprint_ca = enveloppe_privee.enveloppe_ca.fingerprint()?;
    let fingerprint = enveloppe_privee.enveloppe_pub.fingerprint()?;

    // debug!("commande_rechiffrer_batch Consommer commande : {:?}", &m.message);
    let nom_collection_cles = match gestionnaire.get_collection_cles()? {
        Some(c) => c,
        None => Err(Error::Str("maitredescles_partition.commande_rechiffrer_batch Gestionnaire sans partition/certificat"))?
    };
    let collection = middleware.get_collection(nom_collection_cles.as_str())?;

    // Traiter chaque cle individuellement
    // let liste_cles: Vec<CleSynchronisation> = commande.cles.iter().map(|c| {
    //     //c.hachage_bytes.to_owned()
    //     //CleSynchronisation { hachage_bytes: c.hachage_bytes.clone(), domaine: c.domaine.clone() }
    //     CleSynchronisation { cle_id: c.hachage_bytes.clone(), domaine: c.domaine.clone() }
    // }).collect();
    let mut liste_cle_id: Vec<String> = Vec::new();
    for cle in commande.cles {
        let cle_id = sauvegarder_cle_rechiffrage(
            middleware, &gestionnaire, nom_collection_cles.as_str(), cle).await?;
        liste_cle_id.push(cle_id);
    }

    // Emettre un evenement pour confirmer le traitement.
    // Utilise par le CA (confirme que les cles sont dechiffrables) et par le client (batch traitee)
    let routage_event = RoutageMessageAction::builder(
        DOMAINE_NOM, EVENEMENT_CLE_RECUE_PARTITION, vec![Securite::L4Secure])
        .build();
    let event_contenu = json!({
        "correlation": correlation_id,
        CHAMP_LISTE_CLE_ID: liste_cle_id,
    });
    middleware.emettre_evenement(routage_event, &event_contenu).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn sauvegarder_cle_rechiffrage<M>(middleware: &M,
                                        gestionnaire: &GestionnaireMaitreDesClesPartition,
                                        nom_collection_cles: &str,
                                        cle: CleSecreteRechiffrage)
    -> Result<String, Error>
    where M: MongoDao
{
    let collection = middleware.get_collection(nom_collection_cles)?;
    let (cle_id, cle_rechiffree) = cle.rechiffrer_cle(&gestionnaire.handler_rechiffrage)?;

    let filtre = doc!{CHAMP_CLE_ID: &cle_id};
    let mut set_on_insert = doc!{
        "dirty": true,
        "confirmation_ca": false,
        CHAMP_CREATION: Utc::now(),
        // CHAMP_CLE_ID: &cle_id,
        CHAMP_CLE_SYMMETRIQUE: cle_rechiffree.cle,
        CHAMP_NONCE_SYMMETRIQUE: cle_rechiffree.nonce,
        "signature": convertir_to_bson(&cle.signature)?,
    };

    // Supporter l'ancienne version de cles
    match cle.signature.version {
        SignatureDomainesVersion::NonSigne => {
            // set_on_insert.insert(CHAMP_HACHAGE_BYTES, cle.signature.signature.as_str());
            set_on_insert.insert("format", cle.format.as_ref());
            set_on_insert.insert("header", cle.header.as_ref());
        },
        _ => ()
    }

    let ops = doc! {
        "$setOnInsert": set_on_insert,
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let opts = UpdateOptions::builder().upsert(true).build();
    collection.update_one(filtre, ops, opts).await?;

    Ok(cle_id)

    // let mut doc_cle = convertir_to_bson(cle.clone())?;
    // doc_cle.remove("cleSecrete");
    // doc_cle.insert("dirty", true);
    // doc_cle.insert("confirmation_ca", false);
    // doc_cle.insert(CHAMP_CREATION, Utc::now());
    // doc_cle.insert(CHAMP_MODIFICATION, Utc::now());
    // doc_cle.insert(CHAMP_CLE_REF, cle_ref.as_str());
    //
    // // Retirer le champ cles
    // doc_cle.remove(CHAMP_CLES);
    //
    // // Inserer la cle pour cette partition
    // // doc_cle.insert(TRANSACTION_CLE, cle_chiffree_str);
    // doc_cle.insert(TRANSACTION_CLE, "");
    //
    // doc_cle.insert(CHAMP_CLE_SYMMETRIQUE, cle_rechiffree.cle);
    // doc_cle.insert(CHAMP_NONCE_SYMMETRIQUE, cle_rechiffree.nonce);
    //
    // let filtre = doc! { CHAMP_CLE_REF: cle_ref.as_str() };
    // let ops = doc! { "$setOnInsert": doc_cle };
    // let opts = UpdateOptions::builder().upsert(true).build();
    // collection.update_one(filtre, ops, opts).await?;
    //
    // Ok(cle_ref)
}

async fn aiguillage_transaction<M>(middleware: &M, transaction: TransactionValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let action = match transaction.transaction.routage.as_ref() {
        Some(inner) => match inner.action.as_ref() {
            Some(inner) => inner.clone(),
            None => Err(Error::String(format!("core_backup.aiguillage_transaction: Transaction {} n'a pas d'action", transaction.transaction.id)))?
        },
        None => Err(Error::String(format!("core_backup.aiguillage_transaction: Transaction {} n'a pas de routage", transaction.transaction.id)))?
    };

    match action {
        // TRANSACTION_CLE => transaction_cle(middleware, transaction, gestionnaire).await,
        _ => Err(Error::String(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.transaction.id, action))),
    }
}

async fn requete_dechiffrage<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + CleChiffrageHandler
{
    warn!("requete_dechiffrage Consommer requete OBSOLETE : {:?}", & m.message);
    return Ok(Some(middleware.reponse_err(99, None, Some("obsolete"))?))

    // let message_ref = m.message.parse()?;
    // let requete: RequeteDechiffrage = match message_ref.contenu()?.deserialize() {
    //     Ok(inner) => inner,
    //     Err(e) => {
    //         info!("requete_dechiffrage Erreur mapping ParametresGetPermissionMessages : {:?}", e);
    //         return Ok(Some(middleware.reponse_err(None, None, Some(format!("Erreur mapping requete : {:?}", e).as_str()))?))
    //     }
    // };
    //
    // // Supporter l'ancien format de requete (liste_hachage_bytes) avec le nouveau (cle_ids)
    // let cle_ids = match requete.cle_ids.as_ref() {
    //     Some(inner) => inner,
    //     None => match requete.liste_hachage_bytes.as_ref() {
    //         Some(inner) => inner,
    //         None => Err(Error::Str("Aucunes cles demandees pour le rechiffrage"))?
    //     }
    // };
    //
    // // Verifier que la requete est autorisee
    // let (certificat, requete_autorisee_globalement) = match verifier_permission_rechiffrage(middleware, &m, &requete).await {
    //     Ok(inner) => inner,
    //     Err(ErreurPermissionRechiffrage::Refuse(e)) => {
    //         let refuse = json!({"ok": false, "err": e.err, "acces": "0.refuse", "code": e.code});
    //         return Ok(Some(middleware.build_reponse(&refuse)?.0))
    //     },
    //     Err(ErreurPermissionRechiffrage::Error(e)) => Err(e)?
    // };
    //
    // let enveloppe_privee = middleware.get_enveloppe_signature();
    // let fingerprint = enveloppe_privee.fingerprint()?;
    //
    // // Trouver les cles demandees et rechiffrer
    // let mut curseur = preparer_curseur_cles(
    //     middleware, gestionnaire, &requete, Some(&vec![requete.domaine.to_string()])).await?;
    // let (mut cles, cles_trouvees) = rechiffrer_cles(
    //     middleware, gestionnaire,
    //     &m, &requete, enveloppe_privee.clone(), certificat.as_ref(),
    //     requete_autorisee_globalement, &mut curseur).await?;
    //
    // let nom_collection = match gestionnaire.get_collection_cles()? {
    //     Some(n) => n,
    //     None => Err(Error::Str("maitredescles_partition.preparer_curseur_cles Collection cles n'est pas definie"))?
    // };
    //
    // // Verifier si on a des cles inconnues
    // if cles.len() < cle_ids.len() {
    //     debug!("requete_dechiffrage Cles manquantes, on a {} trouvees sur {} demandees", cles.len(), cle_ids.len());
    //
    //     error!("requete_dechiffrage Requete Cle non dechiffrages, fix me");  // TODO
    //     // todo!("fix me")
    //
    //     // let cles_connues = cles.keys().map(|s|s.to_owned()).collect();
    //     // // emettre_cles_inconnues(middleware, requete, cles_connues).await?;
    //     // let cles_recues = match requete_cles_inconnues(
    //     //     middleware, &requete, cles_connues).await
    //     // {
    //     //     Ok(reponse) => {
    //     //         debug!("Reponse cles manquantes : {:?}", reponse.cles);
    //     //         reponse.cles
    //     //     },
    //     //     Err(e) => {
    //     //         error!("requete_dechiffrage Erreur requete_cles_inconnues, skip : {:?}", e);
    //     //         Vec::new()
    //     //     }
    //     // };
    //     //
    //     // debug!("Reponse cle manquantes recue : {:?}", cles_recues);
    //     // for cle in cles_recues.into_iter() {
    //     //
    //     //     let hachage_bytes = cle.hachage_bytes.clone();
    //     //
    //     //     let cle_secrete = cle.get_cle_secrete()?;
    //     //     let (_, cle_rechiffree) = cle.rechiffrer_cle(&gestionnaire.handler_rechiffrage)?;
    //     //
    //     //     let mut doc_cle: RowClePartition = cle.try_into()?;
    //     //     doc_cle.cle_symmetrique = Some(cle_rechiffree.cle);
    //     //     doc_cle.nonce_symmetrique = Some(cle_rechiffree.nonce);
    //     //
    //     //     let cle_interne = CleSecreteRechiffrage::from_doc_cle(cle_secrete, doc_cle.clone())?;
    //     //
    //     //     sauvegarder_cle_rechiffrage(middleware, &gestionnaire,
    //     //         nom_collection.as_str(),
    //     //         cle_interne).await?;
    //     //
    //     //     match rechiffrer_cle(&mut doc_cle, &gestionnaire.handler_rechiffrage, certificat.as_ref()) {
    //     //         Ok(()) => {
    //     //             cles.insert(hachage_bytes, doc_cle);
    //     //         },
    //     //         Err(e) => {
    //     //             error!("rechiffrer_cles Erreur rechiffrage cle {:?}", e);
    //     //             continue;  // Skip cette cle
    //     //         }
    //     //     }
    //     // }
    // }
    //
    // // Preparer la reponse
    // // Verifier si on a au moins une cle dans la reponse
    // let reponse = if cles.len() > 0 {
    //     let reponse = json!({
    //         "acces": CHAMP_ACCES_PERMIS,
    //         "code": 1,
    //         "cles": &cles,
    //     });
    //     debug!("requete_dechiffrage Reponse rechiffrage {:?} : {:?}", m.type_message, reponse);
    //     middleware.build_reponse(reponse)?.0
    // } else {
    //     // On n'a pas trouve de cles
    //     debug!("requete_dechiffrage Requete {:?} de dechiffrage {:?}, cles inconnues", m.type_message, &requete.liste_hachage_bytes);
    //
    //     // Retourner cle inconnu a l'usager
    //     let inconnu = json!({"ok": false, "err": "Cles inconnues", "acces": CHAMP_ACCES_CLE_INCONNUE, "code": 4});
    //     middleware.build_reponse(&inconnu)?.0
    // };
    //
    // Ok(Some(reponse))
}

async fn requete_dechiffrage_v2<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
                                -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + CleChiffrageHandler
{
    debug!("requete_dechiffrage_v2 Consommer requete : {:?}", & m.type_message);
    let message_ref = m.message.parse()?;
    let requete: RequeteDechiffrage = match message_ref.contenu()?.deserialize() {
        Ok(inner) => inner,
        Err(e) => {
            info!("requete_dechiffrage_v2 Erreur mapping ParametresGetPermissionMessages : {:?}", e);
            // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": format!("Erreur mapping requete : {:?}", e)}), None)?))
            return Ok(Some(middleware.reponse_err(None, None, Some(format!("Erreur mapping requete : {:?}", e).as_str()))?))
        }
    };

    // Supporter l'ancien format de requete (liste_hachage_bytes) avec le nouveau (cle_ids)
    let cle_ids = match requete.cle_ids.as_ref() {
        Some(inner) => inner,
        None => match requete.liste_hachage_bytes.as_ref() {
            Some(inner) => inner,
            None => Err(Error::Str("Aucunes cles demandees pour le rechiffrage"))?
        }
    };

    // Verifier que la requete est autorisee
    let (certificat, requete_autorisee_globalement) = match verifier_permission_rechiffrage(middleware, &m, &requete).await {
        Ok(inner) => inner,
        Err(ErreurPermissionRechiffrage::Refuse(e)) => {
            let refuse = json!({"ok": false, "err": e.err, "acces": "0.refuse", "code": e.code});
            return Ok(Some(middleware.build_reponse(&refuse)?.0))
        },
        Err(ErreurPermissionRechiffrage::Error(e)) => Err(e)?
    };

    let enveloppe_privee = middleware.get_enveloppe_signature();
    let fingerprint = enveloppe_privee.fingerprint()?;

    // Recuperer les cles et dechiffrer
    let mut cles = Vec::new();

    let nom_collection = match gestionnaire.get_collection_cles()? {
        Some(inner) => inner, None => Err(Error::Str("Nom de collection pour les cles est manquant"))?
    };

    let requete_cle_ids = match requete.cle_ids.as_ref() {
        Some(inner) => inner,
        None => match requete.liste_hachage_bytes.as_ref() {
            Some(inner) => inner,
            None => {
                info!("requete_dechiffrage_v2 requete sans cle_ids ni liste_hachage_bytes");
                return Ok(Some(middleware.reponse_err(1, None, Some("Requete sans cle_ids ni liste_hachage_bytes"))?))
            }
        }
    };

    let filtre = doc! {
        CHAMP_CLE_ID: {"$in": requete_cle_ids},
        // "signature.domaines": {"$in": vec![&requete.domaine]}
    };
    // filtre.insert("signature.domaines", doc!{"$in": vec![&requete.domaine]});
    let collection = middleware.get_collection_typed::<RowClePartition>(nom_collection.as_str())?;
    let mut curseur = collection.find(filtre, None).await?;
    let domaine: heapless::String<40> = requete.domaine.as_str().try_into()
        .map_err(|_| Error::Str("Erreur map domain dans heapless::String<40>"))?;

    // Compter les cles trouvees separement de la liste. On rejete des cles qui ont un mismatch de domaine
    // mais elles comptent sur le total trouve.
    let mut cles_trouvees = 0;

    while let Some(row) = curseur.next().await {
        match row {
            Ok(inner) => {
                cles_trouvees += 1;
                if inner.signature.domaines.contains(&domaine) {
                    match inner.to_cle_secrete_serialisee(gestionnaire.handler_rechiffrage.as_ref()) {
                        Ok(inner) => cles.push(inner),
                        Err(e) => {
                            warn!("Erreur mapping / dechiffrage cle - SKIP : {:?}", e);
                            continue
                        }
                    }
                } else {
                    warn!("requete_dechiffrage_v2 Requete de cle rejetee, domaines {:?} ne match pas la cle {}", inner.signature.domaines, inner.cle_id);
                }
            },
            Err(e) => {
                warn!("requete_dechiffrage_v2 Erreur mapping cle, SKIP : {:?}", e);
                continue
            }
        }
    }

    // Verifier si on a des cles inconnues
    // En cas de cles inconnues, et si on a plusieurs maitre des cles, faire une requete
    let nombre_maitre_des_cles = middleware.get_publickeys_chiffrage().len();
    if cles_trouvees < cle_ids.len() && nombre_maitre_des_cles > 1 {
        debug!("requete_dechiffrage_v2 Cles manquantes, on a {} trouvees sur {} demandees", cles.len(), cle_ids.len());

        // Identifier les cles manquantes
        let mut cles_hashset = HashSet::new();
        for item in cle_ids {
            cles_hashset.insert(item.as_str());
        }
        for item in &cles {
            if let Some(cle_id) = &item.cle_id {
                cles_hashset.remove(cle_id.as_str());
            }
        }

        // Effectuer une requete pour verifier si les cles sont connues d'un autre maitre des cles
        let liste_cles: Vec<String> = cles_hashset.iter().map(|m| m.to_string()).collect();
        let requete_transfert = RequeteTransfert {
            fingerprint,
            cle_ids: liste_cles,
            toujours_repondre: Some(true),
        };
        let data_reponse = effectuer_requete_cles_manquantes(
            middleware, &requete_transfert).await.unwrap_or_else(|e| {
            error!("traiter_batch_synchroniser_cles Erreur requete cles manquantes : {:?}", e);
            None
        });
        if let Some(data_reponse) = data_reponse {
            debug!("traiter_batch_synchroniser_cles Recu {}/{} cles suite a requete de cles manquantes",
                data_reponse.cles.len(), cles_hashset.len());
            for cle in data_reponse.cles {
                let cle_id = cle.signature.get_cle_ref()?;
                let mut cle_secrete_bytes = [0u8; 32];
                cle_secrete_bytes.copy_from_slice(&base64_nopad.decode(cle.cle_secrete_base64.as_str())?[0..32]);
                let cle_secrete = CleSecreteX25519 {0: cle_secrete_bytes};

                // Ajouter la cle serialisee a la liste des reponses
                let cle_serialisee = CleSecreteSerialisee::from_cle_secrete(
                    cle_secrete.clone(), Some(cle_id.as_str()), cle.format.clone(), cle.nonce.as_ref(), cle.verification.as_ref())?;
                cles.push(cle_serialisee);

                // Sauvegarder la nouvelle cle
                if let Err(e) = sauvegarder_cle_secrete(middleware, gestionnaire, cle.signature.clone(), &cle_secrete).await {
                    error!("traiter_batch_synchroniser_cles Erreur sauvegarde cle {} : {:?}", cle_id, e);
                }
            }
        }
    }

    // Preparer la reponse
    // Verifier si on a au moins une cle dans la reponse
    let reponse = if cles.len() > 0 {
        let reponse = ReponseRequeteDechiffrageV2 { ok: true, code: 1, cles: Some(cles), err: None };
        middleware.build_reponse_chiffree(reponse, certificat.as_ref())?.0
    } else {
        // On n'a pas trouve de cles
        debug!("requete_dechiffrage_v2 Requete {:?} de dechiffrage {:?}, cles inconnues", m.type_message, &cle_ids);

        // Retourner cle inconnu a l'usager
        let inconnu = json!({"ok": false, "err": "Cles inconnues", "acces": CHAMP_ACCES_CLE_INCONNUE, "code": 4});
        let reponse = ReponseRequeteDechiffrageV2 {
            ok: false,
            code: 4,
            cles: None,
            err: Some("Cles inconnues".to_string())
        };
        middleware.build_reponse(&inconnu)?.0
    };

    Ok(Some(reponse))
}

#[derive(Serialize)]
struct ReponseDechiffrageMessage {
    ok: bool,
    cle_secrete_base64: String
}

async fn requete_dechiffrage_message<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
                                   -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + CleChiffrageHandler
{
    debug!("requete_dechiffrage_message Consommer requete : {:?}", & m.type_message);

    // Une requete de dechiffrage de message doit etre effectuee par un module backend (Securite 3 ou 4).
    if ! m.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
        return Ok(Some(middleware.reponse_err(401, None, Some("Acces refuse"))?))
    }

    let message_ref = m.message.parse()?;
    let requete: RequeteDechiffrageMessage = match message_ref.contenu()?.deserialize() {
        Ok(inner) => inner,
        Err(e) => {
            info!("requete_dechiffrage_message Erreur mapping RequeteDechiffrageMessage : {:?}", e);
            return Ok(Some(middleware.reponse_err(Some(500), None, Some(format!("Erreur mapping requete : {:?}", e).as_str()))?))
        }
    };

    let enveloppe_signature = middleware.get_enveloppe_signature();
    let fingerprint = enveloppe_signature.fingerprint()?;

    let cle_chiffree = match requete.cles.get(fingerprint.as_str()) {
        Some(inner) => inner.as_str(),
        None => return Ok(Some(middleware.reponse_err(3, None, Some("Cles non supportees"))?))
    };

    debug!("requete_dechiffrage_message Decoder cle chiffree {}", cle_chiffree);

    let cle_bytes = base64_nopad.decode(cle_chiffree)?;
    let cle_dechiffree = dechiffrer_asymmetrique_ed25519(cle_bytes.as_slice(), &enveloppe_signature.cle_privee)?;

    // Verifier que le domaine est inclus dans la signature
    if let Err(_) = requete.signature.verifier_derivee(&cle_dechiffree.0) {
        return Ok(Some(middleware.reponse_err(4, None, Some("Signature domaines invalide"))?))
    }

    // Verifier que le certificat donne acces a au moins 1 domaine dans la signature
    let domaines_permis: Vec<String> = requete.signature.domaines.iter().map(|d| d.to_string()).collect();
    if ! m.certificat.verifier_domaines(domaines_permis)? {
        return Ok(Some(middleware.reponse_err(5, None, Some("Acces pour domaines refuse"))?))
    }

    let cle_secrete_base64 = base64_nopad.encode(cle_dechiffree.0);

    let reponse = ReponseDechiffrageMessage { ok: true, cle_secrete_base64 };
    Ok(Some(middleware.build_reponse_chiffree(reponse, m.certificat.as_ref())?.0))
}

/// Methode qui repond a un maitre des cles avec la liste complete des cles demandees. Si la liste
/// ne peut etre completee, une commande de transfert de cles emets la liste partielle chiffrees
/// pour tous les maitre des cles.
async fn requete_transfert_cles<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + CleChiffrageHandler
{
    debug!("requete_transfert_cles Consommer requete : {:?}", & m.type_message);

    // Verifier que la requete provient d'un maitre des cles
    if ! m.certificat.verifier_roles(vec![RolesCertificats::MaitreDesCles])? {
        Err(Error::Str("requete_transfert_cles Requete qui ne provient pas d'un maitre des cles (role), SKIP"))?
    }
    if ! m.certificat.verifier_domaines(vec![DOMAINE_NOM.to_string()])? {
        Err(Error::Str("requete_transfert_cles Requete qui ne provient pas d'un maitre des cles (domaine), SKIP"))?
    }
    if ! m.certificat.verifier_exchanges(vec![Securite::L3Protege])? {
        Err(Error::Str("requete_transfert_cles Requete qui ne provient pas d'un certificat 3.protege, SKIP"))?
    }

    let message_ref = m.message.parse()?;
    let requete: RequeteTransfert = match message_ref.contenu()?.deserialize() {
        Ok(inner) => inner,
        Err(e) => {
            error!("requete_transfert_cles Erreur mapping RequeteTransfert : {:?}", e);
            return Ok(Some(middleware.reponse_err(None, None, Some(format!("requete_transfert_cles Erreur mapping requete : {:?}", e).as_str()))?))
        }
    };

    // Verifier si on a emis cette requete de transfert (localement)
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let fingerprint = enveloppe_privee.fingerprint()?;
    if requete.fingerprint.as_str() == fingerprint.as_str() {
        debug!("requete_transfert_cles Requete emise par le maitre de cle local (c'est notre requete), on l'ignore");
        return Ok(None)
    }

    // Recuperer les cles et dechiffrer
    let mut cles = Vec::new();

    let nom_collection = match gestionnaire.get_collection_cles()? {
        Some(inner) => inner, None => Err(Error::Str("requete_transfert_cles Nom de collection pour les cles est manquant"))?
    };

    let filtre = doc! { CHAMP_CLE_ID: {"$in": &requete.cle_ids} };
    let collection = middleware.get_collection_typed::<RowClePartition>(nom_collection.as_str())?;
    let mut curseur = collection.find(filtre, None).await?;

    while let Some(row) = curseur.next().await {
        match row {
            Ok(row_cle) => {
                let signature = row_cle.signature.clone();
                match row_cle.to_cle_secrete_serialisee(gestionnaire.handler_rechiffrage.as_ref()) {
                    Ok(inner) => {
                        let cle = CleTransfert {
                            cle_secrete_base64: inner.cle_secrete_base64.to_string(),
                            signature,
                            format: inner.format.clone(),
                            nonce: match inner.nonce.as_ref() { Some(inner) => Some(inner.to_string()), None => None },
                            verification: match inner.verification.as_ref() { Some(inner) => Some(inner.to_string()), None => None },
                        };
                        cles.push(cle)
                    },
                    Err(e) => {
                        warn!("requete_transfert_cles Erreur mapping / dechiffrage cle - SKIP : {:?}", e);
                        continue
                    }
                }
            },
            Err(e) => {
                warn!("requete_transfert_cles Erreur mapping cle, SKIP : {:?}", e);
                continue
            }
        }
    }

    // Verifier si on a des cles inconnues
    let toujours_repondre = requete.toujours_repondre.unwrap_or_else(||false);
    let nombre_cles_trouvees = cles.len();
    let toutes_cles_trouvees = nombre_cles_trouvees == requete.cle_ids.len();
    let repondre = toujours_repondre || toutes_cles_trouvees;

    let reponse = CommandeTransfertClesV2 {
        fingerprint_emetteur: fingerprint,
        cles,
    };

    if repondre {
        // On a la liste complete ou on doit toujours repondre.
        info!("requete_transfert_cles Repondre avec {} cles", nombre_cles_trouvees);
        Ok(Some(middleware.build_reponse_chiffree(reponse, m.certificat.as_ref())?.0))
    } else if ! toutes_cles_trouvees {
        info!("requete_transfert_cles Cles manquantes, on a {} trouvees sur {} demandees", nombre_cles_trouvees, requete.cle_ids.len());
        // Generer une commande de transfert de cles pour tous les maitres des cles avec la liste partielle
        // Va permettre a plusieurs maitres des cles de repondre avec leur liste au besoin
        let cles_chiffrage_vec = middleware.get_publickeys_chiffrage();
        let routage = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_TRANSFERT_CLE, vec![Securite::L3Protege])
            .build();
        let commande_chiffree = middleware.build_message_action_chiffre(
            millegrilles_cryptographie::messages_structs::MessageKind::CommandeInterMillegrille,
            routage, reponse, cles_chiffrage_vec)?.0;
        Ok(Some(commande_chiffree))
    } else {
        debug!("requete_transfert_cles Cles manquantes, on n'a aucunes cles a transmettre, SKIP");
        Ok(None)
    }
}

/// Verifie que la requete contient des cles secretes qui correspondent aux cles stockees.
/// Confirme que le demandeur a bien en sa possession (via methode tierce) les cles secretes.
async fn requete_verifier_preuve<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao +  ValidateurX509 + CleChiffrageHandler
{
    let nom_collection = match gestionnaire.get_collection_cles()? {
        Some(n) => n,
        None => Err(Error::Str("maitredescles_partition.requete_verifier_preuve Collection cles n'est pas definie"))?
    };

    debug!("requete_verifier_preuve Consommer requete : {:?}", & m.message);
    let message_ref = m.message.parse()?;
    let requete: RequeteVerifierPreuve = message_ref.contenu()?.deserialize()?;
    debug!("requete_verifier_preuve cle parsed : {:?}", requete);

    let certificat = m.certificat.as_ref();
    let extensions = certificat.extensions()?;
    let domaines = match extensions.domaines {
        Some(inner) => inner,
        None => Err(Error::Str("maitredescles_partition.requete_verifier_preuve Certificat sans domaines"))?
    };

    // La preuve doit etre recente (moins de 5 minutes)
    let date_now = Utc::now();
    let date_valid_min = date_now - Duration::minutes(5);  // Expiration
    let date_valid_max = date_now + Duration::minutes(2);  // Futur - systime sync issue
    {
        let datetime_estampille = &message_ref.estampille;
        // let datetime_estampille = estampille.get_datetime();
        if &date_valid_min > datetime_estampille || &date_valid_max < datetime_estampille {
            Err(format!("maitredescles_partition.requete_verifier_preuve Demande preuve est expiree ({:?})", datetime_estampille))?;
        }
    }

    let enveloppe_privee = middleware.get_enveloppe_signature();

    // Preparer une liste de verification pour chaque cle par hachage_bytes
    let mut map_validite_fuuid = HashMap::new();  // fuuid = valide(true/false)
    let mut liste_hachage_bytes = Vec::new();
    for (cle, _) in requete.preuves.iter() {
        map_validite_fuuid.insert(cle.clone(), false);
        liste_hachage_bytes.push(cle);
    }

    // Trouver les cles en reference
    let filtre = doc! {
        "domaine": {"$in": domaines},
        CHAMP_HACHAGE_BYTES: {"$in": liste_hachage_bytes}
    };
    debug!("requete_verifier_preuve Filtre cles sur collection {} : {:?}", nom_collection, filtre);

    let collection = middleware.get_collection_typed::<RowClePartition>(nom_collection.as_str())?;
    let mut curseur = collection.find(filtre, None).await?;

    let cle_privee = &enveloppe_privee.cle_privee;
    while let Some(rc) = curseur.next().await {
        let cle_mongo_chiffree = rc?;
        // let cle_mongo_chiffree: DocumentClePartition = match convertir_bson_deserializable(doc_cle) {
        //     Ok(c) => c,
        //     Err(e) => {
        //         error!("requete_verifier_preuve Erreur conversion bson vers TransactionCle : {:?}", e);
        //         continue
        //     }
        // };

        let cle_interne_chiffree = CleInterneChiffree::try_from(cle_mongo_chiffree.clone())?;
        let cle_mongo_dechiffree = gestionnaire.handler_rechiffrage.dechiffer_cle_secrete(cle_interne_chiffree)?;
        // let cle_mongo_dechiffree = extraire_cle_secrete(cle_privee, cle_mongo_chiffree.cle.as_str())?;
        todo!("fix me")
        // let hachage_bytes_mongo = cle_mongo_chiffree.hachage_bytes.as_str();
        //
        // debug!("requete_verifier_preuve Resultat mongo hachage_bytes {}", hachage_bytes_mongo);
        //
        // if let Some(cle_preuve) = requete.preuves.get(hachage_bytes_mongo) {
        //     let date_preuve = cle_preuve.date;
        //     if &date_valid_min > &date_preuve || &date_valid_max < &date_preuve {
        //         warn!("requete_verifier_preuve Date preuve {} invalide : {:?}", hachage_bytes_mongo, date_preuve);
        //         continue;  // Skip
        //     }
        //
        //     // Valider la preuve (hachage)
        //     let valide = match cle_preuve.verifier_preuve(requete.fingerprint.as_str(), &cle_mongo_dechiffree) {
        //         Ok(inner) => inner,
        //         Err(e) => {
        //             error!("Erreur verification preuve : {:?}", e);
        //             false
        //         }
        //     };
        //
        //     map_validite_fuuid.insert(hachage_bytes_mongo.to_string(), valide);
        // }
    }

    debug!("Resultat verification preuve : {:?}", map_validite_fuuid);

    // // Verifier toutes les cles qui n'ont pas ete identifiees dans la base de donnees (inconnues)
    // let liste_inconnues: Vec<String> = liste_verification.iter().filter(|(k, v)| match v {
    //     Some(_) => false,
    //     None => true
    // }).map(|(k,_)| k.to_owned()).collect();
    // for hachage_bytes in liste_inconnues.into_iter() {
    //     if let Some(info_cle) = map_hachage_bytes.remove(&hachage_bytes) {
    //         debug!("requete_verifier_preuve Conserver nouvelle cle {}", hachage_bytes);
    //
    //         todo!("Fix me");
    //         // let commande_cle = rechiffrer_pour_maitredescles(middleware, &info_cle)?;
    //         //
    //         // // Conserver la cle via commande
    //         // let partition = gestionnaire.fingerprint.as_str();
    //         // let routage = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE)
    //         //     .partition(partition)
    //         //     .build();
    //         // // Conserver la cle
    //         // // let commande_cle = info_cle.into_commande(partition);
    //         // // Transmettre commande de sauvegarde - on n'attend pas la reponse (deadlock)
    //         // middleware.transmettre_commande(routage, &commande_cle, false).await?;
    //         //
    //         // // Indiquer que la cle est autorisee (c'est l'usager qui vient de la pousser)
    //         // liste_verification.insert(hachage_bytes, Some(true));
    //     }
    // }

    // Preparer la reponse
    let reponse_json = json!({
        "verification": map_validite_fuuid,
    });
    let reponse = middleware.build_reponse(reponse_json)?.0;

    Ok(Some(reponse))
}

async fn rechiffrer_cles<M>(
    _middleware: &M,
    gestionnaire: &GestionnaireMaitreDesClesPartition,
    _m: &MessageValide,
    _requete: &RequeteDechiffrage,
    enveloppe_privee: Arc<EnveloppePrivee>,
    certificat: &EnveloppeCertificat,
    _requete_autorisee_globalement: bool,
    // _permission: Option<EnveloppePermission>,
    curseur: &mut Cursor<Document>
)
    -> Result<(HashMap<String, RowClePartition>, bool), Error>
    where M: ValidateurX509
{
    let mut cles: HashMap<String, RowClePartition> = HashMap::new();
    let mut cles_trouvees = false;  // Flag pour dire qu'on a matche au moins 1 cle

    let rechiffreur = &gestionnaire.handler_rechiffrage;

    while let Some(rc) = curseur.next().await {
        debug!("rechiffrer_cles document {:?}", rc);
        cles_trouvees = true;  // On a trouve au moins une cle
        match rc {
            Ok(doc_cle) => {
                let mut cle: RowClePartition = match convertir_bson_deserializable(doc_cle) {
                    Ok(c) => c,
                    Err(e) => {
                        error!("rechiffrer_cles Erreur conversion bson vers TransactionCle : {:?}", e);
                        continue
                    }
                };
                todo!("fix me")
                // let hachage_bytes = cle.hachage_bytes.clone();
                //
                // // match rechiffrer_cle(&mut cle, enveloppe_privee.as_ref(), certificat) {
                // match rechiffrer_cle(&mut cle, rechiffreur, certificat) {
                //     Ok(()) => {
                //         cles.insert(hachage_bytes, cle);
                //     },
                //     Err(e) => {
                //         error!("rechiffrer_cles Erreur rechiffrage cle {:?}", e);
                //         continue;  // Skip cette cle
                //     }
                // }
            },
            Err(e) => error!("rechiffrer_cles: Erreur lecture curseur cle : {:?}", e)
        }
    }

    Ok((cles, cles_trouvees))
}

/// Prepare le curseur sur les cles demandees
async fn preparer_curseur_cles<M>(
    middleware: &M,
    gestionnaire: &GestionnaireMaitreDesClesPartition,
    requete: &RequeteDechiffrage,
    // permission: Option<&EnveloppePermission>,
    domaines_permis: Option<&Vec<String>>
)
    -> Result<Cursor<Document>, Error>
    where M: MongoDao
{
    let nom_collection = match gestionnaire.get_collection_cles()? {
        Some(n) => n,
        None => Err(Error::Str("maitredescles_partition.preparer_curseur_cles Collection cles n'est pas definie"))?
    };

    // if permission.is_some() {
    //     Err(format!("Permission non supporte - FIX ME"))?;
    // }

    let mut filtre = doc! {CHAMP_HACHAGE_BYTES: {"$in": &requete.liste_hachage_bytes}};
    if let Some(d) = domaines_permis {
        filtre.insert("domaine", doc!{"$in": d});
    }
    debug!("requete_dechiffrage Filtre cles sur collection {} : {:?}", nom_collection, filtre);

    let collection = middleware.get_collection(nom_collection.as_str())?;
    Ok(collection.find(filtre, None).await?)
}

/// Verifier si la requete de dechiffrage est valide (autorisee) de maniere globale
/// Les certificats 4.secure et delegations globales proprietaire donnent acces a toutes les cles
// async fn verifier_autorisation_dechiffrage_global<M>(middleware: &M, m: &MessageValide, requete: &RequeteDechiffrage)
//     // -> Result<(bool, Option<EnveloppePermission>), Error>
//     -> Result<bool, Error>
//     where M:  ValidateurX509
// {
//     // Verifier si le certificat est une delegation globale
//     if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
//         debug!("verifier_autorisation_dechiffrage Certificat delegation globale proprietaire - toujours autorise");
//         return Ok(true)
//     }
//
//     Ok(false)
//
//     // Acces global refuse.
//     // On verifie la presence et validite d'une permission
//
//     // let mut permission: Option<EnveloppePermission> = None;
//     // if let Some(p) = &requete.permission {
//     //     debug!("verifier_autorisation_dechiffrage_global On a une permission, valider le message {:?}", p);
//     //     let mut ms = match MessageSerialise::from_parsed(p.to_owned()) {
//     //         Ok(ms) => Ok(ms),
//     //         Err(e) => Err(format!("verifier_autorisation_dechiffrage_global Erreur verification permission (2), refuse: {:?}", e))
//     //     }?;
//     //
//     //     // Charger le certificat dans ms
//     //     let resultat = ms.valider(middleware, None).await?;
//     //     if ! resultat.valide() {
//     //         Err(format!("verifier_autorisation_dechiffrage_global Erreur verification certificat permission (1), refuse: certificat invalide"))?
//     //     }
//     //
//     //     match ms.parsed.map_contenu::<PermissionDechiffrage>(None) {
//     //         Ok(contenu_permission) => {
//     //             // Verifier la date d'expiration de la permission
//     //             let estampille = &ms.get_entete().estampille.get_datetime().timestamp();
//     //             let duree_validite = contenu_permission.permission_duree as i64;
//     //             let ts_courant = Utc::now().timestamp();
//     //             if estampille + duree_validite > ts_courant {
//     //                 debug!("Permission encore valide (duree {}), on va l'utiliser", duree_validite);
//     //                 // Note : conserver permission "localement" pour return false global
//     //                 permission = Some(EnveloppePermission {
//     //                     enveloppe: ms.certificat.clone().expect("cert"),
//     //                     permission: contenu_permission
//     //                 });
//     //             }
//     //         },
//     //         Err(e) => info!("verifier_autorisation_dechiffrage_global Erreur verification permission (1), refuse: {:?}", e)
//     //     }
//     // }
//     //
//     // match permission {
//     //     Some(p) => {
//     //         // Verifier si le certificat de permission est une delegation globale
//     //         if p.enveloppe.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
//     //             debug!("verifier_autorisation_dechiffrage Certificat delegation globale proprietaire - toujours autorise");
//     //             return Ok((true, Some(p)))
//     //         }
//     //         // Utiliser regles de la permission
//     //         Ok((false, Some(p)))
//     //     },
//     //     None => Ok((false, None))
//     // }
//
// }

/// Rechiffre une cle secrete
// fn rechiffrer_cle(cle: &mut DocumentClePartition, rechiffreur: &HandlerCleRechiffrage, certificat_destination: &EnveloppeCertificat)
//     -> Result<(), Error>
// {
//     if certificat_destination.verifier_exchanges(vec![Securite::L4Secure]) {
//         // Ok, acces global
//     } else if certificat_destination.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
//         // Ok, acces global,
//     } else if certificat_destination.verifier_roles(vec![RolesCertificats::ComptePrive]) {
//         // Compte prive, certificats sont verifies par le domaine (relai de permission)
//     } else if certificat_destination.verifier_roles(vec![RolesCertificats::Stream]) &&
//         certificat_destination.verifier_exchanges(vec![Securite::L2Prive]) {
//         // Certificat de streaming - on doit se fier a l'autorisation pour garantir que c'est un fichier video/audio
//     } else {
//         Err(format!("maitredescles_partition.rechiffrer_cle Certificat sans user_id ni L4Secure, acces refuse"))?
//     }
//
//     let hachage_bytes = cle.hachage_bytes.as_str();
//
//     let cle_interne = CleInterneChiffree::try_from(cle.clone())?;
//     let cle_secrete = rechiffreur.dechiffer_cle_secrete(cle_interne)?;
//
//     // let cle_secrete = match cle.cle_symmetrique.as_ref() {
//     //     Some(cle_symmetrique) => {
//     //         match cle.nonce_symmetrique.as_ref() {
//     //             Some(nonce) => {
//     //                 let cle_interne = CleInterneChiffree { cle: cle_symmetrique.to_owned(), nonce: nonce.to_owned() };
//     //                 rechiffreur.dechiffer_cle_secrete(cle_interne)?
//     //             },
//     //             None => {
//     //                 Err(format!("rechiffrer_cles Nonce manquant pour {}", hachage_bytes))?
//     //             }
//     //         }
//     //     },
//     //     None => {
//     //         Err(format!("rechiffrer_cles Cle symmetrique manquant pour {}", hachage_bytes))?
//     //     }
//     // };
//
//     // let cle_originale = cle.cle.as_str();
//     // let cle_privee = privee.cle_privee();
//     let cle_publique = certificat_destination.certificat().public_key()?;
//     // let cle_rechiffree = rechiffrer_asymetrique_multibase(cle_privee, &cle_publique, cle_originale)?;
//     let cle_rechiffree = chiffrer_asymetrique_multibase(cle_secrete, &cle_publique)?;
//
//     // Remplacer cle dans message reponse
//     cle.cle = cle_rechiffree;
//
//     Ok(())
// }

// fn rechiffrer_cle(cle: &mut DocumentClePartition, privee: &EnveloppePrivee, certificat_destination: &EnveloppeCertificat)
//     -> Result<(), Error>
// {
//     if certificat_destination.verifier_exchanges(vec![Securite::L4Secure]) {
//         // Ok, acces global
//     } else if certificat_destination.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
//         // Ok, acces global,
//     } else if certificat_destination.verifier_roles(vec![RolesCertificats::ComptePrive]) {
//         // Compte prive, certificats sont verifies par le domaine (relai de permission)
//     } else if certificat_destination.verifier_roles(vec![RolesCertificats::Stream]) &&
//         certificat_destination.verifier_exchanges(vec![Securite::L2Prive]) {
//         // Certificat de streaming - on doit se fier a l'autorisation pour garantir que c'est un fichier video/audio
//     } else {
//         Err(format!("maitredescles_partition.rechiffrer_cle Certificat sans user_id ni L4Secure, acces refuse"))?
//     }
//
//     let cle_originale = cle.cle.as_str();
//     let cle_privee = privee.cle_privee();
//     let cle_publique = certificat_destination.certificat().public_key()?;
//
//     let cle_rechiffree = rechiffrer_asymetrique_multibase(cle_privee, &cle_publique, cle_originale)?;
//
//     // Remplacer cle dans message reponse
//     cle.cle = cle_rechiffree;
//
//     Ok(())
// }

async fn synchroniser_cles<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition) -> Result<(), Error>
    where M: GenerateurMessages + MongoDao +  CleChiffrageHandler
{
    debug!("synchroniser_cles Debut");
    if ! gestionnaire.handler_rechiffrage.is_ready() {
       Err(format!("maitredescles_partition.synchroniser_cles Rechiffreur n'est pas initialise"))?
    }

    // Requete vers CA pour obtenir la liste des cles connues
    let mut requete_sync = RequeteSynchroniserCles {page: 0, limite: 1000};
    let routage_sync = RoutageMessageAction::builder(DOMAINE_NOM, REQUETE_SYNCHRONISER_CLES, vec![Securite::L4Secure])
        .build();

    loop {
        let reponse: ReponseSynchroniserCles = match middleware.transmettre_requete(routage_sync.clone(), &requete_sync).await? {
            Some(inner) => match inner {
                TypeMessage::Valide(reponse) => deser_message_buffer!(reponse.message),
                _ => {
                    warn!("synchroniser_cles Mauvais type de reponse recu, on abort");
                    break
                }
            },
            None => {
                warn!("synchroniser_cles Aucune reponse recue, on abort");
                break
            }
        };
        requete_sync.page += 1;  // Incrementer page pour prochaine requete

        if reponse.liste_cle_id.len() == 0 {
            debug!("Traitement sync termine");
            break
        }

        if let Err(e) = traiter_batch_synchroniser_cles(middleware, gestionnaire, reponse).await {
            error!("synchroniser_cles Erreur traitement batch cles : {:?}", e);
        }
    }

    debug!("synchroniser_cles Fin");

    Ok(())
}

async fn traiter_batch_synchroniser_cles<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition, reponse: ReponseSynchroniserCles)
    -> Result<(), Error>
    where M: MongoDao + GenerateurMessages
{
    let liste_cles = reponse.liste_cle_id;

    let mut cles_hashset = HashSet::new();
    for item in &liste_cles {
        cles_hashset.insert(item.as_str());
    }

    debug!("traiter_batch_synchroniser_cles Recu liste_hachage_bytes a verifier : {} cles", liste_cles.len());
    let filtre_cles = doc! {"cle_id": { "$in": &liste_cles } };
    let projection = doc! { CHAMP_CLE_ID: 1 };
    let find_options = FindOptions::builder().projection(projection).build();

    let nom_collection = match gestionnaire.get_collection_cles()? {
        Some(n) => n,
        None => Err(Error::Str("maitredescles_partition.traiter_batch_synchroniser_cles Collection cles n'est pas definie"))?
    };

    let collection = middleware.get_collection_typed::<CleSynchronisation>(nom_collection.as_str())?;
    let mut cles = collection.find(filtre_cles, Some(find_options)).await?;
    while let Some(row) = cles.next().await {
        match row {
            Ok(inner) => {
                cles_hashset.remove(inner.cle_id.as_str());
            },
            Err(e) => {
                info!("traiter_batch_synchroniser_cles Erreur mapping cle : {:?}", e);
                continue
            }
        }
    }

    if cles_hashset.len() > 0 {
        debug!("traiter_batch_synchroniser_cles Cles absentes localement : {} cles", cles_hashset.len());

        let enveloppe_signature = middleware.get_enveloppe_signature();
        let fingerprint = enveloppe_signature.fingerprint()?;

        // Emettre requete pour indiquer que ces cles sont manquantes dans la partition
        let liste_cles: Vec<String> = cles_hashset.iter().map(|m| m.to_string()).collect();
        let requete_transfert = RequeteTransfert {
            fingerprint,
            cle_ids: liste_cles,
            toujours_repondre: Some(false),
        };

        let data_reponse = effectuer_requete_cles_manquantes(
            middleware, &requete_transfert).await.unwrap_or_else(|e| {
            error!("traiter_batch_synchroniser_cles Erreur requete cles manquantes : {:?}", e);
            None
        });

        if let Some(data_reponse) = data_reponse {
            debug!("traiter_batch_synchroniser_cles Recu {} cles suite a la requete de cles manquantes", data_reponse.cles.len());
            let nom_collection_cles = match gestionnaire.get_collection_cles()? {
                Some(c) => c,
                None => Err(Error::Str("maitredescles_partition.commande_rechiffrer_batch Gestionnaire sans partition/certificat"))?
            };

            for cle in data_reponse.cles {
                let cle_id = cle.signature.get_cle_ref()?;

                match cle.signature.version {
                    SignatureDomainesVersion::NonSigne => {
                        // Obsolete, ancienne methode avec header/format
                        let format: Option<String> = match cle.format.clone() {
                            Some(inner) => {
                                let format_str: &str = inner.into();
                                Some(format_str.to_string())
                            },
                            None => None
                        };

                        let header = match cle.nonce.clone() {
                            Some(inner) => Some(format!("m{}", inner)),  // Ajouter 'm' multibase,
                            None => None
                        };

                        let cle_secrete_rechiffrage = CleSecreteRechiffrage {
                            signature: cle.signature.clone(),
                            cle_secrete: cle.cle_secrete_base64.clone(),
                            format,
                            header,
                        };

                        if let Err(e) = sauvegarder_cle_rechiffrage(middleware, gestionnaire, nom_collection_cles.as_str(), cle_secrete_rechiffrage).await {
                            error!("traiter_batch_synchroniser_cles Erreur sauvegarde cle {} : {:?}", cle_id, e);
                        }
                    }
                    _ => {
                        // Methode courante
                        let mut cle_secrete_bytes = [0u8; 32];
                        cle_secrete_bytes.copy_from_slice(&base64_nopad.decode(cle.cle_secrete_base64.as_str())?[0..32]);
                        let cle_secrete = CleSecreteX25519 {0: cle_secrete_bytes};
                        if let Err(e) = sauvegarder_cle_secrete(middleware, gestionnaire, cle.signature.clone(), &cle_secrete).await {
                            error!("traiter_batch_synchroniser_cles Erreur sauvegarde cle {} : {:?}", cle_id, e);
                        }
                    }
                }
            }
        }

        if cles_hashset.len() > 0 {
            info!("traiter_batch_synchroniser_cles Il reste {} cles non dechiffrables", cles_hashset.len());
        }
    }

    Ok(())
}

async fn effectuer_requete_cles_manquantes<M>(
    middleware: &M, requete_transfert: &RequeteTransfert)
    -> Result<Option<CommandeTransfertClesV2>, Error>
    where M: GenerateurMessages
{
    let delai_blocking = match &requete_transfert.toujours_repondre {
        Some(true) => 3_000,  // Requete live, temps court
        _ => 20_000,  // Requete batch, temps long
    };

    let routage_evenement_manquant = RoutageMessageAction::builder(
        DOMAINE_NOM, REQUETE_TRANSFERT_CLES, vec![Securite::L3Protege])
        .timeout_blocking(delai_blocking)
        .build();

    let data_reponse: Option<CommandeTransfertClesV2> = match middleware.transmettre_requete(
        routage_evenement_manquant.clone(), &requete_transfert).await
    {
        Ok(inner) => match inner {
            Some(inner) => match inner {
                TypeMessage::Valide(inner) => {
                    debug!("synchroniser_cles Reponse demande cles manquantes\n{}", from_utf8(inner.message.buffer.as_slice())?);
                    let message_ref = inner.message.parse()?;
                    let enveloppe_privee = middleware.get_enveloppe_signature();
                    match message_ref.dechiffrer(enveloppe_privee.as_ref()) {
                        Ok(inner) => Some(inner),
                        Err(e) => {
                            warn!("synchroniser_cles Erreur dechiffrage reponse : {:?}", e);
                            None
                        }
                    }
                },
                _ => {
                    warn!("synchroniser_cles Erreur reception reponse cles manquantes, mauvais type reponse.");
                    None
                }
            },
            None => {
                warn!("synchroniser_cles Erreur reception reponse cles manquantes, resultat None");
                None
            }
        },
        Err(e) => {
            warn!("synchroniser_cles Erreur reception reponse cles manquantes (e.g. timeout) : {:?}", e);
            None
        },
    };
    Ok(data_reponse)
}

/// S'assurer que le CA a toutes les cles de la partition. Permet aussi de resetter le flag non-dechiffrable.
async fn confirmer_cles_ca<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition, reset_flag: Option<bool>) -> Result<(), Error>
    where M: GenerateurMessages + MongoDao +  CleChiffrageHandler
{
    let batch_size = 200;
    let nom_collection = match gestionnaire.get_collection_cles()? {
        Some(n) => n,
        None => Err(Error::Str("maitredescles_partition.confirmer_cles_ca Collection cles n'est pas definie"))?
    };

    debug!("confirmer_cles_ca Debut confirmation cles locales avec confirmation_ca=false (reset flag: {:?}", reset_flag);
    if let Some(true) = reset_flag {
        info!("Reset flag confirmation_ca a false");
        let filtre = doc! { CHAMP_CONFIRMATION_CA: true };
        let ops = doc! { "$set": {CHAMP_CONFIRMATION_CA: false } };
        let collection = middleware.get_collection(nom_collection.as_str())?;
        collection.update_many(filtre, ops, None).await?;
    }

    let mut curseur = {
        // let limit_cles = 1000000;
        let filtre = doc! { CHAMP_CONFIRMATION_CA: false };
        let opts = FindOptions::builder()
            // .limit(limit_cles)
            .build();
        let collection = middleware.get_collection(nom_collection.as_str())?;
        let curseur = collection.find(filtre, opts).await?;
        curseur
    };

    let mut cles = Vec::new();
    while let Some(d) = curseur.next().await {
        match d {
            Ok(cle) => {
                let cle_synchronisation: CleSynchronisation = convertir_bson_deserializable(cle)?;
                cles.push(cle_synchronisation.cle_id);

                if cles.len() == batch_size {
                    emettre_cles_vers_ca(middleware, gestionnaire, &cles).await?;
                    cles.clear();  // Retirer toutes les cles pour prochaine page
                }
            },
            Err(e) => Err(format!("maitredescles_partition.confirmer_cles_ca Erreur traitement {:?}", e))?
        };
    }

    // Derniere batch de cles
    if cles.len() > 0 {
        emettre_cles_vers_ca(middleware, gestionnaire, &cles).await?;
        cles.clear();
    }

    debug!("confirmer_cles_ca Fin confirmation cles locales");

    Ok(())
}

/// Emet un message vers CA pour verifier quels cles sont manquantes (sur le CA)
/// Marque les cles presentes sur la partition et CA comme confirmation_ca=true
/// Rechiffre et emet vers le CA les cles manquantes
async fn emettre_cles_vers_ca<M>(
    middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition, liste_cles: &Vec<String>)
    -> Result<(), Error>
    where M: GenerateurMessages + MongoDao +  CleChiffrageHandler
{
    // let hachage_bytes: Vec<String> = cles.keys().into_iter().map(|h| h.to_owned()).collect();
    // let liste_cles: Vec<CleSynchronisation> = cles.into_iter().map(|h| {
    //     CleSynchronisation { hachage_bytes: h.hachage_bytes.clone(), domaine: h.domaine.clone() }
    // }).collect();
    debug!("emettre_cles_vers_ca Batch {:?} cles", liste_cles.len());

    let commande = ReponseSynchroniserCles { liste_cle_id: liste_cles.clone() };
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_CONFIRMER_CLES_SUR_CA, vec![Securite::L4Secure])
        .build();
    let option_reponse = middleware.transmettre_commande(routage, &commande).await?;
    match option_reponse {
        Some(r) => {
            match r {
                TypeMessage::Valide(reponse) => {
                    debug!("emettre_cles_vers_ca Reponse confirmer cle sur CA : {:?}", reponse.type_message);
                    let reponse_cles_manquantes: ReponseConfirmerClesSurCa = deser_message_buffer!(reponse.message);
                    let cles_manquantes = reponse_cles_manquantes.cles_manquantes;
                    traiter_cles_manquantes_ca(middleware, gestionnaire, &commande.liste_cle_id, &cles_manquantes).await?;
                },
                _ => Err(Error::Str("emettre_cles_vers_ca Recu mauvais type de reponse "))?
            }
        },
        None => info!("emettre_cles_vers_ca Aucune reponse du serveur")
    }

    // liste_cles.clear();  // Retirer toutes les cles pour prochaine page

    Ok(())
}

/// Marque les cles emises comme confirmees par le CA sauf si elles sont dans la liste de cles manquantes.
async fn traiter_cles_manquantes_ca<M>(
    middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition,
    cles_emises: &Vec<String>,
    cles_manquantes: &Vec<String>
)
    -> Result<(), Error>
    where M: MongoDao + GenerateurMessages + CleChiffrageHandler
{
    let nom_collection = match gestionnaire.get_collection_cles()? {
        Some(n) => n,
        None => Err(Error::Str("maitredescles_partition.traiter_cles_manquantes_ca Collection cles n'est pas definie"))?
    };

    // Marquer cles emises comme confirmees par CA si pas dans la liste de manquantes
    {
        let cles_confirmees: Vec<&String> = cles_emises.iter()
            .filter(|c| !cles_manquantes.contains(c))
            .collect();
        debug!("traiter_cles_manquantes_ca Cles confirmees par le CA: {} cles", cles_confirmees.len());
        if ! cles_confirmees.is_empty() {
            // let filtre_confirmees = doc! {CHAMP_HACHAGE_BYTES: {"$in": cles_confirmees}};
            // let filtre_confirmees = doc! { "$or": CleSynchronisation::get_bson_filter(&cles_confirmees)? };
            let filtre_confirmees = doc! { "cle_id": { "$in": &cles_confirmees } };
            let ops = doc! {
                "$set": {CHAMP_CONFIRMATION_CA: true},
                "$currentDate": {CHAMP_MODIFICATION: true}
            };
            let collection = middleware.get_collection(nom_collection.as_str())?;
            let resultat_confirmees = collection.update_many(filtre_confirmees, ops, None).await?;
            debug!("traiter_cles_manquantes_ca Resultat maj cles confirmees: {:?}", resultat_confirmees);
        }
    }

    // Rechiffrer et emettre les cles manquantes.
    if ! cles_manquantes.is_empty() {
        let filtre_manquantes = doc! { "cle_id": { "$in": &cles_manquantes } };
        let collection = middleware.get_collection_typed::<RowClePartition>(nom_collection.as_str())?;
        let mut curseur = collection.find(filtre_manquantes, None).await?;
        let mut cles = Vec::new();
        while let Some(d) = curseur.next().await {
            match d {
                Ok(cle) => {
                    let cle_transfert_ca = CleTransfertCa {
                        signature: cle.signature,
                        format: cle.format,
                        nonce: cle.header,
                        verification: cle.tag,
                    };
                    cles.push(cle_transfert_ca)
                },
                Err(e) => {
                    warn!("traiter_cles_manquantes_ca Erreur conversion document en cle : {:?}", e);
                    continue
                }
            };
        }

        let routage_commande = RoutageMessageAction::builder(
            DOMAINE_NOM, COMMANDE_TRANSFERT_CLE_CA, vec![Securite::L3Protege]
        )
            .blocking(false)
            .build();

        let commande = CommandeTransfertClesCaV2 { cles };
        debug!("traiter_cles_manquantes_ca Emettre {} cles rechiffrees pour CA", commande.cles.len());
        middleware.transmettre_commande(routage_commande.clone(), &commande).await?;
    }

    Ok(())
}

async fn evenement_cle_manquante<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler + CleChiffrageCache + ConfigMessages
{
    error!("evenement_cle_manquante Evenement obsolete");
    Ok(None)
    // debug!("evenement_cle_manquante Verifier si on peut transmettre la cle manquante {:?}", &m.message);
    // debug!("evenement_cle_manquante Verifier si on peut transmettre la cle manquante");

    // // Conserver flag pour indiquer methode de reponse
    // // est_evenement true : commande rechiffrage
    // //              false : reponse
    // // let est_evenement = m.routing_key.starts_with("evenement.");
    // let est_evenement = match & m.type_message {
    //     TypeMessageOut::Evenement(_) => true,
    //     _ => false
    // };
    //
    // if ! m.certificat.verifier_roles(vec![RolesCertificats::MaitreDesCles])? {
    //     debug!("evenement_cle_manquante Certificat sans role maitredescles, on rejette la demande");
    //     return Ok(None)
    // }
    //
    // let partition = m.certificat.fingerprint()?;
    // let enveloppe_privee = middleware.get_enveloppe_signature();
    // let partition_locale = enveloppe_privee.fingerprint()?;
    //
    // if partition == partition_locale {
    //     debug!("evenement_cle_manquante Evenement emis par la partition locale, on l'ignore");
    //     return Ok(None)
    // }
    //
    // let event_non_dechiffrables: ReponseSynchroniserCles = deser_message_buffer!(m.message);
    //
    // let nom_collection = match gestionnaire.get_collection_cles()? {
    //     Some(n) => n,
    //     None => Err(Error::Str("maitredescles_partition.evenement_cle_manquante Collection cles n'est pas definie"))?
    // };
    //
    // // S'assurer que le certificat de maitre des cles recus est dans la liste de rechiffrage
    // // middleware.recevoir_certificat_chiffrage(middleware, &m.message).await?;
    // if let Err(e) = middleware.ajouter_certificat_chiffrage(m.certificat.clone()) {
    //     error!("Erreur reception certificat chiffrage : {:?}", e);
    // }
    //
    // let routage_commande = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE, vec![Securite::L4Secure])
    //     .partition(partition)
    //     .build();
    //
    // let liste_cles = event_non_dechiffrables.liste_cle_id;
    // let filtre = doc! {
    //     // "$or": CleSynchronisation::get_bson_filter(&liste_cles)?
    //     "$in": liste_cles
    // };
    // trace!("evenement_cle_manquante filtre {:?}", filtre);
    //
    // let collection = middleware.get_collection(nom_collection.as_str())?;
    // let mut curseur = collection.find(filtre, None).await?;
    //
    // let mut cles = Vec::new();
    // while let Some(d) = curseur.next().await {
    //     let commande = match d {
    //         Ok(cle) => {
    //             match convertir_bson_deserializable::<RowClePartition>(cle) {
    //                 Ok(doc_cle) => {
    //                     todo!("fix me")
    //                     // trace!("evenement_cle_manquante Rechiffrer cle {}/{}", doc_cle.domaine, doc_cle.hachage_bytes);
    //                     // let cle_interne = CleInterneChiffree::try_from(doc_cle.clone())?;
    //                     // let cle_secrete = gestionnaire.handler_rechiffrage.dechiffer_cle_secrete(cle_interne)?;
    //                     // CleSecreteRechiffrage::from_doc_cle(cle_secrete, doc_cle)?
    //                 },
    //                 Err(e) => {
    //                     warn!("evenement_cle_manquante Erreur conversion document en cle : {:?}", e);
    //                     continue
    //                 }
    //             }
    //         },
    //         Err(e) => Err(format!("maitredescles_partition.evenement_cle_manquante Erreur lecture curseur : {:?}", e))?
    //     };
    //
    //     cles.push(commande);
    // }
    //
    // if cles.len() > 0 {
    //
    //     if est_evenement {
    //         // Batir une commande de rechiffrage
    //         todo!("obsolete");
    //     } else {
    //         // Repondre normalement
    //         let reponse = json!({
    //             "ok": true,
    //             "cles": cles,
    //         });
    //
    //         debug!("evenement_cle_manquante Emettre reponse avec {} cles", cles.len());
    //         let reponse = middleware.build_reponse_chiffree(
    //             reponse, m.certificat.as_ref())?.0;
    //         debug!("evenement_cle_manquante Reponse chiffree {:?}", reponse);
    //         Ok(Some(reponse))
    //     }
    // } else {
    //     // Si on n'a aucune cle, ne pas repondre. Un autre maitre des cles pourrait le faire
    //     debug!("evenement_cle_manquante On n'a aucune des cles demandees");
    //     Ok(None)
    // }
}

async fn commande_verifier_cle_symmetrique<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition, m: &MessageValide)
                                              -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("evenement_verifier_cle_symmetrique Verifier si la cle symmetrique est chargee");

    if gestionnaire.handler_rechiffrage.is_ready() == false {
        // Cle symmetrique manquante, on l'emet
        debug!("evenement_verifier_cle_symmetrique Cle symmetrique manquante");
        preparer_rechiffreur_mongo(middleware, &gestionnaire.handler_rechiffrage).await?;
    } else {
        debug!("evenement_verifier_cle_symmetrique Cle symmetrique OK");
    }

    Ok(None)
}

async fn evenement_cle_rechiffrage<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler + ConfigMessages
{
    debug!("evenement_cle_rechiffrage Conserver cles de rechiffrage {:?}", &m.type_message);

    let enveloppe_signature = middleware.get_enveloppe_signature();
    let fingerprint_local = enveloppe_signature.fingerprint()?;

    let instance_id = m.certificat.get_common_name()?;
    let fingerprint = m.certificat.fingerprint()?;

    if fingerprint_local.as_str() == fingerprint.as_str() {
        debug!("evenement_cle_rechiffrage Evenement pour cle locale (fingerprint {}), skip", fingerprint);
        return Ok(None);
    }

    // Mapper evenement
    let evenement: EvenementClesRechiffrage = deser_message_buffer!(m.message);

    let collection = middleware.get_collection(NOM_COLLECTION_CONFIGURATION)?;
    // let doc_ca = doc! {
    //     "type": "CA-tiers",
    //     "instance_id": &instance_id,
    //     "cle": evenement.cle_ca,
    // };
    let filtre_ca = doc! { "type": "CA-tiers", "instance_id": &instance_id };
    let ops_ca = doc! {
        "$set": {
            "cle": evenement.cle_ca,
        },
        "$setOnInsert": {
            CHAMP_CREATION: Utc::now(),
            "type": "CA-tiers",
            "instance_id": &instance_id,
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let options_ca = UpdateOptions::builder().upsert(true).build();
    collection.update_one(filtre_ca, ops_ca, Some(options_ca)).await?;

    // if let Err(e) = collection.insert_one(doc_ca, None).await {
    //     if ! verifier_erreur_duplication_mongo(&e.kind) {
    //         // L'erreur n'est pas une duplication, relancer
    //         Err(e)?
    //     }
    // }

    // Dechiffrer cle du tiers, rechiffrer en symmetrique local
    if let Some(cle_tierce) = evenement.cles_dechiffrage.get(fingerprint_local.as_str()) {

        let cle_tierce_vec = multibase::decode(cle_tierce)?;
        let cle_dechiffree = dechiffrer_asymmetrique_ed25519(
            &cle_tierce_vec.1[..], &enveloppe_signature.cle_privee)?;
        let cle_chiffree = gestionnaire.handler_rechiffrage.chiffrer_cle_secrete(&cle_dechiffree.0[..])?;

        // let doc_cle = doc! {
        //     "type": "tiers",
        //     "instance_id": &instance_id,
        //     "fingerprint": &fingerprint,
        //     "cle_symmetrique": cle_chiffree.cle,
        //     "nonce_symmetrique": cle_chiffree.nonce,
        // };
        // if let Err(e) = collection.insert_one(doc_cle, None).await {
        //     if ! verifier_erreur_duplication_mongo(&e.kind) {
        //         // L'erreur n'est pas une duplication, relancer
        //         Err(e)?
        //     }
        // }

        let filtre_cle = doc! {
            "type": "tiers",
            "instance_id": &instance_id,
            // "fingerprint": "tiers"
        };
        let ops_cle = doc! {
            "$set": {
                "cle_symmetrique": cle_chiffree.cle,
                "nonce_symmetrique": cle_chiffree.nonce,
            },
            "$setOnInsert": {
                CHAMP_CREATION: Utc::now(),
                "type": "tiers",
                "instance_id": &instance_id,
                // "fingerprint": "tiers",
            },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        let options_cle = UpdateOptions::builder().upsert(true).build();
        collection.update_one(filtre_cle, ops_cle, Some(options_cle)).await?;
    }

    Ok(None)
}

pub async fn preparer_rechiffreur_mongo<M>(middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage)
    -> Result<(), Error>
    where M: GenerateurMessages + ValidateurX509 + MongoDao
{

    let enveloppe_privee = middleware.get_enveloppe_signature();
    let instance_id = enveloppe_privee.enveloppe_pub.get_common_name()?;

    // Verifier si les cles de dechiffrage existent deja.
    let collection = middleware.get_collection(NOM_COLLECTION_CONFIGURATION)?;
    let filtre = doc!{"type": "CA", "instance_id": instance_id.as_str()};
    match collection.find_one(filtre, None).await? {
        Some(doc_cle_ca) => {
            info!("preparer_rechiffreur_mongo Cle de rechiffrage CA est presente");

            let filtre = doc!{
                "type": "local",
                "instance_id": instance_id.as_str(),
                "fingerprint": enveloppe_privee.fingerprint()?,
            };

            match collection.find_one(filtre, None).await? {
                Some(doc_cle_locale) => {
                    let cle_locale: DocumentCleRechiffrage = convertir_bson_deserializable(doc_cle_locale)?;
                    handler_rechiffrage.set_cle_symmetrique(cle_locale.cle)?;
                    info!("preparer_rechiffreur_mongo Cle de rechiffrage locale est chargee");
                },
                None => {
                    let cle_ca: DocumentCleRechiffrage = convertir_bson_deserializable(doc_cle_ca)?;

                    info!("preparer_rechiffreur_mongo Demander la cle de rechiffrage");
                    emettre_demande_cle_symmetrique(middleware, cle_ca.cle).await?;
                    Err(format!("preparer_rechiffreur_mongo Attente cle de rechiffrage"))?;
                }
            }

        },
        None => {
            // Initialiser la base de donnees
            info!("preparer_rechiffreur_mongo Initiliser cle de rechiffrage");

            preparer_rechiffreur(middleware, handler_rechiffrage).await?;

            // Conserver la cle de rechiffrage
            let cle_secrete_chiffree_ca = handler_rechiffrage.get_cle_symmetrique_chiffree(&enveloppe_privee.enveloppe_ca.certificat.public_key()?)?;
            let cle_secrete_chiffree_local = handler_rechiffrage.get_cle_symmetrique_chiffree(&enveloppe_privee.enveloppe_pub.certificat.public_key()?)?;
            debug!("Cle secrete chiffree pour instance {} :\nCA = {}\n local = {}", instance_id, cle_secrete_chiffree_ca, cle_secrete_chiffree_local);

            let cle_ca = doc! {
                "type": "CA",
                "instance_id": instance_id.as_str(),
                "cle": cle_secrete_chiffree_ca,
            };
            collection.insert_one(cle_ca, None).await?;

            let cle_locale = doc! {
                "type": "local",
                "instance_id": instance_id.as_str(),
                "fingerprint": enveloppe_privee.fingerprint()?,
                "cle": cle_secrete_chiffree_local,
            };
            collection.insert_one(cle_locale, None).await?;
        }
    }

    Ok(())
}

pub async fn commande_dechiffrer_cle<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages
{
    debug!("commande_dechiffrer_cle Dechiffrer cle {:?}", &m.type_message);
    let commande: CommandeDechiffrerCle = deser_message_buffer!(m.message);

    let enveloppe_signature = middleware.get_enveloppe_signature();
    let enveloppe_destinataire = m.certificat.as_ref();

    // verifier que le destinataire est de type L4Secure
    if enveloppe_destinataire.verifier_exchanges(vec![Securite::L4Secure])? == false {
        warn!("commande_dechiffrer_cle Certificat mauvais type (doit etre L4Secure)");
        // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false}), None)?));
        return Ok(Some(middleware.reponse_err(None, None, None)?))
    }

    let (_, cle_chiffree) = multibase::decode(commande.cle.as_str())?;
    let cle_secrete = dechiffrer_asymmetrique_ed25519(&cle_chiffree[..], &enveloppe_signature.cle_privee)?;
    let cle_rechiffree = chiffrer_asymmetrique_ed25519(
        &cle_secrete.0[..], &enveloppe_destinataire.certificat.public_key()?)?;
    let cle_rechiffree_str: String = multibase::encode(Base::Base64, cle_rechiffree);

    let cle_reponse = CommandeCleRechiffree { ok: true, cle: Some(cle_rechiffree_str) };

    Ok(Some(middleware.build_reponse(&cle_reponse)?.0))
}

// #[cfg(test)]
// mod ut {
//     use std::error::Error;
//     use std::path::{Path, PathBuf};
//     use std::thread::sleep;
//     use std::time::Duration;
//
//     use millegrilles_common_rust::certificats::{build_store_path, charger_enveloppe_privee, ValidateurX509Impl};
//     use millegrilles_common_rust::chiffrage::FormatChiffrage;
//     use millegrilles_common_rust::configuration::{charger_configuration, ConfigMessages, ConfigurationMessages};
//     use millegrilles_common_rust::formatteur_messages::{MessageMilleGrillesBufferDefault, MessageSerialise};
//     use millegrilles_common_rust::openssl::x509::store::X509Store;
//     use millegrilles_common_rust::openssl::x509::X509;
//     use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
//     use millegrilles_common_rust::recepteur_messages::MessageValide;
//     use millegrilles_common_rust::serde_json::Value;
//     use millegrilles_common_rust::verificateur::{ResultatValidation, ValidationOptions, VerificateurMessage};
//     use millegrilles_common_rust::tokio as tokio;
//     use crate::test_setup::setup;
//
//     use super::*;
//
//     fn init() -> ConfigurationMessages {
//         charger_configuration().expect("Erreur configuration")
//     }
//
//     pub fn charger_enveloppe_privee_part(cert: &Path, cle: &Path) -> (Arc<ValidateurX509Impl>, EnveloppePrivee) {
//         const CA_CERT_PATH: &str = "/home/mathieu/mgdev/certs/pki.millegrille";
//         let validateur = build_store_path(PathBuf::from(CA_CERT_PATH).as_path()).expect("store");
//         let validateur = Arc::new(validateur);
//         let enveloppe_privee = charger_enveloppe_privee(
//             cert,
//             cle,
//             validateur.clone()
//         ).expect("privee");
//
//         (validateur, enveloppe_privee)
//     }
//
//     struct MiddlewareStub { resultat: ResultatValidation, certificat: Option<Arc<EnveloppeCertificat>> }
//     impl VerificateurMessage for MiddlewareStub {
//         fn verifier_message(&self, message: &mut MessageSerialise, options: Option<&ValidationOptions>) -> Result<ResultatValidation, Error> {
//             message.certificat = self.certificat.clone();
//             Ok(self.resultat.clone())
//         }
//     }
//     #[async_trait]
//     impl ValidateurX509 for MiddlewareStub {
//         async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
//             todo!()
//         }
//
//         async fn cacher(&self, certificat: EnveloppeCertificat) -> Arc<EnveloppeCertificat> {
//             todo!()
//         }
//
//         async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
//             todo!()
//         }
//
//         fn idmg(&self) -> &str {
//             todo!()
//         }
//
//         fn ca_pem(&self) -> &str {
//             todo!()
//         }
//
//         fn ca_cert(&self) -> &X509 {
//             todo!()
//         }
//
//         fn store(&self) -> &X509Store {
//             todo!()
//         }
//
//         fn store_notime(&self) -> &X509Store {
//             todo!()
//         }
//
//         async fn entretien_validateur(&self) {
//             todo!()
//         }
//     }
//
//     fn prep_mva<S>(enveloppe_privee: &EnveloppePrivee, contenu_message: &S) -> MessageValide
//         where S: Serialize
//     {
//         let message_millegrille = MessageMilleGrillesBufferDefault::new_signer(
//             enveloppe_privee, contenu_message, Some("domaine"), Some("action"), None::<&str>, None).expect("mg");
//         let mut message_serialise = MessageSerialise::from_parsed(message_millegrille).expect("ms");
//         message_serialise.certificat = Some(enveloppe_privee.enveloppe.clone());
//         let message_valide_action = MessageValide::new(
//             message_serialise, "q", "rk","domaine", "action", TypeMessageOut::Requete);
//
//         message_valide_action
//     }
//
//     #[tokio::test]
//     async fn acces_global_ok() {
//         setup("acces_global_ok");
//
//         let config = init();
//         let enveloppe_privee = config.get_configuration_pki().get_enveloppe_privee();
//
//         // Stub middleware, resultat verification
//         let middleware = MiddlewareStub{
//             resultat: ResultatValidation {signature_valide: true, hachage_valide: Some(true), certificat_valide: true, regles_valides: true},
//             certificat: None,
//         };
//
//         // Stub message requete
//         let requete = RequeteDechiffrage { liste_hachage_bytes: vec!["DUMMY".into()], permission: None, certificat_rechiffrage: None };
//         let message_valide_action = prep_mva(enveloppe_privee.as_ref(), &requete);
//
//         // verifier_autorisation_dechiffrage_global<M>(middleware: &M, m: &MessageValide, requete: &RequeteDechiffrage)
//         let (global_permis, permission) = verifier_autorisation_dechiffrage_global(
//             &middleware, &message_valide_action, &requete).await.expect("resultat");
//
//         debug!("acces_global_ok Resultat global_permis: {}, permission {:?}", global_permis, permission);
//
//         assert_eq!(true, global_permis);
//         assert_eq!(true, permission.is_none());
//     }
//
//     #[tokio::test]
//     async fn acces_global_refuse() {
//         setup("acces_global_refuse");
//
//         let path_cert = PathBuf::from("/home/mathieu/mgdev/certs/pki.nginx.cert");
//         let path_key = PathBuf::from("/home/mathieu/mgdev/certs/pki.nginx.key");
//         let (_, env_privee_autre) = charger_enveloppe_privee_part(path_cert.as_path(), path_key.as_path());
//         let enveloppe_privee_autre = Arc::new(env_privee_autre);
//
//         let config = init();
//         let enveloppe_privee = config.get_configuration_pki().get_enveloppe_privee();
//
//         // Stub middleware, resultat verification
//         let middleware = MiddlewareStub{
//             resultat: ResultatValidation {signature_valide: true, hachage_valide: Some(true), certificat_valide: true, regles_valides: true},
//             certificat: None
//         };
//
//         // Stub message requete
//         let requete = RequeteDechiffrage { liste_hachage_bytes: vec!["DUMMY".into()], permission: None, certificat_rechiffrage: None };
//
//         // Preparer message avec certificat "autre" (qui n'a pas exchange 4.secure)
//         let mut message_valide_action = prep_mva(enveloppe_privee_autre.as_ref(), &requete);
//
//         // verifier_autorisation_dechiffrage_global<M>(middleware: &M, m: &MessageValide, requete: &RequeteDechiffrage)
//         let (global_permis, permission) = verifier_autorisation_dechiffrage_global(
//             &middleware, &message_valide_action, &requete).await.expect("resultat");
//
//         debug!("acces_global_ok Resultat global_permis: {}, permission {:?}", global_permis, permission);
//
//         assert_eq!(false, global_permis);
//         assert_eq!(true, permission.is_none());
//     }
//
//     #[tokio::test]
//     async fn permission_globale_ok() {
//         setup("acces_global_ok");
//
//         let path_cert = PathBuf::from("/home/mathieu/mgdev/certs/pki.nginx.cert");
//         let path_key = PathBuf::from("/home/mathieu/mgdev/certs/pki.nginx.key");
//         let (_, env_privee_autre) = charger_enveloppe_privee_part(path_cert.as_path(), path_key.as_path());
//         let enveloppe_privee_autre = Arc::new(env_privee_autre);
//
//         let config = init();
//         let enveloppe_privee = config.get_configuration_pki().get_enveloppe_privee();
//
//         // Stub middleware, resultat verification
//         let middleware = MiddlewareStub{
//             resultat: ResultatValidation {signature_valide: true, hachage_valide: Some(true), certificat_valide: true, regles_valides: true},
//             certificat: Some(enveloppe_privee.enveloppe.clone())  // Injecter cert 4.secure
//         };
//
//         // Creer permission
//         let contenu_permission = PermissionDechiffrage {
//             permission_hachage_bytes: vec!["DUMMY".into()],
//             domaines_permis: None,
//             user_id: None,
//             permission_duree: 5,
//         };
//         let permission = MessageMilleGrillesBufferDefault::new_signer(
//             enveloppe_privee.as_ref(), &contenu_permission, Some("domaine"), Some("action"), None::<&str>, None).expect("mg");
//
//         // Stub message requete
//         let requete = RequeteDechiffrage { liste_hachage_bytes: vec!["DUMMY".into()], permission: Some(permission), certificat_rechiffrage: None };
//
//         // Preparer message avec certificat "autre" (qui n'a pas exchange 4.secure)
//         let mut message_valide_action = prep_mva(enveloppe_privee_autre.as_ref(), &requete);
//
//         // verifier_autorisation_dechiffrage_global<M>(middleware: &M, m: &MessageValide, requete: &RequeteDechiffrage)
//         let (global_permis, permission) = verifier_autorisation_dechiffrage_global(
//             &middleware, &message_valide_action, &requete).await.expect("resultat");
//
//         debug!("acces_global_ok Resultat global_permis: {}, permission {:?}", global_permis, permission);
//
//         assert_eq!(false, global_permis);
//         assert_eq!(true, permission.is_some());
//     }
//
//     #[tokio::test]
//     async fn permission_expiree() {
//         setup("permission_expiree");
//
//         let path_cert = PathBuf::from("/home/mathieu/mgdev/certs/pki.nginx.cert");
//         let path_key = PathBuf::from("/home/mathieu/mgdev/certs/pki.nginx.key");
//         let (_, env_privee_autre) = charger_enveloppe_privee_part(path_cert.as_path(), path_key.as_path());
//         let enveloppe_privee_autre = Arc::new(env_privee_autre);
//
//         let config = init();
//         let enveloppe_privee = config.get_configuration_pki().get_enveloppe_privee();
//
//         // Stub middleware, resultat verification
//         let middleware = MiddlewareStub{
//             resultat: ResultatValidation {signature_valide: true, hachage_valide: Some(true), certificat_valide: true, regles_valides: true},
//             certificat: Some(enveloppe_privee.enveloppe.clone())  // Injecter cert 4.secure
//         };
//
//         // Creer permission
//         let contenu_permission = PermissionDechiffrage {
//             permission_hachage_bytes: vec!["DUMMY".into()],
//             domaines_permis: None,
//             user_id: None,
//             permission_duree: 0,
//         };
//         let permission = MessageMilleGrillesBufferDefault::new_signer(
//             enveloppe_privee.as_ref(),
//             &contenu_permission,
//             Some("domaine"),
//             Some("action"),
//             None::<&str>,
//             None
//         ).expect("mg");
//
//         // Stub message requete
//         let requete = RequeteDechiffrage { liste_hachage_bytes: vec!["DUMMY".into()], permission: Some(permission), certificat_rechiffrage: None };
//
//         // Preparer message avec certificat "autre" (qui n'a pas exchange 4.secure)
//         let mut message_valide_action = prep_mva(enveloppe_privee_autre.as_ref(), &requete);
//
//         sleep(Duration::new(1, 0)); // Attendre expiration de la permission
//
//         // verifier_autorisation_dechiffrage_global<M>(middleware: &M, m: &MessageValide, requete: &RequeteDechiffrage)
//         let (global_permis, permission) = verifier_autorisation_dechiffrage_global(
//             &middleware, &message_valide_action, &requete).await.expect("resultat");
//
//         debug!("acces_global_ok Resultat global_permis: {}, permission {:?}", global_permis, permission);
//
//         assert_eq!(false, global_permis);
//         assert_eq!(true, permission.is_none());
//     }
//
//     #[test]
//     fn permission_specifique_tout() {
//         setup("permission_specifique_tout");
//
//         let config = init();
//         let enveloppe_privee = config.get_configuration_pki().get_enveloppe_privee();
//
//         let path_cert = PathBuf::from("/home/mathieu/mgdev/certs/pki.nginx.cert");
//         let path_key = PathBuf::from("/home/mathieu/mgdev/certs/pki.nginx.key");
//         let (_, env_privee_autre) = charger_enveloppe_privee_part(path_cert.as_path(), path_key.as_path());
//         let enveloppe_privee_autre = Arc::new(env_privee_autre);
//         let certificat_destination = enveloppe_privee_autre.enveloppe.clone();
//
//         // Creer permission
//         let contenu_permission = PermissionDechiffrage {
//             permission_hachage_bytes: vec!["DUMMY".into()],
//             domaines_permis: None,
//             user_id: None,
//             permission_duree: 5,
//         };
//
//         let enveloppe_permission = EnveloppePermission {
//             enveloppe: enveloppe_privee.enveloppe.clone(),
//             permission: contenu_permission,
//         };
//
//         let identificateurs_document: HashMap<String, String> = HashMap::new();
//         let cle = TransactionCle {
//             cle: "CLE".into(),
//             domaine: "domaine".into(),
//             partition: None,
//             format: FormatChiffrage::mgs2,
//             hachage_bytes: "DUMMY".into(),
//             identificateurs_document,
//             iv: "iv".into(),
//             tag: "tag".into(),
//         };
//
//         let resultat = verifier_autorisation_dechiffrage_specifique(
//             certificat_destination.as_ref(), Some(&enveloppe_permission), &cle).expect("permission");
//         debug!("permission_specifique_tout Resultat : {:?}", resultat);
//
//         assert_eq!(true, resultat);
//     }
//
//     #[test]
//     fn permission_specifique_domaine() {
//         setup("permission_specifique_domaine");
//
//         let config = init();
//         let enveloppe_privee = config.get_configuration_pki().get_enveloppe_privee();
//
//         let path_cert = PathBuf::from("/home/mathieu/mgdev/certs/pki.nginx.cert");
//         let path_key = PathBuf::from("/home/mathieu/mgdev/certs/pki.nginx.key");
//         let (_, env_privee_autre) = charger_enveloppe_privee_part(path_cert.as_path(), path_key.as_path());
//         let enveloppe_privee_autre = Arc::new(env_privee_autre);
//         let certificat_destination = enveloppe_privee_autre.enveloppe.clone();
//
//         // Creer permission
//         let contenu_permission = PermissionDechiffrage {
//             permission_hachage_bytes: vec!["DUMMY".into()],
//             domaines_permis: Some(vec!["DomaineTest".into()]),
//             user_id: None,
//             permission_duree: 5,
//         };
//
//         let enveloppe_permission = EnveloppePermission {
//             enveloppe: enveloppe_privee.enveloppe.clone(),
//             permission: contenu_permission,
//         };
//
//         let identificateurs_document: HashMap<String, String> = HashMap::new();
//         let cle = TransactionCle {
//             cle: "CLE".into(),
//             domaine: "DomaineTest".into(),
//             partition: None,
//             format: FormatChiffrage::mgs2,
//             hachage_bytes: "DUMMY".into(),
//             identificateurs_document,
//             iv: "iv".into(),
//             tag: "tag".into(),
//         };
//
//         let resultat = verifier_autorisation_dechiffrage_specifique(
//             certificat_destination.as_ref(), Some(&enveloppe_permission), &cle).expect("permission");
//         debug!("permission_specifique_tout Resultat : {:?}", resultat);
//
//         assert_eq!(true, resultat);
//     }
//
//     #[test]
//     fn permission_specifique_domaine_refuse() {
//         setup("permission_specifique_domaine_refuse");
//
//         let config = init();
//         let enveloppe_privee = config.get_configuration_pki().get_enveloppe_privee();
//
//         let path_cert = PathBuf::from("/home/mathieu/mgdev/certs/pki.nginx.cert");
//         let path_key = PathBuf::from("/home/mathieu/mgdev/certs/pki.nginx.key");
//         let (_, env_privee_autre) = charger_enveloppe_privee_part(path_cert.as_path(), path_key.as_path());
//         let enveloppe_privee_autre = Arc::new(env_privee_autre);
//         let certificat_destination = enveloppe_privee_autre.enveloppe.clone();
//
//         // Creer permission
//         let contenu_permission = PermissionDechiffrage {
//             permission_hachage_bytes: vec!["DUMMY".into()],
//             domaines_permis: Some(vec!["DomaineTest_MAUVAIS".into()]),
//             user_id: None,
//             permission_duree: 5,
//         };
//
//         let enveloppe_permission = EnveloppePermission {
//             enveloppe: enveloppe_privee.enveloppe.clone(),
//             permission: contenu_permission,
//         };
//
//         let identificateurs_document: HashMap<String, String> = HashMap::new();
//         let cle = TransactionCle {
//             cle: "CLE".into(),
//             domaine: "DomaineTest".into(),
//             partition: None,
//             format: FormatChiffrage::mgs2,
//             hachage_bytes: "DUMMY".into(),
//             identificateurs_document,
//             iv: "iv".into(),
//             tag: "tag".into(),
//         };
//
//         let resultat = verifier_autorisation_dechiffrage_specifique(
//             certificat_destination.as_ref(), Some(&enveloppe_permission), &cle).expect("permission");
//         debug!("permission_specifique_tout Resultat : {:?}", resultat);
//
//         assert_eq!(false, resultat);
//     }
//
//     #[test]
//     fn permission_specifique_user_id() {
//         setup("permission_specifique_user_id");
//
//         let config = init();
//         let enveloppe_privee = config.get_configuration_pki().get_enveloppe_privee();
//
//         let path_cert = PathBuf::from("/home/mathieu/mgdev/certs/pki.nginx.cert");
//         let path_key = PathBuf::from("/home/mathieu/mgdev/certs/pki.nginx.key");
//         let (_, env_privee_autre) = charger_enveloppe_privee_part(path_cert.as_path(), path_key.as_path());
//         let enveloppe_privee_autre = Arc::new(env_privee_autre);
//         let certificat_destination = enveloppe_privee_autre.enveloppe.clone();
//
//         // Creer permission
//         let contenu_permission = PermissionDechiffrage {
//             permission_hachage_bytes: vec!["DUMMY".into()],
//             domaines_permis: None,
//             user_id: Some("dummy_user".into()),
//             permission_duree: 0,
//         };
//
//         let enveloppe_permission = EnveloppePermission {
//             enveloppe: enveloppe_privee.enveloppe.clone(),
//             permission: contenu_permission,
//         };
//
//         let identificateurs_document: HashMap<String, String> = HashMap::new();
//         let cle = TransactionCle {
//             cle: "CLE".into(),
//             domaine: "DomaineTest".into(),
//             partition: None,
//             format: FormatChiffrage::mgs2,
//             hachage_bytes: "DUMMY".into(),
//             identificateurs_document,
//             iv: "iv".into(),
//             tag: "tag".into(),
//         };
//
//         let resultat = verifier_autorisation_dechiffrage_specifique(
//             certificat_destination.as_ref(), Some(&enveloppe_permission), &cle).expect("permission");
//         debug!("permission_specifique_tout Resultat : {:?}", resultat);
//
//         assert_eq!(false, resultat);
//     }
// }
//
// #[cfg(test)]
// mod test_integration {
//     use millegrilles_common_rust::backup::CatalogueHoraire;
//     use millegrilles_common_rust::formatteur_messages::MessageSerialise;
//     use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
//     use millegrilles_common_rust::middleware::IsConfigurationPki;
//     use millegrilles_common_rust::middleware_db::preparer_middleware_db;
//     use millegrilles_common_rust::mongo_dao::convertir_to_bson;
//     use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
//     use millegrilles_common_rust::recepteur_messages::TypeMessage;
//     use millegrilles_common_rust::tokio as tokio;
//
//     use crate::test_setup::setup;
//
//     use super::*;
//
//     #[tokio::test]
//     async fn test_requete_dechiffrage() {
//         setup("test_requete_dechiffrage");
//         let (middleware, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
//         let enveloppe_privee = middleware.get_enveloppe_privee();
//         let fingerprint = enveloppe_privee.fingerprint().as_str();
//
//         let gestionnaire = GestionnaireMaitreDesClesPartition {fingerprint: fingerprint.into()};
//         futures.push(tokio::spawn(async move {
//
//             let liste_hachages = vec![
//                 "z8VxfRxXrdrbAAWQZS8uvFUEk1eA4CGYNUMsypLWdexZ8LKLVsrD6WsrsgmbMNMukoMFUzDbCjQZ2n3VeUFHvXcEDoF"
//             ];
//
//             let contenu = json!({CHAMP_LISTE_HACHAGE_BYTES: liste_hachages});
//             let message_mg = MessageMilleGrillesBufferDefault::new_signer(
//                 enveloppe_privee.as_ref(),
//                 &contenu,
//                 DOMAINE_NOM.into(),
//                 REQUETE_DECHIFFRAGE.into(),
//                 None::<&str>,
//                 None
//             ).expect("message");
//             let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");
//
//             // Injecter certificat utilise pour signer
//             message.certificat = Some(enveloppe_privee.enveloppe.clone());
//
//             let mva = MessageValide::new(
//                 message, "dummy_q", "routing_key", "domaine", "action", TypeMessageOut::Requete);
//
//             let reponse = requete_dechiffrage(middleware.as_ref(), mva, &gestionnaire).await.expect("dechiffrage");
//             debug!("Reponse requete dechiffrage : {:?}", reponse);
//
//         }));
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
//
// }
