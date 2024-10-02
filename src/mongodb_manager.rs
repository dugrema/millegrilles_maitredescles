use std::sync::{Arc, Mutex};
use log::{debug, error, info};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::BackupStarter;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage_cle::CleChiffrageCache;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{RolesCertificats, Securite, COMMANDE_AJOUTER_CLE_DOMAINES, COMMANDE_CERT_MAITREDESCLES, COMMANDE_ROTATION_CERTIFICAT, COMMANDE_SAUVEGARDER_CLE, COMMANDE_TRANSFERT_CLE, DEFAULT_Q_TTL, DELEGATION_GLOBALE_PROPRIETAIRE, EVENEMENT_CLES_RECHIFFRAGE, MAITREDESCLES_REQUETE_DECHIFFRAGE_MESSAGE, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, COMMANDE_DECHIFFRER_CLE};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, ConsommateurMessagesBus, GestionnaireBusMillegrilles, GestionnaireDomaineV2};
use millegrilles_common_rust::domaines_v2::GestionnaireDomaineSimple;
use millegrilles_common_rust::error::{Error as CommonError, Error};
use millegrilles_common_rust::futures_util::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::get_domaine_action;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, MiddlewareMessages, RabbitMqTrait};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, NamedQueue, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::sync::mpsc;
use millegrilles_common_rust::tokio::time::{sleep, Duration as DurationTokio};
use millegrilles_common_rust::tokio_stream::StreamExt;
use crate::builder::MaitreDesClesSymmetricManagerTrait;
use crate::commands::{commande_dechiffrer_cle, commande_verifier_cle_symmetrique};
use crate::constants::*;
use crate::maitredescles_commun::{emettre_certificat_maitredescles, GestionnaireRessources};
use crate::maitredescles_mongodb::{commande_ajouter_cle_domaines, commande_cle_symmetrique, commande_rechiffrer_batch, commande_rotation_certificat, commande_transfert_cle, confirmer_cles_ca, evenement_cle_manquante, evenement_cle_rechiffrage, preparer_index_mongodb_custom, preparer_index_mongodb_partition, preparer_rechiffreur_mongo, requete_dechiffrage_v2, requete_transfert_cles, synchroniser_cles, NOM_COLLECTION_SYMMETRIQUE_CLES};
// use crate::maitredescles_partition::GestionnaireMaitreDesClesPartition;
use crate::maitredescles_rechiffrage::HandlerCleRechiffrage;
use crate::requests::{requete_certificat_maitredescles, requete_dechiffrage_message};

pub struct MaitreDesClesMongoDbManager {
    pub handler_rechiffrage: HandlerCleRechiffrage,
    pub ressources: Mutex<Option<GestionnaireRessources>>,
}

impl MaitreDesClesMongoDbManager {
    pub fn new(handler_rechiffrage: HandlerCleRechiffrage) -> MaitreDesClesMongoDbManager {
        MaitreDesClesMongoDbManager { handler_rechiffrage, ressources: Mutex::new(None) }
    }

    /// Verifie si le CA a des cles qui ne sont pas connues localement
    pub async fn synchroniser_cles<M>(&self, middleware: &M) -> Result<(), Error>
    where M: GenerateurMessages + MongoDao + CleChiffrageHandler
    {
        synchroniser_cles(middleware, &self.handler_rechiffrage).await?;
        Ok(())
    }

    /// S'assure que le CA a toutes les cles presentes dans la partition
    pub async fn confirmer_cles_ca<M>(&self, middleware: &M, reset_flag: Option<bool>) -> Result<(), Error>
    where M: GenerateurMessages + MongoDao + CleChiffrageHandler
    {
        confirmer_cles_ca(middleware, reset_flag).await?;
        Ok(())
    }

    /// Preparer les Qs une fois le certificat pret
    pub fn preparer_queues_rechiffrage(&self) -> Result<Vec<QueueType>, Error> {
        preparer_queues_rechiffrage(self)
    }

    pub fn get_q_sauvegarder_cle(&self) -> Result<Option<String>, Error> {
        let fingerprint = self.handler_rechiffrage.fingerprint()?;
        Ok(Some(format!("MaitreDesCles/{}/sauvegarder", fingerprint)))
    }

    fn get_q_volatils(&self) -> Result<Option<String>, Error> {
        let fingerprint = self.handler_rechiffrage.fingerprint()?;
        Ok(Some(format!("MaitreDesCles/{}/volatils", fingerprint)))
    }

    pub async fn emettre_certificat_maitredescles<M>(&self, middleware: &M, m: Option<MessageValide>) -> Result<(), Error>
    where M: GenerateurMessages
    {
        if self.handler_rechiffrage.is_ready() {
            emettre_certificat_maitredescles(middleware, m).await
        } else {
            Ok(())
        }
    }
}

impl MaitreDesClesSymmetricManagerTrait for MaitreDesClesMongoDbManager {}

impl GestionnaireDomaineV2 for MaitreDesClesMongoDbManager {
    fn get_collection_transactions(&self) -> Option<String> {
        None
    }

    fn get_collections_volatiles(&self) -> Result<Vec<String>, CommonError> {
        Ok(vec![])  // No volatile collection to truncate on regeneration
    }
}

impl GestionnaireBusMillegrilles for MaitreDesClesMongoDbManager {
    fn get_nom_domaine(&self) -> String {
        DOMAINE_NOM.to_string()
    }

    fn get_q_volatils(&self) -> String {
        format!("{}/volatiles", DOMAINE_NOM)
    }

    fn get_q_triggers(&self) -> String {
        format!("{}/triggers", DOMAINE_NOM)
    }

    fn preparer_queues(&self) -> Vec<QueueType> {
        let mut queues = match self.handler_rechiffrage.is_ready() {
            true => self.preparer_queues_rechiffrage().expect("preparer queues rechiffrage"),
            false => Vec::new()
        };

        // Ajouter Q reception cle symmetriques rechiffrees
        let fingerprint = self.handler_rechiffrage.fingerprint().expect("fingerprint");
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

        queues
    }
}

#[async_trait]
impl ConsommateurMessagesBus for MaitreDesClesMongoDbManager {
    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_requete(middleware, message, self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_commande(middleware, message, self).await
    }

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_evenement(middleware, self, message).await
    }
}

#[async_trait]
impl AiguillageTransactions for MaitreDesClesMongoDbManager {
    async fn aiguillage_transaction<M>(&self, _middleware: &M, transaction: TransactionValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        // Aucunes transactions
        Err(Error::String(format!("MaitreDesClesMongoDbManager.aiguillage_transaction: Transaction {} est de type non gere ", transaction.transaction.id)))
    }
}

#[async_trait]
impl GestionnaireDomaineSimple for MaitreDesClesMongoDbManager {
    async fn traiter_cedule<M>(&self, _middleware: &M, _trigger: &MessageCedule) -> Result<(), CommonError>
    where
        M: MiddlewareMessages + BackupStarter + MongoDao
    {
        Ok(())
    }
}

fn preparer_queues_rechiffrage(manager: &MaitreDesClesMongoDbManager) -> Result<Vec<QueueType>, Error> {
    let mut rk_dechiffrage = Vec::new();
    let mut rk_commande_cle = Vec::new();
    let mut rk_volatils = Vec::new();

    let dechiffrer = if let Ok(v) = std::env::var("DESACTIVER_DECHIFFRAGE") {
        info!("Desactiver rechiffrage public/prive/protege");
        false
    } else {
        true
    };

    let fingerprint = manager.handler_rechiffrage.fingerprint()?;

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
    if let Some(nom_queue) = manager.get_q_sauvegarder_cle()? {
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
    if let Some(nom_queue) = manager.get_q_volatils()? {
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

pub async fn preparer_index_mongodb<M>(middleware: &M) -> Result<(), CommonError>
where M: MongoDao + ConfigMessages
{
    debug!("preparer_database Ajouter index pour collection {}", NOM_COLLECTION_SYMMETRIQUE_CLES);
    preparer_index_mongodb_custom(middleware, NOM_COLLECTION_SYMMETRIQUE_CLES, false).await?;
    preparer_index_mongodb_partition(middleware).await?;
    Ok(())
}

pub async fn thread_entretien_manager_mongodb<M>(manager: &'static MaitreDesClesMongoDbManager, middleware: &'static M)
    where M: Middleware
{
    thread_configuration_rechiffrage(manager, middleware).await
}

pub async fn thread_configuration_rechiffrage<M>(manager: &'static MaitreDesClesMongoDbManager, middleware: &'static M)
    where M: Middleware
{
    let mut q_preparation_completee = false;
    loop {
        if !manager.handler_rechiffrage.is_ready() || q_preparation_completee == false {

            if q_preparation_completee == true {
                panic!("handler rechiffrage is_ready() == false et q_preparation_completee == true");
            }

            info!("entretien_rechiffreur Aucun certificat configure, on demande de generer un certificat volatil");
            let resultat = match preparer_rechiffreur_mongo(
                middleware, &manager.handler_rechiffrage).await {
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
                // // Preparer la collection avec index
                // manager.preparer_database(middleware).await.expect("preparer_database");

                let queues = manager.preparer_queues_rechiffrage().expect("queues");
                for queue in queues {

                    let queue_name = match &queue {
                        QueueType::ExchangeQueue(q) => q.nom_queue.clone(),
                        QueueType::ReplyQueue(_) => { continue },
                        QueueType::Triggers(d,s) => format!("{}.{:?}", d, s)
                    };

                    // Creer thread de traitement
                    let (tx, rx) = mpsc::channel::<TypeMessage>(1);
                    let mut futures_consumer = FuturesUnordered::new();
                    futures_consumer.push(spawn(manager.consommer_messages(middleware, rx)));

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
        sleep(DurationTokio::new(30, 0)).await;
    }
}

async fn consommer_requete<M>(middleware: &M, message: MessageValide, gestionnaire: &MaitreDesClesMongoDbManager) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
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
                REQUETE_DECHIFFRAGE_V2 => requete_dechiffrage_v2(middleware, message, &gestionnaire.handler_rechiffrage).await,
                MAITREDESCLES_REQUETE_DECHIFFRAGE_MESSAGE => requete_dechiffrage_message(middleware, message).await,
                REQUETE_TRANSFERT_CLES => requete_transfert_cles(middleware, message, &gestionnaire.handler_rechiffrage).await,
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

async fn consommer_commande<M>(middleware: &M, m: MessageValide, gestionnaire: &MaitreDesClesMongoDbManager)
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
            COMMANDE_AJOUTER_CLE_DOMAINES => commande_ajouter_cle_domaines(middleware, m, &gestionnaire.handler_rechiffrage).await,
            COMMANDE_CERT_MAITREDESCLES => {emettre_certificat_maitredescles(middleware, Some(m)).await?; Ok(None)},

            COMMANDE_RECHIFFRER_BATCH => commande_rechiffrer_batch(middleware, m, &gestionnaire.handler_rechiffrage).await,
            COMMANDE_CLE_SYMMETRIQUE => commande_cle_symmetrique(middleware, m, &gestionnaire.handler_rechiffrage).await,
            COMMANDE_VERIFIER_CLE_SYMMETRIQUE => commande_verifier_cle_symmetrique(middleware, &gestionnaire.handler_rechiffrage).await,

            // Commandes inconnues
            _ => Err(format!("maitredescles_partition.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else if role_prive == true && user_id.is_some() {
        match action.as_str() {
            // Commandes standard
            COMMANDE_AJOUTER_CLE_DOMAINES => commande_ajouter_cle_domaines(middleware, m, &gestionnaire.handler_rechiffrage).await,
            COMMANDE_CERT_MAITREDESCLES => {emettre_certificat_maitredescles(middleware, Some(m)).await?; Ok(None)},
            // Commandes inconnues
            _ => Err(format!("maitredescles_partition.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else if m.certificat.verifier_exchanges(vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])? {
        match action.as_str() {
            // Commandes standard
            COMMANDE_AJOUTER_CLE_DOMAINES => commande_ajouter_cle_domaines(middleware, m, &gestionnaire.handler_rechiffrage).await,
            COMMANDE_TRANSFERT_CLE => commande_transfert_cle(middleware, m, &gestionnaire.handler_rechiffrage).await,
            COMMANDE_CERT_MAITREDESCLES => {emettre_certificat_maitredescles(middleware, Some(m)).await?; Ok(None)},
            COMMANDE_ROTATION_CERTIFICAT => commande_rotation_certificat(middleware, m, &gestionnaire.handler_rechiffrage).await,
            COMMANDE_CLE_SYMMETRIQUE => commande_cle_symmetrique(middleware, m, &gestionnaire.handler_rechiffrage).await,
            COMMANDE_DECHIFFRER_CLE => commande_dechiffrer_cle(middleware, m).await,
            // Commandes inconnues
            _ => Err(format!("maitredescles_partition.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else {
        Err(Error::Str("Autorisation commande invalide, acces refuse"))?
    }
}

async fn consommer_evenement<M>(middleware: &M, gestionnaire: &MaitreDesClesMongoDbManager, m: MessageValide)
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
        EVENEMENT_CLES_MANQUANTES_PARTITION => evenement_cle_manquante(middleware, &m).await,
        EVENEMENT_CLES_RECHIFFRAGE => evenement_cle_rechiffrage(middleware, m, &gestionnaire.handler_rechiffrage).await,
        _ => Err(format!("consommer_evenement: Mauvais type d'action pour un evenement : {}", action))?,
    }
}