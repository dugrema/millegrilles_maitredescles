use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::BackupStarter;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{Securite, COMMANDE_AJOUTER_CLE_DOMAINES, COMMANDE_SAUVEGARDER_CLE, COMMANDE_TRANSFERT_CLE, COMMANDE_TRANSFERT_CLE_CA, DEFAULT_Q_TTL};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, ConsommateurMessagesBus, GestionnaireBusMillegrilles, GestionnaireDomaineV2};
use millegrilles_common_rust::domaines_v2::GestionnaireDomaineSimple;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, MiddlewareMessages};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValide;

use crate::constants::*;
use crate::maitredescles_mongodb::{preparer_index_mongodb_custom, NOM_COLLECTION_CA_CLES, NOM_COLLECTION_TRANSACTIONS};


#[derive(Clone)]
pub struct MaitreDesClesCaManager {
    pub fingerprint: String,
}

impl MaitreDesClesCaManager {
    pub fn new(fingerprint: String) -> MaitreDesClesCaManager {
        MaitreDesClesCaManager { fingerprint }
    }
}

impl GestionnaireDomaineV2 for MaitreDesClesCaManager {
    fn get_collection_transactions(&self) -> Option<String> {
        Some(String::from(NOM_COLLECTION_TRANSACTIONS))
    }

    fn get_collections_volatiles(&self) -> Result<Vec<String>, CommonError> {
        Ok(vec![String::from(NOM_COLLECTION_CA_CLES)])
    }
}

impl GestionnaireBusMillegrilles for MaitreDesClesCaManager {
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
        preparer_queues(self)
    }
}

#[async_trait]
impl ConsommateurMessagesBus for MaitreDesClesCaManager {
    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        todo!()
        // consommer_requete(middleware, message, self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        todo!()
        // consommer_commande(middleware, message, self).await
    }

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        todo!()
        // consommer_evenement(self, middleware, message).await
    }
}

#[async_trait]
impl AiguillageTransactions for MaitreDesClesCaManager {
    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        todo!()
        // aiguillage_transaction(self, middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaineSimple for MaitreDesClesCaManager {
    async fn traiter_cedule<M>(&self, _middleware: &M, _trigger: &MessageCedule) -> Result<(), CommonError>
    where
        M: MiddlewareMessages + BackupStarter + MongoDao
    {
        Ok(())
    }
}

fn preparer_queues(manager: &MaitreDesClesCaManager) -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();
    let mut rk_sauvegarder_cle = Vec::new();

    // RK 3.protege et 4.secure
    let requetes_protegees: Vec<&str> = vec![
        REQUETE_CLES_NON_DECHIFFRABLES,
        REQUETE_COMPTER_CLES_NON_DECHIFFRABLES,
        REQUETE_SYNCHRONISER_CLES,
    ];
    for req in requetes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L3Protege});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L4Secure});
    }
    let evenements_proteges: Vec<&str> = vec![
        EVENEMENT_CLES_MANQUANTES_PARTITION,
        EVENEMENT_CLE_RECUE_PARTITION,
    ];
    for evnt in evenements_proteges {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_NOM, evnt), exchange: Securite::L3Protege});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_NOM, evnt), exchange: Securite::L4Secure});
    }

    let commandes_protegees: Vec<&str> = vec![
        COMMANDE_CONFIRMER_CLES_SUR_CA,
        COMMANDE_RESET_NON_DECHIFFRABLE,
    ];
    for cmd in commandes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L3Protege});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L4Secure});
    }

    rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_TRANSFERT_CLE_CA), exchange: Securite::L3Protege});

    // Capturer les commandes "sauver cle" sur tous les exchanges pour toutes les partitions
    // Va creer la transaction locale CA si approprie
    for sec in [Securite::L1Public, Securite::L2Prive] {
        rk_sauvegarder_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.*.{}", DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE), exchange: sec });
    }
    // Nouvelle methode de sauvegarde de cle
    rk_sauvegarder_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_AJOUTER_CLE_DOMAINES), exchange: Securite::L1Public });
    rk_sauvegarder_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_TRANSFERT_CLE), exchange: Securite::L3Protege });

    for sec in [Securite::L3Protege, Securite::L4Secure] {
        // Conserver sauver cle pour
        rk_sauvegarder_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.*.{}", DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE), exchange: sec.clone() });

        // Capturer commande sauvegarder cle CA sur 3.protege et 4.secure
        rk_sauvegarder_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE), exchange: sec });
    }

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_CA_VOLATILS.into(),
            routing_keys: rk_volatils,
            ttl: DEFAULT_Q_TTL.into(),
            durable: true,
            autodelete: false,
        }
    ));

    // Queue commande de sauvegarde de cle
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: String::from(format!("{}/sauvegarder", NOM_COLLECTION_TRANSACTIONS)),
            routing_keys: rk_sauvegarder_cle,
            ttl: None,
            durable: true,
            autodelete: false,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (DOMAINE_NOM.into(), Securite::L3Protege));

    queues
}

pub async fn preparer_index_mongodb_ca<M>(middleware: &M) -> Result<(), CommonError>
where M: MongoDao + ConfigMessages
{
    preparer_index_mongodb_custom(middleware, NOM_COLLECTION_CA_CLES, true).await
}
