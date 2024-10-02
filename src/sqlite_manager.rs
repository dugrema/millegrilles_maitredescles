use std::sync::Mutex;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::BackupStarter;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, ConsommateurMessagesBus, GestionnaireBusMillegrilles, GestionnaireDomaineV2};
use millegrilles_common_rust::domaines_v2::GestionnaireDomaineSimple;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, MiddlewareMessages};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::QueueType;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use sqlite::Connection;
use crate::builder::MaitreDesClesSymmetricManagerTrait;
use crate::constants::*;
use crate::maitredescles_rechiffrage::HandlerCleRechiffrage;

pub struct MaitreDesClesSqliteManager {
    pub handler_rechiffrage: HandlerCleRechiffrage,
    connexion_read_only: Mutex<Option<Connection>>,
    connexion_sauvegarder_cle: Mutex<Option<Connection>>,
}

impl MaitreDesClesSqliteManager {
    pub fn new(handler_rechiffrage: HandlerCleRechiffrage) -> MaitreDesClesSqliteManager {
        MaitreDesClesSqliteManager {
            handler_rechiffrage,
            connexion_read_only: Mutex::new(None),
            connexion_sauvegarder_cle: Mutex::new(None),
        }
    }
}

impl MaitreDesClesSymmetricManagerTrait for MaitreDesClesSqliteManager {}

impl GestionnaireDomaineV2 for MaitreDesClesSqliteManager {
    fn get_collection_transactions(&self) -> Option<String> {
        panic!("Transactions not supported")
    }

    fn get_collections_volatiles(&self) -> Result<Vec<String>, CommonError> {
        Ok(vec![])  // No volatile collection to truncate on regeneration
    }
}

impl GestionnaireBusMillegrilles for MaitreDesClesSqliteManager {
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
impl ConsommateurMessagesBus for MaitreDesClesSqliteManager {
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
impl AiguillageTransactions for MaitreDesClesSqliteManager {
    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        todo!()
        // aiguillage_transaction(self, middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaineSimple for MaitreDesClesSqliteManager {
    async fn traiter_cedule<M>(&self, _middleware: &M, _trigger: &MessageCedule) -> Result<(), CommonError>
    where
        M: MiddlewareMessages + BackupStarter + MongoDao
    {
        Ok(())
    }
}

fn preparer_queues(manager: &MaitreDesClesSqliteManager) -> Vec<QueueType> {
    todo!()
}

pub async fn preparer_index_mongodb<M>(middleware: &M) -> Result<(), CommonError>
where M: MongoDao + ConfigMessages
{
    todo!()
}
