use std::error::Error;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::Middleware;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::transactions::{TraiterTransaction, Transaction, TransactionImpl};
use crate::maitredescles_commun::*;

// pub const NOM_COLLECTION_CLES: &str = "MaitreDesCles_CA/cles";
// pub const NOM_COLLECTION_TRANSACTIONS: &str = "MaitreDesCles_CA";

const NOM_Q_VOLATILS_GLOBAL: &str = "MaitreDesCles/volatils";

// const NOM_Q_TRANSACTIONS: &str = "MaitreDesCles_CA/transactions";
// const NOM_Q_VOLATILS: &str = "MaitreDesCles_CA/volatils";
// const NOM_Q_TRIGGERS: &str = "MaitreDesCles_CA/triggers";

#[derive(Clone, Debug)]
pub struct GestionnaireMaitreDesClesPartition {
    pub nom_partition: String,
}

impl GestionnaireMaitreDesClesPartition {
    pub fn new(nom_partition: &str) -> Self {
        Self {
            nom_partition: String::from(nom_partition)
        }
    }
}

#[async_trait]
impl TraiterTransaction for GestionnaireMaitreDesClesPartition {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        // aiguillage_transaction(middleware, transaction).await
        todo!()
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireMaitreDesClesPartition {

    fn get_nom_domaine(&self) -> String { String::from(DOMAINE_NOM) }

    fn get_collection_transactions(&self) -> String {
        format!("MaitreDesCles_{}", self.nom_partition)
    }

    fn get_collections_documents(&self) -> Vec<String> {
        vec![format!("MaitreDesCles_{}/cles", self.nom_partition)]
    }

    fn get_q_transactions(&self) -> String {
        format!("MaitreDesCles_{}/transactions", self.nom_partition)
    }

    fn get_q_volatils(&self) -> String {
        format!("MaitreDesCles_{}/volatils", self.nom_partition)
    }

    fn get_q_triggers(&self) -> String {
        format!("MaitreDesCles_{}/triggers", self.nom_partition)
    }

    fn preparer_queues(&self) -> Vec<QueueType> {
        let mut rk_volatils = Vec::new();

        // RK 3.protege seulement
        let requetes_protegees: Vec<&str> = vec![
            // REQUETE_DERNIER_HORAIRE,
        ];
        for req in requetes_protegees {
            rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L3Protege});
        }

        let commandes: Vec<&str> = vec![
            // COMMANDE_DECLENCHER_BACKUP_QUOTIDIEN,
        ];
        for commande in commandes {
            rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, commande), exchange: Securite::L4Secure});
        }

        let mut queues = Vec::new();

        // Queue de messages volatils (requete, commande, evenements)
        queues.push(QueueType::ExchangeQueue (
            ConfigQueue {
                nom_queue: self.get_q_volatils(),
                routing_keys: rk_volatils,
                ttl: 300000.into(),
                durable: false,
            }
        ));

        let mut rk_transactions = Vec::new();
        // rk_transactions.push(ConfigRoutingExchange {
        //     routing_key: format!("transaction.{}.{}", DOMAINE_NOM, TRANSACTION_CATALOGUE_HORAIRE).into(),
        //     exchange: Securite::L3Protege
        // });

        // Queue de transactions
        queues.push(QueueType::ExchangeQueue (
            ConfigQueue {
                nom_queue: self.get_q_transactions(),
                routing_keys: rk_transactions,
                ttl: None,
                durable: true,
            }
        ));

        // Queue de triggers
        queues.push(QueueType::Triggers (format!("MaitreDesCles_{}", self.nom_partition)));

        queues
    }

    async fn preparer_index_mongodb_custom<M>(&self, middleware: &M) -> Result<(), String> where M: MongoDao {
        let nom_collection_cles = format!("MaitreDesCles_{}/cles", self.nom_partition);
        preparer_index_mongodb_custom(middleware, nom_collection_cles.as_str()).await
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        todo!()
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        todo!()
    }

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        todo!()
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        todo!()
    }

    async fn entretien<M>(&self, middleware: Arc<M>) where M: Middleware + 'static {
        todo!()
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: MessageValideAction) -> Result<(), Box<dyn Error>> where M: Middleware + 'static {
        todo!()
    }

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String> where M: ValidateurX509 + GenerateurMessages + MongoDao, T: Transaction {
        todo!()
    }
}
