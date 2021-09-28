use std::error::Error;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageReponse};
use millegrilles_common_rust::middleware::Middleware;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::transactions::{TraiterTransaction, Transaction, TransactionImpl};

use crate::maitredescles_commun::*;

// pub const NOM_COLLECTION_CLES: &str = "MaitreDesCles_CA/cles";
// pub const NOM_COLLECTION_TRANSACTIONS: &str = "MaitreDesCles_CA";

const NOM_Q_VOLATILS_GLOBAL: &str = "MaitreDesCles/volatils";

// const NOM_Q_TRANSACTIONS: &str = "MaitreDesCles_CA/transactions";
// const NOM_Q_VOLATILS: &str = "MaitreDesCles_CA/volatils";
// const NOM_Q_TRIGGERS: &str = "MaitreDesCles_CA/triggers";

const REQUETE_CERTIFICAT_MAITREDESCLES: &str = "certMaitreDesCles";
const REQUETE_DECHIFFRAGE: &str = "dechiffrage";

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

    fn get_q_sauvegarder_cle(&self) -> String {
        format!("MaitreDesCles_{}/sauvegarder", self.nom_partition)
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
        let mut rk_dechiffrage = Vec::new();
        let mut rk_commande_cle = Vec::new();
        let mut rk_volatils = Vec::new();

        let nom_domaine_partition = format!("{}_{}", DOMAINE_NOM, self.nom_partition);

        // Requetes sur tous les exchanges
        // let requetes_protegees: Vec<&str> = vec![
        //     REQUETE_CERTIFICAT_MAITREDESCLES,
        //     REQUETE_DECHIFFRAGE,
        // ];
        let commandes: Vec<&str> = vec![
            COMMANDE_SAUVEGARDER_CLE,
        ];

        let nom_partition = self.nom_partition.as_str();

        for sec in [Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure] {
            rk_dechiffrage.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_DECHIFFRAGE), exchange: sec.clone() });
            rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_CERTIFICAT_MAITREDESCLES), exchange: sec.clone() });

            for commande in &commandes {
                rk_commande_cle.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, nom_partition, commande), exchange: sec.clone()});
            }
        }

        let mut queues = Vec::new();

        // Queue de messages dechiffrage - taches partagees entre toutes les partitions
        queues.push(QueueType::ExchangeQueue (
            ConfigQueue {
                nom_queue: NOM_Q_DECHIFFRAGE.into(),
                routing_keys: rk_dechiffrage,
                ttl: 300000.into(),
                durable: false,
            }
        ));

        // Queue commande de sauvegarde de cle
        queues.push(QueueType::ExchangeQueue (
            ConfigQueue {
                nom_queue: self.get_q_sauvegarder_cle(),
                routing_keys: rk_commande_cle,
                ttl: None,
                durable: true,
            }
        ));

        // Queue volatils
        queues.push(QueueType::ExchangeQueue (
            ConfigQueue {
                nom_queue: self.get_q_volatils().into(),
                routing_keys: rk_volatils,
                ttl: None,
                durable: true,
            }
        ));

        let mut rk_transactions = Vec::new();
        rk_transactions.push(ConfigRoutingExchange {
            routing_key: format!("transaction.{}.{}.{}", DOMAINE_NOM, nom_partition, TRANSACTION_CLE).into(),
            exchange: Securite::L4Secure
        });

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
        queues.push(QueueType::Triggers (format!("MaitreDesCles.{}", self.nom_partition)));

        queues
    }

    async fn preparer_index_mongodb_custom<M>(&self, middleware: &M) -> Result<(), String> where M: MongoDao {
        let nom_collection_cles = format!("MaitreDesCles_{}/cles", self.nom_partition);
        preparer_index_mongodb_custom(middleware, nom_collection_cles.as_str()).await
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_requete(middleware, message, self.nom_partition.as_str()).await
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
        entretien(middleware).await
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: MessageValideAction) -> Result<(), Box<dyn Error>> where M: Middleware + 'static {
        traiter_cedule(middleware, trigger).await
    }

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String> where M: ValidateurX509 + GenerateurMessages + MongoDao, T: Transaction {
        todo!()
    }
}

async fn consommer_requete<M>(middleware: &M, message: MessageValideAction, nom_partition: &str) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Consommer requete : {:?}", &message.message);

    // Autorisation : doit etre de niveau 4.secure
    match message.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                REQUETE_CERTIFICAT_MAITREDESCLES => emettre_certificat_maitredescles(middleware, message).await,
                _ => {
                    error!("Message requete/action inconnue : '{}'. Message dropped.", message.action);
                    Ok(None)
                },
            }
        },
        _ => {
            error!("Message requete/domaine inconnu : '{}'. Message dropped.", message.domaine);
            Ok(None)
        },
    }
}

async fn emettre_certificat_maitredescles<M>(middleware: &M, m: MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    debug!("emettre_certificat_maitredescles: {:?}", &m.message);
    let enveloppe_privee = middleware.get_enveloppe_privee();
    let chaine_pem = enveloppe_privee.chaine_pem();

    let reponse = json!({ "certificat": chaine_pem });

    let message_reponse = middleware.formatter_reponse(&reponse, None)?;
    Ok(Some(message_reponse))
}
