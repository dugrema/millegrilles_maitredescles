use std::error::Error;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{bson, doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage::CommandeSauvegarderCle;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::middleware::{Middleware, sauvegarder_transaction_recue};
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::options::UpdateOptions;
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
    pub fingerprint: String,
}

impl GestionnaireMaitreDesClesPartition {
    pub fn new(fingerprint: &str) -> Self {
        Self {
            fingerprint: String::from(fingerprint)
        }
    }

    /// Retourne une version tronquee du nom de partition
    /// Utilise pour nommer certaines ressources (e.g. collections Mongo)
    pub fn get_partition_tronquee(&self) -> String {
        let partition = self.fingerprint.as_str();

        // On utilise les 12 derniers chars du fingerprint (35..48)
        String::from(&partition[35..])
    }

    pub fn get_partition(&self) -> &str {
        self.fingerprint.as_str()
    }

    fn get_q_sauvegarder_cle(&self) -> String {
        format!("MaitreDesCles_{}/sauvegarder", self.fingerprint)
    }

    fn get_collection_cles(&self) -> String {
        format!("MaitreDesCles_{}/cles", self.get_partition_tronquee())
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
        // Utiliser le nom de la partition tronquee - evite que les noms de collections deviennent
        // trop long (cause un probleme lors de la creation d'index, max 127 chars sur path)
        format!("MaitreDesCles_{}", self.get_partition_tronquee())
    }

    fn get_collections_documents(&self) -> Vec<String> {
        // Utiliser le nom de la partition tronquee - evite que les noms de collections deviennent
        // trop long (cause un probleme lors de la creation d'index, max 127 chars sur path)
        vec![format!("MaitreDesCles_{}/cles", self.get_partition_tronquee())]
    }

    fn get_q_transactions(&self) -> String {
        format!("MaitreDesCles_{}/transactions", self.fingerprint)
    }

    fn get_q_volatils(&self) -> String {
        format!("MaitreDesCles_{}/volatils", self.fingerprint)
    }

    fn get_q_triggers(&self) -> String {
        format!("MaitreDesCles_{}/triggers", self.fingerprint)
    }

    fn preparer_queues(&self) -> Vec<QueueType> {
        let mut rk_dechiffrage = Vec::new();
        let mut rk_commande_cle = Vec::new();
        let mut rk_volatils = Vec::new();

        let commandes: Vec<&str> = vec![
            COMMANDE_SAUVEGARDER_CLE,
        ];
        let nom_partition = self.fingerprint.as_str();

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
                ttl: DEFAULT_Q_TTL.into(),
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
        queues.push(QueueType::Triggers (format!("MaitreDesCles.{}", self.fingerprint)));

        queues
    }

    async fn preparer_index_mongodb_custom<M>(&self, middleware: &M) -> Result<(), String> where M: MongoDao {
        let nom_collection_cles = self.get_collection_cles();
        preparer_index_mongodb_custom(middleware, nom_collection_cles.as_str()).await
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_requete(middleware, message, self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_commande(middleware, message, self).await
    }

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_transaction(middleware, message, self).await
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
        aiguillage_transaction(middleware, transaction, self).await
    }
}

async fn consommer_requete<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesPartition) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
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

async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesPartition) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("maitredescles_ca.consommer_transaction Consommer transaction : {:?}", &m.message);

    // Autorisation : doit etre de niveau 4.secure
    match m.verifier_exchanges(vec![Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("maitredescles_ca.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    match m.action.as_str() {
        TRANSACTION_CLE  => {
            sauvegarder_transaction_recue(middleware, m, gestionnaire.get_collection_transactions().as_str()).await?;
            Ok(None)
        },
        _ => Err(format!("maitredescles_ca.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    debug!("consommer_commande : {:?}", &m.message);

    // Autorisation : doit etre un message via exchange
    match m.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) {
        true => Ok(()),
        false => Err(format!("core_backup.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id)),
    }?;

    match m.action.as_str() {
        // Commandes standard
        COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire).await,
        // Commandes inconnues
        _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
    }
}

async fn commande_sauvegarder_cle<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao,
{
    debug!("commande_sauvegarder_cle Consommer commande : {:?}", & m.message);
    let commande: CommandeSauvegarderCle = m.message.get_msg().map_contenu(None)?;
    debug!("Commande sauvegarder cle parsed : {:?}", commande);

    let fingerprint = gestionnaire.fingerprint.as_str();
    let mut doc_bson: Document = commande.clone().into();

    // // Sauvegarder pour partition CA, on retire la partition recue
    // let _ = doc_bson.remove("partition");

    // Retirer cles, on re-insere la cle necessaire uniquement
    let cles = doc_bson.remove("cles");

    let cle = match commande.cles.get(fingerprint) {
        Some(cle) => cle.as_str(),
        None => {
            let message = format!("maitredescles_ca.commande_sauvegarder_cle: Erreur validation - commande sauvegarder cles ne contient pas la cle CA : {:?}", commande);
            warn!("{}", message);
            let reponse_err = json!({"ok": false, "err": message});
            return Ok(Some(middleware.formatter_reponse(&reponse_err, None)?));
        }
    };

    doc_bson.insert("dirty", true);
    doc_bson.insert("cle", cle);
    doc_bson.insert(CHAMP_CREATION, Utc::now());
    doc_bson.insert(CHAMP_MODIFICATION, Utc::now());

    let ops = doc! { "$setOnInsert": doc_bson };

    debug!("commande_sauvegarder_cle: Ops bson : {:?}", ops);

    let filtre = doc! { "hachage_bytes": commande.hachage_bytes.as_str() };
    let opts = UpdateOptions::builder().upsert(true).build();

    let collection = middleware.get_collection(gestionnaire.get_collection_cles().as_str())?;
    let resultat = collection.update_one(filtre, ops, opts).await?;
    debug!("commande_sauvegarder_cle Resultat update : {:?}", resultat);

    if let Some(uid) = resultat.upserted_id {
        debug!("commande_sauvegarder_cle Nouvelle cle insere _id: {}, generer transaction", uid);
        let transaction = TransactionCle::new_from_commande(&commande, fingerprint)?;
        let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_CLE)
            .partition(fingerprint)
            .exchanges(vec![Securite::L4Secure])
            .build();
        middleware.soumettre_transaction(routage, &transaction, false).await?;
    }

    Ok(middleware.reponse_ok()?)
}

async fn aiguillage_transaction<M, T>(middleware: &M, transaction: T, gestionnaire: &GestionnaireMaitreDesClesPartition) -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    match transaction.get_action() {
        TRANSACTION_CLE => transaction_cle(middleware, transaction, gestionnaire).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

async fn transaction_cle<M, T>(middleware: &M, transaction: T, gestionnaire: &GestionnaireMaitreDesClesPartition) -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_catalogue_horaire Consommer transaction : {:?}", &transaction);
    let transaction_cle: TransactionCle = match transaction.clone().convertir::<TransactionCle>() {
        Ok(t) => t,
        Err(e) => Err(format!("maitredescles_ca.transaction_cle Erreur conversion transaction : {:?}", e))?
    };
    let hachage_bytes = transaction_cle.hachage_bytes.as_str();
    let mut doc_bson_transaction = transaction.contenu();

    doc_bson_transaction.insert("non_dechiffrable", true);  // Flag non-dechiffrable par defaut (setOnInsert seulement)

    let filtre = doc! {CHAMP_HACHAGE_BYTES: hachage_bytes};
    let ops = doc! {
        "$set": {"dirty": false},
        "$setOnInsert": doc_bson_transaction,
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let opts = UpdateOptions::builder().upsert(true).build();
    let collection = middleware.get_collection(gestionnaire.get_collection_cles().as_str())?;
    debug!("transaction_cle update ops : {:?}", ops);
    let resultat = match collection.update_one(filtre, ops, opts).await {
        Ok(r) => r,
        Err(e) => Err(format!("maitredescles_ca.transaction_cle Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("transaction_cle Resultat transaction update : {:?}", resultat);

    Ok(None)
}
