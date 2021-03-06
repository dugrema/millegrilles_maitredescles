use std::collections::HashSet;
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage::CommandeSauvegarderCle;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::{Middleware, sauvegarder_transaction_recue};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::mongodb::options::{CountOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{TraiterTransaction, Transaction, TransactionImpl};
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::maitredescles_commun::*;

pub const NOM_COLLECTION_CLES: &str = "MaitreDesCles_CA/cles";
pub const NOM_COLLECTION_TRANSACTIONS: &str = "MaitreDesCles_CA";

// const NOM_Q_VOLATILS_GLOBAL: &str = "MaitreDesCles/volatils";

const NOM_Q_TRANSACTIONS: &str = "MaitreDesCles_CA/transactions";
const NOM_Q_VOLATILS: &str = "MaitreDesCles_CA/volatils";
const NOM_Q_TRIGGERS: &str = "MaitreDesCles_CA/triggers";
// const NOM_Q_PREFIXE: &str = "MaitreDesCles_CA";

const REQUETE_CLES_NON_DECHIFFRABLES: &str = "clesNonDechiffrables";
const REQUETE_COMPTER_CLES_NON_DECHIFFRABLES: &str = "compterClesNonDechiffrables";

#[derive(Clone, Debug)]
pub struct GestionnaireMaitreDesClesCa {
    pub fingerprint: String,
}

#[async_trait]
impl TraiterTransaction for GestionnaireMaitreDesClesCa {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireMaitreDesClesCa {
    fn get_nom_domaine(&self) -> String { String::from(DOMAINE_NOM) }

    fn get_collection_transactions(&self) -> String { String::from(NOM_COLLECTION_TRANSACTIONS) }

    fn get_collections_documents(&self) -> Vec<String> { vec![String::from(NOM_COLLECTION_CLES)] }

    fn get_q_transactions(&self) -> String { String::from(NOM_Q_TRANSACTIONS) }

    fn get_q_volatils(&self) -> String { String::from(NOM_Q_VOLATILS) }

    fn get_q_triggers(&self) -> String { String::from(NOM_Q_TRIGGERS) }

    fn preparer_queues(&self) -> Vec<QueueType> { preparer_queues() }

    fn chiffrer_backup(&self) -> bool {
        false
    }

    async fn preparer_index_mongodb_custom<M>(&self, middleware: &M) -> Result<(), String> where M: MongoDao {
        preparer_index_mongodb_custom(middleware, NOM_COLLECTION_CLES).await
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_requete(middleware, message, &self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_commande(middleware, message, &self).await
    }

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_transaction(middleware, message).await
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_evenement(middleware, message).await
    }

    async fn entretien<M>(&self, middleware: Arc<M>) where M: Middleware + 'static {
        entretien(middleware).await
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: MessageValideAction) -> Result<(), Box<dyn Error>> where M: Middleware + 'static {
        traiter_cedule(middleware, trigger).await
    }

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String> where M: ValidateurX509 + GenerateurMessages + MongoDao, T: Transaction {
        aiguillage_transaction(middleware, transaction).await
    }
}

pub fn preparer_queues() -> Vec<QueueType> {
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
    ];
    for evnt in evenements_proteges {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_NOM, evnt), exchange: Securite::L3Protege});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("evenement.{}.{}", DOMAINE_NOM, evnt), exchange: Securite::L4Secure});
    }
    let commandes_protegees: Vec<&str> = vec![COMMANDE_CONFIRMER_CLES_SUR_CA];
    for cmd in commandes_protegees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L3Protege});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L4Secure});
    }

    // Capturer les commandes "sauver cle" sur tous les exchanges pour toutes les partitions
    // Va creer la transaction locale CA si approprie
    for sec in [Securite::L1Public, Securite::L2Prive] {
        rk_sauvegarder_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.*.{}", DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE), exchange: sec });
    }

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
            nom_queue: NOM_Q_VOLATILS.into(),
            routing_keys: rk_volatils,
            ttl: DEFAULT_Q_TTL.into(),
            durable: true,
        }
    ));

    let mut rk_transactions = Vec::new();
    rk_transactions.push(ConfigRoutingExchange {
        routing_key: format!("transaction.{}.{}", DOMAINE_NOM, TRANSACTION_CLE).into(),
        exchange: Securite::L4Secure
    });

    // Queue commande de sauvegarde de cle
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: String::from("MaitreDesCles_CA/sauvegarder"),
            routing_keys: rk_sauvegarder_cle,
            ttl: None,
            durable: true,
        }
    ));

    // Queue de transactions
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_TRANSACTIONS.into(),
            routing_keys: rk_transactions,
            ttl: None,
            durable: true,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (DOMAINE_NOM.into()));

    queues
}

async fn consommer_requete<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesCa) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("Consommer requete : {:?}", &message.message);

    // Autorisation : On accepte les requetes de 3.protege ou 4.secure
    match message.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("Trigger cedule autorisation invalide (pas d'un exchange reconnu)")),
    }?;

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                REQUETE_COMPTER_CLES_NON_DECHIFFRABLES => requete_compter_cles_non_dechiffrables(middleware, message, gestionnaire).await,
                REQUETE_CLES_NON_DECHIFFRABLES => requete_cles_non_dechiffrables(middleware, message, gestionnaire).await,
                REQUETE_SYNCHRONISER_CLES => requete_synchronizer_cles(middleware, message, gestionnaire).await,
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

async fn consommer_evenement<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("maitredescles_ca.consommer_evenement Consommer evenement : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("maitredescles_ca.consommer_evenement: Evenement invalide (pas 3.protege ou 4.secure)")),
    }?;

    match m.action.as_str() {
        EVENEMENT_CLES_MANQUANTES_PARTITION => {
            evenement_cle_manquante(middleware, &m).await?;
            Ok(None)
        },
        _ => Err(format!("maitredescles_ca.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}


async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("maitredescles_ca.consommer_transaction Consommer transaction : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("maitredescles_ca.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    match m.action.as_str() {
        TRANSACTION_CLE  => {
            sauvegarder_transaction_recue(middleware, m, NOM_COLLECTION_TRANSACTIONS).await?;
            Ok(None)
        },
        _ => Err(format!("maitredescles_ca.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire_ca: &GestionnaireMaitreDesClesCa)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("consommer_commande : {:?}", &m.message);

    // Autorisation : doit etre un message via exchange
    match m.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) {
        true => Ok(()),
        false => {
            // Verifier si on a un certificat delegation globale
            match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                true => Ok(()),
                false => Err(format!("maitredescles_ca.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id)),
            }
        }
    }?;

    match m.action.as_str() {
        // Commandes standard
        COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire_ca).await,
        COMMANDE_CONFIRMER_CLES_SUR_CA => commande_confirmer_cles_sur_ca(middleware, m, gestionnaire_ca).await,
        // Commandes inconnues
        _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
    }
}

async fn commande_sauvegarder_cle<M>(middleware: &M, m: MessageValideAction, gestionnaire_ca: &GestionnaireMaitreDesClesCa)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao,
{
    debug!("commande_sauvegarder_cle Consommer commande : {:?}", & m.message);
    let commande: CommandeSauvegarderCle = m.message.get_msg().map_contenu(None)?;
    debug!("Commande sauvegarder cle parsed : {:?}", commande);

    let fingerprint = gestionnaire_ca.fingerprint.as_str();
    let mut doc_bson: Document = commande.clone().into();

    // // Sauvegarder pour partition CA, on retire la partition recue
    // let _ = doc_bson.remove("partition");

    // Retirer cles, on re-insere la cle necessaire uniquement
    doc_bson.remove("cles");

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

    let nb_cles = commande.cles.len();
    let non_dechiffrable = nb_cles < 2;
    debug!("commande_sauvegarder_cle: On a recu {} cles, non-dechiffables (presume) : {}", nb_cles, non_dechiffrable);
    doc_bson.insert("non_dechiffrable", non_dechiffrable);

    let ops = doc! { "$setOnInsert": doc_bson };

    debug!("commande_sauvegarder_cle: Ops bson : {:?}", ops);

    let filtre = doc! { "hachage_bytes": commande.hachage_bytes.as_str() };
    let opts = UpdateOptions::builder().upsert(true).build();

    let collection = middleware.get_collection(NOM_COLLECTION_CLES)?;
    let resultat = collection.update_one(filtre, ops, opts).await?;
    debug!("commande_sauvegarder_cle Resultat update : {:?}", resultat);

    if let Some(uid) = resultat.upserted_id {
        debug!("commande_sauvegarder_cle Nouvelle cle insere _id: {}, generer transaction", uid);
        let transaction = TransactionCle::new_from_commande(&commande, fingerprint)?;
        let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_CLE)
            .exchanges(vec![Securite::L4Secure])
            .build();
        middleware.soumettre_transaction(routage, &transaction, false).await?;
    }

    Ok(middleware.reponse_ok()?)
}

async fn aiguillage_transaction<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    match transaction.get_action() {
        TRANSACTION_CLE => transaction_cle(middleware, transaction).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

async fn transaction_cle<M, T>(middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
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
    let collection = middleware.get_collection(NOM_COLLECTION_CLES)?;
    debug!("transaction_cle update ops : {:?}", ops);
    let resultat = match collection.update_one(filtre, ops, opts).await {
        Ok(r) => r,
        Err(e) => Err(format!("maitredescles_ca.transaction_cle Erreur update_one sur transcation : {:?}", e))?
    };
    debug!("transaction_cle Resultat transaction update : {:?}", resultat);

    Ok(None)
}

async fn requete_compter_cles_non_dechiffrables<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesCa)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_compter_cles_non_dechiffrables Consommer commande : {:?}", & m.message);
    // let requete: RequeteDechiffrage = m.message.get_msg().map_contenu(None)?;
    // debug!("requete_compter_cles_non_dechiffrables cle parsed : {:?}", requete);

    let filtre = doc! { CHAMP_NON_DECHIFFRABLE: true };
    let hint = Hint::Name(INDEX_NON_DECHIFFRABLES.into());
    // let sort_doc = doc! {
    //     CHAMP_NON_DECHIFFRABLE: 1,
    //     CHAMP_CREATION: 1,
    // };
    let opts = CountOptions::builder().hint(hint).build();
    let collection = middleware.get_collection(NOM_COLLECTION_CLES)?;
    let compte = collection.count_documents(filtre, opts).await?;

    let reponse = json!({ "compte": compte });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_cles_non_dechiffrables<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesCa)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_cles_non_dechiffrables Consommer commande : {:?}", & m.message);
    let requete: RequeteClesNonDechiffrable = m.message.get_msg().map_contenu(None)?;
    debug!("requete_cles_non_dechiffrables cle parsed : {:?}", requete);

    let mut curseur = {
        let limite_docs = match requete.limite {
            Some(l) => l,
            None => 1000 as u64
        };
        let page = match requete.page {
            Some(p) => p,
            None => 0 as u64
        };
        let start_index = page * limite_docs;

        let filtre = doc! { CHAMP_NON_DECHIFFRABLE: true };
        let hint = Hint::Name(INDEX_NON_DECHIFFRABLES.into());
        let sort_doc = doc! {
            CHAMP_NON_DECHIFFRABLE: 1,
            CHAMP_CREATION: 1,
        };
        let opts = FindOptions::builder()
            .hint(hint)
            .sort(sort_doc)
            .skip(Some(start_index))
            .limit(Some(limite_docs as i64))
            .build();
        let collection = middleware.get_collection(NOM_COLLECTION_CLES)?;

        collection.find(filtre, opts).await?
    };

    let mut cles = Vec::new();
    while let Some(d) = curseur.next().await {
        match d {
            Ok(doc_cle) => {
                let rep_cle: TransactionCle = convertir_bson_deserializable(doc_cle)?;
                cles.push(rep_cle);
            },
            Err(e) => error!("requete_cles_non_dechiffrables Erreur lecture doc cle : {:?}", e)
        }
    }

    let reponse = json!({ "cles": cles });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteClesNonDechiffrable {
    limite: Option<u64>,
    page: Option<u64>,
}

async fn requete_synchronizer_cles<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesCa)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_synchronizer_cles Consommer requete : {:?}", & m.message);
    let requete: RequeteSynchroniserCles = m.message.get_msg().map_contenu(None)?;
    debug!("requete_synchronizer_cles cle parsed : {:?}", requete);

    let mut curseur = {
        let limite_docs = requete.limite;
        let page = requete.page;
        let start_index = page * limite_docs;

        let filtre = doc! {};
        let hint = Hint::Keys(doc!{"_id": 1});  // Index _id
        let sort_doc = doc! {"_id": 1};
        let projection = doc!{CHAMP_HACHAGE_BYTES: 1};
        let opts = FindOptions::builder()
            .hint(hint)
            .sort(sort_doc)
            .skip(Some(start_index as u64))
            .limit(Some(limite_docs as i64))
            .projection(Some(projection))
            .build();
        let collection = middleware.get_collection(NOM_COLLECTION_CLES)?;

        collection.find(filtre, opts).await?
    };

    let mut cles = Vec::new();
    while let Some(d) = curseur.next().await {
        match d {
            Ok(doc_cle) => {
                match doc_cle.get(CHAMP_HACHAGE_BYTES) {
                    Some(h) => {
                        match h.as_str() {
                            Some(h) => cles.push(h.to_owned()),
                            None => ()
                        }
                    },
                    None => ()
                }
            },
            Err(e) => error!("requete_synchronizer_cles Erreur lecture doc cle : {:?}", e)
        }
    }

    let reponse = ReponseSynchroniserCles { liste_hachage_bytes: cles };
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn evenement_cle_manquante<M>(middleware: &M, m: &MessageValideAction) -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("evenement_cle_manquante Marquer cles comme non dechiffrables {:?}", &m.message);
    let event_non_dechiffrables: ReponseSynchroniserCles = m.message.get_msg().map_contenu(None)?;

    let filtre = doc! { CHAMP_HACHAGE_BYTES: { "$in": event_non_dechiffrables.liste_hachage_bytes }};
    let ops = doc! {
        "$set": { CHAMP_NON_DECHIFFRABLE: true },
        "$currentDate": { CHAMP_MODIFICATION: true },
    };
    let collection = middleware.get_collection(NOM_COLLECTION_CLES)?;
    let resultat_update = collection.update_many(filtre, ops, None).await?;
    debug!("evenement_cle_manquante Resultat update : {:?}", resultat_update);

    Ok(())
}

async fn commande_confirmer_cles_sur_ca<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesCa)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("commande_confirmer_cles_sur_ca Consommer commande : {:?}", & m.message);
    let requete: ReponseSynchroniserCles = m.message.get_msg().map_contenu(None)?;
    debug!("requete_synchronizer_cles cle parsed : {:?}", requete);

    let mut cles_manquantes = HashSet::new();
    cles_manquantes.extend(requete.liste_hachage_bytes.clone());

    let filtre = doc! [ CHAMP_HACHAGE_BYTES: {"$in": &requete.liste_hachage_bytes } ];

    // Marquer les cles recues comme dechiffrables sur au moins une partition
    let ops = doc! {
        "$set": { CHAMP_NON_DECHIFFRABLE: false},
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let collection = middleware.get_collection(NOM_COLLECTION_CLES)?;
    let resultat_update = collection.update_many(filtre.clone(), ops, None).await?;
    debug!("commande_confirmer_cles_sur_ca Resultat update : {:?}", resultat_update);

    let projection = doc! { CHAMP_HACHAGE_BYTES: 1 };
    let opts = FindOptions::builder().projection(projection).build();
    let mut curseur = collection.find(filtre, opts).await?;
    while let Some(d) = curseur.next().await {
        match d {
            Ok(d) => {
                match d.get(CHAMP_HACHAGE_BYTES) {
                    Some(c) => match c.as_str() {
                        Some(hachage) => {
                            // Enlever la cle de la liste de cles manquantes
                            cles_manquantes.remove(hachage);
                        },
                        None => ()
                    },
                    None => ()
                }
            },
            Err(e) => warn!("Erreur traitement curseur mongo : {:?}", e)
        }
    }

    let mut vec_cles_manquantes = Vec::new();
    vec_cles_manquantes.extend(cles_manquantes);
    let reponse = ReponseConfirmerClesSurCa { cles_manquantes: vec_cles_manquantes };
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[cfg(test)]
mod test_integration {
    use millegrilles_common_rust::backup::CatalogueHoraire;
    use millegrilles_common_rust::formatteur_messages::MessageSerialise;
    use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
    use millegrilles_common_rust::middleware::IsConfigurationPki;
    use millegrilles_common_rust::middleware_db::preparer_middleware_db;
    use millegrilles_common_rust::mongo_dao::convertir_to_bson;
    use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
    use millegrilles_common_rust::recepteur_messages::TypeMessage;
    use millegrilles_common_rust::tokio as tokio;

    use crate::test_setup::setup;

    use super::*;

    #[tokio::test]
    async fn test_requete_compte_non_dechiffrable() {
        setup("test_requete_compte_non_dechiffrable");
        let (middleware, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
        let enveloppe_privee = middleware.get_enveloppe_privee();
        let fingerprint = enveloppe_privee.fingerprint().as_str();

        let gestionnaire = GestionnaireMaitreDesClesCa {fingerprint: fingerprint.into()};
        futures.push(tokio::spawn(async move {

            let contenu = json!({});
            let message_mg = MessageMilleGrille::new_signer(
                enveloppe_privee.as_ref(),
                &contenu,
                DOMAINE_NOM.into(),
                REQUETE_COMPTER_CLES_NON_DECHIFFRABLES.into(),
                None::<&str>,
                None
            ).expect("message");
            let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");

            // Injecter certificat utilise pour signer
            message.certificat = Some(enveloppe_privee.enveloppe.clone());

            let mva = MessageValideAction::new(
                message, "dummy_q", "routing_key", "domaine", "action", TypeMessageOut::Requete);

            let reponse = requete_compter_cles_non_dechiffrables(middleware.as_ref(), mva, &gestionnaire).await.expect("dechiffrage");
            debug!("Reponse requete compte cles non dechiffrables : {:?}", reponse);

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }

    #[tokio::test]
    async fn test_requete_cles_non_dechiffrable() {
        setup("test_requete_cles_non_dechiffrable");
        let (middleware, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
        let enveloppe_privee = middleware.get_enveloppe_privee();
        let fingerprint = enveloppe_privee.fingerprint().as_str();

        let gestionnaire = GestionnaireMaitreDesClesCa {fingerprint: fingerprint.into()};
        futures.push(tokio::spawn(async move {

            let contenu = json!({
                "limite": 5,
                "page": 0,
            });
            let message_mg = MessageMilleGrille::new_signer(
                enveloppe_privee.as_ref(),
                &contenu,
                DOMAINE_NOM.into(),
                REQUETE_COMPTER_CLES_NON_DECHIFFRABLES.into(),
                None::<&str>,
                None
            ).expect("message");
            let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");

            // Injecter certificat utilise pour signer
            message.certificat = Some(enveloppe_privee.enveloppe.clone());

            let mva = MessageValideAction::new(
                message, "dummy_q", "routing_key", "domaine", "action", TypeMessageOut::Requete);

            let reponse = requete_cles_non_dechiffrables(middleware.as_ref(), mva, &gestionnaire).await.expect("dechiffrage");
            debug!("Reponse requete compte cles non dechiffrables : {:?}", reponse);

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }

    #[tokio::test]
    async fn test_requete_synchronizer_cles() {
        setup("test_requete_synchronizer_cles");
        let (middleware, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
        let enveloppe_privee = middleware.get_enveloppe_privee();
        let fingerprint = enveloppe_privee.fingerprint().as_str();

        let gestionnaire = GestionnaireMaitreDesClesCa {fingerprint: fingerprint.into()};
        futures.push(tokio::spawn(async move {

            let contenu = json!({
                "limite": 5,
                "page": 0,
            });
            let message_mg = MessageMilleGrille::new_signer(
                enveloppe_privee.as_ref(),
                &contenu,
                DOMAINE_NOM.into(),
                REQUETE_COMPTER_CLES_NON_DECHIFFRABLES.into(),
                None::<&str>,
                None
            ).expect("message");
            let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");

            // Injecter certificat utilise pour signer
            message.certificat = Some(enveloppe_privee.enveloppe.clone());

            let mva = MessageValideAction::new(
                message, "dummy_q", "routing_key", "domaine", "action", TypeMessageOut::Requete);

            let reponse = requete_synchronizer_cles(middleware.as_ref(), mva, &gestionnaire).await.expect("dechiffrage");
            debug!("test_requete_synchronizer_cles Reponse : {:?}", reponse);

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }
}
