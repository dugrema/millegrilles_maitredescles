use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::error::Error;
use std::fs::read_dir;
use std::sync::Arc;

use log::{debug, error, info, warn};
use millegrilles_common_rust::multibase::Base;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{EnveloppeCertificat, EnveloppePrivee, ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage::{Chiffreur, CommandeSauvegarderCle, dechiffrer_asymetrique_multibase, rechiffrer_asymetrique_multibase};
use millegrilles_common_rust::chiffrage_chacha20poly1305::{CipherMgs3, Mgs3CipherKeys};
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::constantes::Securite::L3Protege;
use millegrilles_common_rust::common_messages::{RequeteVerifierPreuve, TransactionCle};
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille, MessageSerialise};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::hachages::hacher_bytes;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, sauvegarder_transaction, sauvegarder_transaction_recue};
use millegrilles_common_rust::mongo_dao::{ChampIndex, convertir_bson_deserializable, convertir_to_bson, IndexOptions, MongoDao};
use millegrilles_common_rust::mongodb::Cursor;
use millegrilles_common_rust::mongodb::options::{FindOptions, UpdateOptions};
use millegrilles_common_rust::multihash::Code;
use millegrilles_common_rust::openssl::pkey::{PKey, Private};
use millegrilles_common_rust::openssl::rsa::Rsa;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio::fs::File as File_tokio;
use millegrilles_common_rust::tokio::io::AsyncReadExt;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{EtatTransaction, marquer_transaction, TraiterTransaction, Transaction, TransactionImpl};
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::maitredescles_commun::*;

// const NOM_COLLECTION_RECHIFFRAGE: &str = "MaitreDesCles/rechiffrage";

// const NOM_Q_VOLATILS_GLOBAL: &str = "MaitreDesCles/volatils";

const REQUETE_CERTIFICAT_MAITREDESCLES: &str = COMMANDE_CERT_MAITREDESCLES;

const COMMANDE_RECHIFFRER_BATCH: &str = "rechiffrerBatch";

const INDEX_RECHIFFRAGE_PK: &str = "fingerprint_pk";
const INDEX_CONFIRMATION_CA: &str = "confirmation_ca";

const CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";
const CHAMP_CONFIRMATION_CA: &str = "confirmation_ca";

#[derive(Clone, Debug)]
pub struct GestionnaireMaitreDesClesPartition {
    pub fingerprint: String,
}

fn nom_collection_transactions<S>(fingerprint: S) -> String
    where S: AsRef<str>
{
    // On utilise les 12 derniers chars du fingerprint (35..48)
    // let fp = fingerprint.as_ref();
    // format!("MaitreDesCles/{}", &fp[35..])
    String::from("MaitreDesCles/DUMMY")
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

    fn get_q_sauvegarder_cle(&self) -> String {
        format!("MaitreDesCles/{}/sauvegarder", self.fingerprint)
    }

    fn get_collection_cles(&self) -> String {
        format!("MaitreDesCles/{}/cles", self.get_partition_tronquee())
    }

    /// Verifie si le CA a des cles qui ne sont pas connues localement
    pub async fn synchroniser_cles<M>(&self, middleware: &M) -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages + MongoDao + VerificateurMessage + Chiffreur<CipherMgs3, Mgs3CipherKeys>
    {
        synchroniser_cles(middleware, self).await?;
        Ok(())
    }

    /// S'assure que le CA a toutes les cles presentes dans la partition
    pub async fn confirmer_cles_ca<M>(&self, middleware: &M, reset_flag: Option<bool>) -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages + MongoDao + VerificateurMessage + Chiffreur<CipherMgs3, Mgs3CipherKeys>
    {
        confirmer_cles_ca(middleware, self, reset_flag).await?;
        Ok(())
    }

    pub async fn emettre_certificat_maitredescles<M>(&self, middleware: &M, m: Option<MessageValideAction>) -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages + MongoDao
    {
        emettre_certificat_maitredescles(middleware, m).await
    }

}

#[async_trait]
impl TraiterTransaction for GestionnaireMaitreDesClesPartition {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction, self).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireMaitreDesClesPartition {
    fn get_nom_domaine(&self) -> String { String::from(DOMAINE_NOM) }

    fn get_partition(&self) -> Option<String> {
        Some(self.fingerprint.clone())
    }

    fn get_collection_transactions(&self) -> String {
        // Utiliser le nom de la partition tronquee - evite que les noms de collections deviennent
        // trop long (cause un probleme lors de la creation d'index, max 127 chars sur path)
        //format!("MaitreDesCles/{}", self.get_partition_tronquee())
        String::from("MaitreDesCles/DUMMY")
    }

    fn get_collections_documents(&self) -> Vec<String> {
        // Utiliser le nom de la partition tronquee - evite que les noms de collections deviennent
        // trop long (cause un probleme lors de la creation d'index, max 127 chars sur path)
        vec![format!("MaitreDesCles/{}/cles", self.get_partition_tronquee())]
    }

    fn get_q_transactions(&self) -> String {
        format!("MaitreDesCles/{}/transactions", self.fingerprint)
    }

    fn get_q_volatils(&self) -> String {
        format!("MaitreDesCles/{}/volatils", self.fingerprint)
    }

    fn get_q_triggers(&self) -> String {
        format!("MaitreDesCles/{}/triggers", self.fingerprint)
    }

    fn preparer_queues(&self) -> Vec<QueueType> {
        let mut rk_dechiffrage = Vec::new();
        let mut rk_commande_cle = Vec::new();
        let mut rk_volatils = Vec::new();

        let commandes: Vec<&str> = vec![
            COMMANDE_SAUVEGARDER_CLE,
        ];
        let nom_partition = self.fingerprint.as_str();

        for sec in [Securite::L1Public, Securite::L2Prive, Securite::L3Protege] {
            rk_dechiffrage.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_DECHIFFRAGE), exchange: sec.clone() });
            rk_dechiffrage.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_VERIFIER_PREUVE), exchange: sec.clone() });
            rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_CERTIFICAT_MAITREDESCLES), exchange: sec.clone() });
            rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}.{}", DOMAINE_NOM, nom_partition, REQUETE_VERIFIER_PREUVE), exchange: sec.clone() });

            // Commande volatile
            rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_CERT_MAITREDESCLES), exchange: sec.clone() });

            // Commande sauvegarder cles
            for commande in &commandes {
                rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, nom_partition, commande), exchange: sec.clone() });
            }
        }

        // Commande sauvegarder cle 4.secure pour redistribution des cles
        rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE), exchange: Securite::L4Secure });
        rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, nom_partition, COMMANDE_SAUVEGARDER_CLE), exchange: Securite::L4Secure });

        // Requetes de dechiffrage/preuve re-emise sur le bus 4.secure lorsque la cle est inconnue
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_DECHIFFRAGE), exchange: Securite::L4Secure });
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_VERIFIER_PREUVE), exchange: Securite::L4Secure });

        for sec in [Securite::L3Protege, Securite::L4Secure] {
            rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION), exchange: sec.clone() });
        }

        let commandes_protegees = vec![
            COMMANDE_RECHIFFRER_BATCH,
        ];
        for commande in commandes_protegees {
            rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, nom_partition, commande), exchange: L3Protege });
        }

        let mut queues = Vec::new();

        // Queue de messages dechiffrage - taches partagees entre toutes les partitions
        queues.push(QueueType::ExchangeQueue(
            ConfigQueue {
                nom_queue: NOM_Q_DECHIFFRAGE.into(),
                routing_keys: rk_dechiffrage,
                ttl: DEFAULT_Q_TTL.into(),
                durable: false,
            }
        ));

        // Queue commande de sauvegarde de cle
        queues.push(QueueType::ExchangeQueue(
            ConfigQueue {
                nom_queue: self.get_q_sauvegarder_cle(),
                routing_keys: rk_commande_cle,
                ttl: None,
                durable: false,
            }
        ));

        // Queue volatils
        queues.push(QueueType::ExchangeQueue(
            ConfigQueue {
                nom_queue: self.get_q_volatils().into(),
                routing_keys: rk_volatils,
                ttl: DEFAULT_Q_TTL.into(),
                durable: false,
            }
        ));

        let mut rk_transactions = Vec::new();
        // rk_transactions.push(ConfigRoutingExchange {
        //     routing_key: format!("transaction.{}.{}.{}", DOMAINE_NOM, nom_partition, TRANSACTION_CLE).into(),
        //     exchange: Securite::L4Secure
        // });

        // Queue de transactions
        queues.push(QueueType::ExchangeQueue(
            ConfigQueue {
                nom_queue: self.get_q_transactions(),
                routing_keys: rk_transactions,
                ttl: None,
                durable: false,
            }
        ));

        // Queue de triggers
        queues.push(QueueType::Triggers(format!("MaitreDesCles.{}", self.fingerprint), Securite::L3Protege));

        queues
    }

    fn chiffrer_backup(&self) -> bool {
        false
    }

    async fn preparer_database<M>(&self, middleware: &M) -> Result<(), String> where M: Middleware + 'static {
        let nom_collection_cles = self.get_collection_cles();
        preparer_index_mongodb_custom(middleware, nom_collection_cles.as_str()).await?;
        preparer_index_mongodb_partition(middleware, self).await?;

        Ok(())
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
        consommer_evenement(middleware, self, message).await
    }

    async fn entretien<M>(&self, middleware: Arc<M>) where M: Middleware + 'static {
        entretien(middleware).await
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule) -> Result<(), Box<dyn Error>> where M: Middleware + 'static {
        traiter_cedule(middleware, trigger).await
    }

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String> where M: ValidateurX509 + GenerateurMessages + MongoDao, T: Transaction {
        aiguillage_transaction(middleware, transaction, self).await
    }
}

pub async fn preparer_index_mongodb_partition<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition) -> Result<(), String>
    where M: MongoDao
{
    let collection_cles = gestionnaire.get_collection_cles();

    // Index confirmation ca (table cles)
    let options_confirmation_ca = IndexOptions {
        nom_index: Some(String::from(INDEX_CONFIRMATION_CA)),
        unique: false
    };
    let champs_index_confirmation_ca = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_CONFIRMATION_CA), direction: 1},
    );
    middleware.create_index(
        collection_cles.as_ref(),
        champs_index_confirmation_ca,
        Some(options_confirmation_ca)
    ).await?;

    Ok(())
}

async fn consommer_requete<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesPartition) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage + Chiffreur<CipherMgs3, Mgs3CipherKeys>
{
    debug!("Consommer requete : {:?}", &message.message);

    let user_id = message.get_user_id();
    let role_prive = message.verifier_roles(vec![RolesCertificats::ComptePrive]);

    if role_prive == true && user_id.is_some() {
        // OK
    } else if message.verifier_exchanges(vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
        // Autorisation : On accepte les requetes de tous les echanges
    } else if message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Delegation globale
    } else {
        Err(format!("Autorisation requete invalide, acces refuse"))?
    }

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                REQUETE_CERTIFICAT_MAITREDESCLES => requete_certificat_maitredescles(middleware, message).await,
                REQUETE_DECHIFFRAGE => requete_dechiffrage(middleware, message, gestionnaire).await,
                REQUETE_VERIFIER_PREUVE => requete_verifier_preuve(middleware, message, gestionnaire).await,
                EVENEMENT_CLES_MANQUANTES_PARTITION => evenement_cle_manquante(middleware, message, gestionnaire).await,
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

async fn requete_certificat_maitredescles<M>(middleware: &M, m: MessageValideAction)
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

/// Emet le certificat de maitre des cles
/// Le message n'a aucun contenu, c'est l'enveloppe qui permet de livrer le certificat
/// Si message est None, emet sur evenement.MaitreDesCles.certMaitreDesCles
pub async fn emettre_certificat_maitredescles<M>(middleware: &M, m: Option<MessageValideAction>)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao
{
    debug!("emettre_certificat_maitredescles");

    let reponse = json!({});

    match m {
        Some(demande) => {
            match demande.reply_q.as_ref() {
                Some(reply_q) => {
                    // On utilise une correlation fixe pour permettre au demandeur de recevoir les
                    // reponses de plusieurs partitions de maitre des cles en meme temps.
                    let routage = RoutageMessageReponse::new(
                        reply_q, COMMANDE_CERT_MAITREDESCLES);
                    let message_reponse = middleware.formatter_reponse(&reponse, None)?;
                    middleware.repondre(routage, message_reponse).await?;
                },
                None => {
                    debug!("Mauvais message recu pour emettre_certificat (pas de reply_q)");
                }
            }
        },
        None => {
            let routage = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_CERT_MAITREDESCLES)
                .exchanges(vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])
                .correlation_id(COMMANDE_CERT_MAITREDESCLES)
                .build();
            middleware.emettre_evenement(routage, &reponse).await?;
        }
    }

    Ok(())
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

async fn consommer_evenement<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + Chiffreur<CipherMgs3, Mgs3CipherKeys>
{
    debug!("consommer_evenement Consommer evenement : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("consommer_evenement: Evenement invalide (pas 3.protege ou 4.secure)")),
    }?;

    match m.action.as_str() {
        // EVENEMENT_CLES_MANQUANTES_PARTITION => evenement_cle_manquante(middleware, gestionnaire, &m).await,
        _ => Err(format!("consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + Chiffreur<CipherMgs3, Mgs3CipherKeys>
{
    debug!("consommer_commande : {:?}", &m.message);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);

    if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        match m.action.as_str() {
            // Commandes standard
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire).await,
            COMMANDE_CERT_MAITREDESCLES => {emettre_certificat_maitredescles(middleware, Some(m)).await?; Ok(None)},

            COMMANDE_RECHIFFRER_BATCH => commande_rechiffrer_batch(middleware, m, gestionnaire).await,
            // Commandes inconnues
            _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
        }
    } else if role_prive == true && user_id.is_some() {
        match m.action.as_str() {
            // Commandes standard
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire).await,
            COMMANDE_CERT_MAITREDESCLES => {emettre_certificat_maitredescles(middleware, Some(m)).await?; Ok(None)},
            // Commandes inconnues
            _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
        }
    } else if m.verifier_exchanges(vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
        match m.action.as_str() {
            // Commandes standard
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire).await,
            COMMANDE_CERT_MAITREDESCLES => {emettre_certificat_maitredescles(middleware, Some(m)).await?; Ok(None)},
            // Commandes inconnues
            _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
        }
    } else {
        Err(format!("Autorisation commande invalide, acces refuse"))?
    }
}

async fn commande_sauvegarder_cle<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + Chiffreur<CipherMgs3, Mgs3CipherKeys>
{
    debug!("commande_sauvegarder_cle Consommer commande : {:?}", & m.message);
    let commande: CommandeSauvegarderCle = m.message.get_msg().map_contenu(None)?;
    debug!("Commande sauvegarder cle parsed : {:?}", commande);

    let fingerprint = gestionnaire.fingerprint.as_str();

    let cle = match commande.cles.get(fingerprint) {
        Some(cle) => cle.as_str(),
        None => {
            let message = format!("maitredescles_ca.commande_sauvegarder_cle: Erreur validation - commande sauvegarder cles ne contient pas la cle CA : {:?}", commande);
            warn!("{}", message);
            let reponse_err = json!({"ok": false, "err": message});
            return Ok(Some(middleware.formatter_reponse(&reponse_err, None)?));
        }
    };

    // Sauvegarde cle dans mongodb

    let mut doc_bson: Document = commande.clone().into();
    // Retirer cles, on re-insere la cle necessaire uniquement
    doc_bson.remove("cles");

    doc_bson.insert("dirty", true);
    doc_bson.insert("confirmation_ca", false);
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
        // Detecter si on doit rechiffrer et re-emettre la cles
        // Survient si on a recu une commande sur un exchange autre que 4.secure et qu'il a moins de
        // cles dans la commande que le nombre de cles de rechiffrage connues (incluant cert maitre des cles)
        if let Some(exchange) = m.exchange.as_ref() {
            if exchange != SECURITE_4_SECURE {
                let transaction = TransactionCle::new_from_commande(&commande, fingerprint)?;
                let pk_chiffrage = middleware.get_publickeys_chiffrage();
                if pk_chiffrage.len() > commande.cles.len() {
                    debug!("commande_sauvegarder_cle Nouvelle cle sur exchange != 4.secure, re-emettre a l'interne");
                    let commande_cle_rechiffree = rechiffrer_pour_maitredescles(middleware, &transaction)?;
                    let routage_commande = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE)
                        .exchanges(vec![Securite::L4Secure])
                        .build();
                    middleware.transmettre_commande(routage_commande, &commande_cle_rechiffree, false).await?;
                }
            }
        }

    }

    Ok(middleware.reponse_ok()?)
}

async fn commande_rechiffrer_batch<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + Chiffreur<CipherMgs3, Mgs3CipherKeys>
{
    debug!("commande_rechiffrer_batch Consommer commande : {:?}", & m.message);
    let commande: CommandeRechiffrerBatch = m.message.get_msg().map_contenu(None)?;
    debug!("commande_rechiffrer_batch Commande parsed : {:?}", commande);

    let fingerprint = gestionnaire.fingerprint.as_str();
    let enveloppe_privee = middleware.get_enveloppe_privee();
    let fingerprint_ca = enveloppe_privee.enveloppe_ca.fingerprint.clone();

    // Determiner si on doit rechiffrer pour d'autres maitre des cles
    let cles_chiffrage = {
        let mut cles_chiffrage = Vec::new();
        for fingerprint_cert_cle in middleware.get_publickeys_chiffrage() {
            let fingerprint_cle = fingerprint_cert_cle.fingerprint;
            if fingerprint_cle != fingerprint && fingerprint_cle != fingerprint_ca {
                cles_chiffrage.push(fingerprint_cert_cle.public_key);
            }
        }
        cles_chiffrage
    };

    let routage_commande = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE)
        .exchanges(vec![Securite::L4Secure])
        .build();

    let collection = middleware.get_collection(gestionnaire.get_collection_cles().as_str())?;

    // Traiter chaque cle individuellement
    let liste_hachage_bytes: Vec<String> = commande.cles.iter().map(|c| c.hachage_bytes.to_owned()).collect();
    for cle in commande.cles {
        let mut doc_cle = convertir_to_bson(cle.clone())?;
        doc_cle.insert("dirty", true);
        doc_cle.insert("confirmation_ca", false);
        doc_cle.insert(CHAMP_CREATION, Utc::now());
        doc_cle.insert(CHAMP_MODIFICATION, Utc::now());
        let filtre = doc! { "hachage_bytes": cle.hachage_bytes.as_str() };
        let ops = doc! { "$setOnInsert": doc_cle };
        let opts = UpdateOptions::builder().upsert(true).build();
        let resultat = collection.update_one(filtre, ops, opts).await?;

        // Rechiffrer pour tous les autres maitre des cles
        if cles_chiffrage.len() > 0 {
            let commande_rechiffree = rechiffrer_pour_maitredescles(middleware, &cle)?;
            middleware.transmettre_commande(routage_commande.clone(), &commande_rechiffree, false).await?;
        }
    }

    // Emettre un evenement pour confirmer le traitement.
    // Utilise par le CA (confirme que les cles sont dechiffrables) et par le client (batch traitee)
    let routage_event = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_CLE_RECUE_PARTITION).build();
    let event_contenu = json!({
        "correlation": &m.correlation_id,
        "liste_hachage_bytes": liste_hachage_bytes,
    });
    middleware.emettre_evenement(routage_event, &event_contenu).await?;

    Ok(middleware.reponse_ok()?)
}

async fn aiguillage_transaction<M, T>(middleware: &M, transaction: T, gestionnaire: &GestionnaireMaitreDesClesPartition) -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    match transaction.get_action() {
        // TRANSACTION_CLE => transaction_cle(middleware, transaction, gestionnaire).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

async fn requete_dechiffrage<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage + ValidateurX509
{
    debug!("requete_dechiffrage Consommer requete : {:?}", & m.message);
    let requete: RequeteDechiffrage = m.message.get_msg().map_contenu(None)?;
    debug!("requete_dechiffrage cle parsed : {:?}", requete);

    let enveloppe_privee = middleware.get_enveloppe_privee();

    let certificat_requete = m.message.certificat.as_ref();
    let domaines_permis = if let Some(c) = certificat_requete {
        c.get_domaines()?
    } else {
        Err(format!("maitredescles_partition.certificat_requete Erreur chargement enveloppe du message"))?
    };

    // Trouver le certificat de rechiffrage
    let certificat = match requete.certificat_rechiffrage.as_ref() {
        Some(cr) => {
            debug!("Utilisation certificat dans la requete de dechiffrage");
            middleware.charger_enveloppe(cr, None, None).await?
        },
        None => {
            match &m.message.certificat {
                Some(c) => c.clone(),
                None => {
                    debug!("requete_dechiffrage Requete {:?} de dechiffrage {:?} refusee, certificat manquant", m.correlation_id, &requete.liste_hachage_bytes);
                    let refuse = json!({"ok": false, "err": "Autorisation refusee - certificat manquant ou introuvable", "acces": "0.refuse", "code": 0});
                    return Ok(Some(middleware.formatter_reponse(&refuse, None)?))
                }
            }
        }
    };

    if ! certificat.presentement_valide {
        let refuse = json!({"ok": false, "err": "Autorisation refusee - certificat de rechiffrage n'est pas presentement valide", "acces": "0.refuse", "code": 0});
        return Ok(Some(middleware.formatter_reponse(&refuse, None)?))
    }

    // Verifier si on a une autorisation de dechiffrage global
    let (requete_autorisee_globalement, permission) = verifier_autorisation_dechiffrage_global(
        middleware, &m, &requete).await?;

    // Rejeter si global false et permission absente
    if ! requete_autorisee_globalement && permission.is_none() && domaines_permis.is_none() {
        debug!("requete_dechiffrage Requete {:?} de dechiffrage {:?} refusee, permission manquante ou aucuns domaines inclus dans le certificat", m.correlation_id, &requete.liste_hachage_bytes);
        let refuse = json!({"ok": false, "err": "Autorisation refusee - permission manquante", "acces": "0.refuse", "code": 0});
        return Ok(Some(middleware.formatter_reponse(&refuse, None)?))
    }

    // Trouver les cles demandees et rechiffrer
    let mut curseur = preparer_curseur_cles(
        middleware, gestionnaire, &requete, permission.as_ref(), domaines_permis.as_ref()).await?;
    let (cles, cles_trouvees) = rechiffrer_cles(
        middleware, &m, &requete, enveloppe_privee, certificat.as_ref(), requete_autorisee_globalement, permission, &mut curseur).await?;

    // Preparer la reponse
    // Verifier si on a au moins une cle dans la reponse
    let reponse = if cles.len() > 0 {

        // Verifier si on a des cles inconnues
        if cles.len() < requete.liste_hachage_bytes.len() {
            let cles_connues = cles.keys().map(|s|s.to_owned()).collect();
            emettre_cles_inconnues(middleware, requete, cles_connues).await?;
        }

        let reponse = json!({
            "acces": CHAMP_ACCES_PERMIS,
            "code": 1,
            "cles": &cles,
        });
        middleware.formatter_reponse(reponse, None)?
    } else {
        if cles_trouvees {
            // On a trouve des cles mais aucunes n'ont ete rechiffrees (acces refuse)
            debug!("requete_dechiffrage Requete {:?} de dechiffrage {:?} refusee", m.correlation_id, &requete.liste_hachage_bytes);
            let refuse = json!({"ok": false, "err": "Autorisation refusee", "acces": CHAMP_ACCES_REFUSE, "code": 0});
            middleware.formatter_reponse(&refuse, None)?
        } else {
            // On n'a pas trouve de cles
            debug!("requete_dechiffrage Requete {:?} de dechiffrage {:?}, cles inconnues", m.correlation_id, &requete.liste_hachage_bytes);

            // Faire une demande interne de sync pour voir si les cles inconnues existent (async)
            let cles_connues = cles.keys().map(|s|s.to_owned()).collect();
            emettre_cles_inconnues(middleware, requete, cles_connues).await?;

            // Retourner cle inconnu a l'usager
            let inconnu = json!({"ok": false, "err": "Cles inconnues", "acces": CHAMP_ACCES_CLE_INCONNUE, "code": 4});
            middleware.formatter_reponse(&inconnu, None)?
        }
    };

    Ok(Some(reponse))
}

/// Verifie que la requete contient des cles secretes qui correspondent aux cles stockees.
/// Confirme que le demandeur a bien en sa possession (via methode tierce) les cles secretes.
async fn requete_verifier_preuve<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage + ValidateurX509 + Chiffreur<CipherMgs3, Mgs3CipherKeys>
{
    debug!("requete_verifier_preuve Consommer requete : {:?}", & m.message);
    let requete: RequeteVerifierPreuve = m.message.get_msg().map_contenu(None)?;
    debug!("requete_verifier_preuve cle parsed : {:?}", requete);

    // La preuve doit etre recente (moins de 5 minutes)
    {
        let estampille = &m.message.get_entete().estampille;
        let datetime_estampille = estampille.get_datetime();
        let date_expiration = Utc::now() - Duration::minutes(5);
        if datetime_estampille < &date_expiration {
            Err(format!("maitredescles_partition.requete_verifier_preuve Demande preuve est expiree ({:?})", datetime_estampille))?;
        }
    }

    let enveloppe_privee = middleware.get_enveloppe_privee();

    // Preparer une liste de verification pour chaque cle par hachage_bytes
    let mut map_hachage_bytes = HashMap::new();
    for cle in requete.cles.into_iter() {
        map_hachage_bytes.insert(cle.hachage_bytes.clone(), cle);
    }

    let mut liste_hachage_bytes = Vec::new();
    let mut liste_verification = HashMap::new();
    for (hachage_bytes, _) in map_hachage_bytes.iter() {
        let hachage_bytes = hachage_bytes.as_str();
        liste_hachage_bytes.push(hachage_bytes);
        liste_verification.insert(hachage_bytes.to_owned(), None);
    }

    // Trouver les cles en reference
    let filtre = doc! {
        CHAMP_HACHAGE_BYTES: {"$in": liste_hachage_bytes}
    };
    let nom_collection = gestionnaire.get_collection_cles();
    debug!("requete_verifier_preuve Filtre cles sur collection {} : {:?}", nom_collection, filtre);

    let collection = middleware.get_collection(nom_collection.as_str())?;
    let mut curseur = collection.find(filtre, None).await?;

    let cle_privee = enveloppe_privee.cle_privee();
    while let Some(rc) = curseur.next().await {
        let doc_cle = rc?;
        let cle_mongo_chiffree: TransactionCle = match convertir_bson_deserializable::<TransactionCle>(doc_cle) {
            Ok(c) => c,
            Err(e) => {
                error!("requete_verifier_preuve Erreur conversion bson vers TransactionCle : {:?}", e);
                continue
            }
        };
        let cle_mongo_dechiffree = dechiffrer_asymetrique_multibase(cle_privee, cle_mongo_chiffree.cle.as_str())?;
        let hachage_bytes_mongo = cle_mongo_chiffree.hachage_bytes.as_str();
        if let Some(cle_preuve) = map_hachage_bytes.get(hachage_bytes_mongo) {
            match dechiffrer_asymetrique_multibase(cle_privee, cle_preuve.cle.as_str()){
                Ok(cle_preuve_dechiffree) => {
                    if cle_mongo_dechiffree == cle_preuve_dechiffree {
                        // La cle preuve correspond a la cle dans la base de donnees, verification OK
                        liste_verification.insert(hachage_bytes_mongo.into(), Some(true));
                    } else {
                        liste_verification.insert(hachage_bytes_mongo.into(), Some(false));
                    }
                },
                Err(e) => {
                    error!("requete_verifier_preuve Erreur dechiffrage cle {} : {:?}", hachage_bytes_mongo, e);
                    liste_verification.insert(hachage_bytes_mongo.into(), Some(false));
                }
            }
        }
    }

    // Verifier toutes les cles qui n'ont pas ete identifiees dans la base de donnees (inconnues)
    let liste_inconnues: Vec<String> = liste_verification.iter().filter(|(k, v)| match v {
        Some(_) => false,
        None => true
    }).map(|(k,_)| k.to_owned()).collect();
    for hachage_bytes in liste_inconnues.into_iter() {
        if let Some(info_cle) = map_hachage_bytes.remove(&hachage_bytes) {
            debug!("requete_verifier_preuve Conserver nouvelle cle {}", hachage_bytes);
            let commande_cle = rechiffrer_pour_maitredescles(middleware, &info_cle)?;

            // Conserver la cle via commande
            let partition = gestionnaire.fingerprint.as_str();
            let routage = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE)
                .partition(partition)
                .build();
            // Conserver la cle
            // let commande_cle = info_cle.into_commande(partition);
            // Transmettre commande de sauvegarde - on n'attend pas la reponse (deadlock)
            middleware.transmettre_commande(routage, &commande_cle, false).await?;

            // Indiquer que la cle est autorisee (c'est l'usager qui vient de la pousser)
            liste_verification.insert(hachage_bytes, Some(true));
        }
    }

    // Preparer la reponse
    let reponse_json = json!({
        "verification": liste_verification,
    });
    let reponse = middleware.formatter_reponse(reponse_json, None)?;

    Ok(Some(reponse))
}

async fn rechiffrer_cles<M>(
    _middleware: &M,
    _m: &MessageValideAction,
    _requete: &RequeteDechiffrage,
    enveloppe_privee: Arc<EnveloppePrivee>,
    certificat: &EnveloppeCertificat,
    _requete_autorisee_globalement: bool,
    _permission: Option<EnveloppePermission>,
    curseur: &mut Cursor<Document>
)
    -> Result<(HashMap<String, TransactionCle>, bool), Box<dyn Error>>
    where M: VerificateurMessage
{
    let mut cles: HashMap<String, TransactionCle> = HashMap::new();
    let mut cles_trouvees = false;  // Flag pour dire qu'on a matche au moins 1 cle

    while let Some(rc) = curseur.next().await {
        debug!("rechiffrer_cles document {:?}", rc);
        cles_trouvees = true;  // On a trouve au moins une cle
        match rc {
            Ok(doc_cle) => {
                let mut cle: TransactionCle = match convertir_bson_deserializable::<TransactionCle>(doc_cle) {
                    Ok(c) => c,
                    Err(e) => {
                        error!("rechiffrer_cles Erreur conversion bson vers TransactionCle : {:?}", e);
                        continue
                    }
                };
                let hachage_bytes = cle.hachage_bytes.clone();

                match rechiffrer_cle(&mut cle, enveloppe_privee.as_ref(), certificat) {
                    Ok(()) => {
                        cles.insert(hachage_bytes, cle);
                    },
                    Err(e) => {
                        error!("rechiffrer_cles Erreur rechiffrage cle {:?}", e);
                        continue;  // Skip cette cle
                    }
                }
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
    permission: Option<&EnveloppePermission>,
    domaines_permis: Option<&Vec<String>>
)
    -> Result<Cursor<Document>, Box<dyn Error>>
    where M: MongoDao
{
    if permission.is_some() {
        Err(format!("Permission non supporte - FIX ME"))?;
    }

    let mut filtre = doc! {CHAMP_HACHAGE_BYTES: {"$in": &requete.liste_hachage_bytes}};
    if let Some(d) = domaines_permis {
        filtre.insert("domaine", doc!{"$in": d});
    }
    let nom_collection = gestionnaire.get_collection_cles();
    debug!("requete_dechiffrage Filtre cles sur collection {} : {:?}", nom_collection, filtre);

    let collection = middleware.get_collection(nom_collection.as_str())?;
    Ok(collection.find(filtre, None).await?)
}

/// Verifier si la requete de dechiffrage est valide (autorisee) de maniere globale
/// Les certificats 4.secure et delegations globales proprietaire donnent acces a toutes les cles
async fn verifier_autorisation_dechiffrage_global<M>(middleware: &M, m: &MessageValideAction, requete: &RequeteDechiffrage)
    -> Result<(bool, Option<EnveloppePermission>), Box<dyn Error>>
    where M: VerificateurMessage + ValidateurX509
{
    // Verifier si le certificat est une delegation globale
    if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        debug!("verifier_autorisation_dechiffrage Certificat delegation globale proprietaire - toujours autorise");
        return Ok((true, None))
    }

    // Acces global refuse.
    // On verifie la presence et validite d'une permission

    let mut permission: Option<EnveloppePermission> = None;
    if let Some(p) = &requete.permission {
        debug!("verifier_autorisation_dechiffrage_global On a une permission, valider le message {:?}", p);
        let mut ms = match MessageSerialise::from_parsed(p.to_owned()) {
            Ok(ms) => Ok(ms),
            Err(e) => Err(format!("verifier_autorisation_dechiffrage_global Erreur verification permission (2), refuse: {:?}", e))
        }?;

        // Charger le certificat dans ms
        let resultat = ms.valider(middleware, None).await?;
        if ! resultat.valide() {
            Err(format!("verifier_autorisation_dechiffrage_global Erreur verification certificat permission (1), refuse: certificat invalide"))?
        }

        match ms.parsed.map_contenu::<PermissionDechiffrage>(None) {
            Ok(contenu_permission) => {
                // Verifier la date d'expiration de la permission
                let estampille = &ms.get_entete().estampille.get_datetime().timestamp();
                let duree_validite = contenu_permission.permission_duree as i64;
                let ts_courant = Utc::now().timestamp();
                if estampille + duree_validite > ts_courant {
                    debug!("Permission encore valide (duree {}), on va l'utiliser", duree_validite);
                    // Note : conserver permission "localement" pour return false global
                    permission = Some(EnveloppePermission {
                        enveloppe: ms.certificat.clone().expect("cert"),
                        permission: contenu_permission
                    });
                }
            },
            Err(e) => info!("verifier_autorisation_dechiffrage_global Erreur verification permission (1), refuse: {:?}", e)
        }
    }

    match permission {
        Some(p) => {
            // Verifier si le certificat de permission est une delegation globale
            if p.enveloppe.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                debug!("verifier_autorisation_dechiffrage Certificat delegation globale proprietaire - toujours autorise");
                return Ok((true, Some(p)))
            }
            // Utiliser regles de la permission
            Ok((false, Some(p)))
        },
        None => Ok((false, None))
    }

}

/// Rechiffre une cle secrete
fn rechiffrer_cle(cle: &mut TransactionCle, privee: &EnveloppePrivee, certificat_destination: &EnveloppeCertificat)
    -> Result<(), Box<dyn Error>>
{
    let cle_originale = cle.cle.as_str();
    let cle_privee = privee.cle_privee();
    let cle_publique = certificat_destination.certificat().public_key()?;

    let cle_rechiffree = rechiffrer_asymetrique_multibase(
        cle_privee, &cle_publique, cle_originale)?;

    // Remplacer cle dans message reponse
    cle.cle = cle_rechiffree;

    Ok(())
}

/// Genere une commande de sauvegarde de cles pour tous les certificats maitre des cles connus
/// incluant le certificat de millegrille
fn rechiffrer_pour_maitredescles<M>(middleware: &M, cle: &TransactionCle)
    -> Result<CommandeSauvegarderCle, Box<dyn Error>>
    where M: GenerateurMessages + Chiffreur<CipherMgs3, Mgs3CipherKeys>
{
    let enveloppe_privee = middleware.get_enveloppe_privee();
    let fingerprint_local = enveloppe_privee.fingerprint().as_str();
    let pk_chiffrage = middleware.get_publickeys_chiffrage();
    let cle_locale = cle.cle.as_str();
    let cle_privee = enveloppe_privee.cle_privee();

    let mut fingerprint_partitions = Vec::new();
    let mut map_cles = HashMap::new();

    // Inserer la cle locale
    map_cles.insert(fingerprint_local.to_owned(), cle_locale.to_owned());

    for pk_item in pk_chiffrage {
        let fp = pk_item.fingerprint;
        let pk = pk_item.public_key;

        // Conserver liste des partitions
        if ! pk_item.est_cle_millegrille {
            fingerprint_partitions.push(fp.clone());
        }

        // Rechiffrer cle
        if fp.as_str() != fingerprint_local {
            // match chiffrer_asymetrique(&pk, &cle_secrete) {
            match rechiffrer_asymetrique_multibase(cle_privee, &pk, cle_locale) {
                Ok(cle_rechiffree) => {
                    // let cle_mb = multibase::encode(Base::Base64, cle_rechiffree);
                    map_cles.insert(fp, cle_rechiffree);
                },
                Err(e) => error!("Erreur rechiffrage cle : {:?}", e)
            }
        }
    }

    Ok(CommandeSauvegarderCle {
        cles: map_cles,
        domaine: cle.domaine.to_owned(),
        partition: cle.partition.to_owned(),
        format: cle.format.clone(),
        hachage_bytes: cle.hachage_bytes.to_owned(),
        identificateurs_document: cle.identificateurs_document.to_owned(),
        iv: cle.iv.to_owned(),
        tag: cle.tag.to_owned(),
        header: cle.header.to_owned(),
        fingerprint_partitions: Some(fingerprint_partitions)
    })
}

async fn synchroniser_cles<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("synchroniser_cles Debut");
    // Requete vers CA pour obtenir la liste des cles connues
    let mut requete_sync = RequeteSynchroniserCles {page: 0, limite: 1000};
    let routage_sync = RoutageMessageAction::builder(DOMAINE_NOM, REQUETE_SYNCHRONISER_CLES)
        .exchanges(vec![Securite::L4Secure])
        .build();

    let routage_evenement_manquant = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION)
        .exchanges(vec![Securite::L4Secure])
        .build();

    let collection = middleware.get_collection(
        gestionnaire.get_collection_cles().as_str())?;

    loop {
        let reponse = match middleware.transmettre_requete(routage_sync.clone(), &requete_sync).await? {
            TypeMessage::Valide(reponse) => {
                reponse.message.get_msg().map_contenu::<ReponseSynchroniserCles>(None)?
            },
            _ => {
                warn!("synchroniser_cles Mauvais type de reponse recu, on abort");
                break
            }
        };
        requete_sync.page += 1;  // Incrementer page pour prochaine requete

        let liste_hachage_bytes = reponse.liste_hachage_bytes;
        if liste_hachage_bytes.len() == 0 {
            debug!("Traitement sync termine");
            break
        }

        let mut cles_hashset = HashSet::new();
        cles_hashset.extend(&liste_hachage_bytes);

        debug!("Recu liste_hachage_bytes a verifier : {:?}", liste_hachage_bytes);
        let filtre_cles = doc! { CHAMP_HACHAGE_BYTES: {"$in": &liste_hachage_bytes} };
        let projection = doc! { CHAMP_HACHAGE_BYTES: 1 };
        let find_options = FindOptions::builder().projection(projection).build();
        let mut cles = collection.find(filtre_cles, Some(find_options)).await?;
        while let Some(result_cle) = cles.next().await {
            match result_cle {
                Ok(cle) => {
                    match cle.get(CHAMP_HACHAGE_BYTES) {
                        Some(d) => {
                            match d.as_str() {
                                Some(d) => { cles_hashset.remove(&String::from(d)); },
                                None => continue
                            }
                        },
                        None => continue
                    };
                },
                Err(e) => Err(format!("maitredescles_partition.synchroniser_cles Erreur lecture table cles : {:?}", e))?
            }
        }

        if cles_hashset.len() > 0 {
            debug!("Cles absentes localement : {:?}", cles_hashset);
            // Emettre evenement pour indiquer que ces cles sont manquantes dans la partition
            let liste_cles: Vec<String> = cles_hashset.iter().map(|m| String::from(m.as_str())).collect();
            let evenement_cles_manquantes = ReponseSynchroniserCles { liste_hachage_bytes: liste_cles };
            middleware.emettre_evenement(routage_evenement_manquant.clone(), &evenement_cles_manquantes).await?;
        }
    }

    debug!("synchroniser_cles Fin");

    Ok(())
}

/// S'assurer que le CA a toutes les cles de la partition. Permet aussi de resetter le flag non-dechiffrable.
async fn confirmer_cles_ca<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition, reset_flag: Option<bool>) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage + Chiffreur<CipherMgs3, Mgs3CipherKeys>
{
    let batch_size = 50;

    debug!("confirmer_cles_ca Debut confirmation cles locales avec confirmation_ca=false (reset flag: {:?}", reset_flag);
    if let Some(true) = reset_flag {
        info!("Reset flag confirmation_ca a false");
        let filtre = doc! { CHAMP_CONFIRMATION_CA: true };
        let ops = doc! { "$set": {CHAMP_CONFIRMATION_CA: false } };
        let collection = middleware.get_collection(gestionnaire.get_collection_cles().as_str())?;
        collection.update_many(filtre, ops, None).await?;
    }

    let mut curseur = {
        // let limit_cles = 1000000;
        let filtre = doc! { CHAMP_CONFIRMATION_CA: false };
        let opts = FindOptions::builder()
            // .limit(limit_cles)
            .build();
        let collection = middleware.get_collection(gestionnaire.get_collection_cles().as_str())?;
        let curseur = collection.find(filtre, opts).await?;
        curseur
    };

    let mut cles = HashMap::new();
    while let Some(d) = curseur.next().await {
        match d {
            Ok(cle) => {
                let transaction_cle: TransactionCle = convertir_bson_deserializable(cle)?;
                cles.insert(transaction_cle.hachage_bytes.clone(), transaction_cle);

                if cles.len() == batch_size {
                    emettre_cles_vers_ca(middleware, gestionnaire, &mut cles).await?;
                }
            },
            Err(e) => Err(format!("maitredescles_partition.confirmer_cles_ca Erreur traitement {:?}", e))?
        };
    }

    // Derniere batch de cles
    if cles.len() > 0 {
        emettre_cles_vers_ca(middleware, gestionnaire, &mut cles).await?;
    }

    debug!("confirmer_cles_ca Fin confirmation cles locales");

    Ok(())
}

/// Emet un message vers CA pour verifier quels cles sont manquantes (sur le CA)
/// Marque les cles presentes sur la partition et CA comme confirmation_ca=true
/// Rechiffre et emet vers le CA les cles manquantes
async fn emettre_cles_vers_ca<M>(
    middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition, cles: &mut HashMap<String, TransactionCle>)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage + Chiffreur<CipherMgs3, Mgs3CipherKeys>
{
    let hachage_bytes: Vec<String> = cles.keys().into_iter().map(|h| h.to_owned()).collect();
    debug!("emettre_cles_vers_ca Batch {:?} cles", hachage_bytes.len());

    let commande = ReponseSynchroniserCles {liste_hachage_bytes: hachage_bytes.clone()};
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_CONFIRMER_CLES_SUR_CA)
        .exchanges(vec![Securite::L4Secure])
        .build();
    let option_reponse = middleware.transmettre_commande(routage, &commande, true).await?;
    match option_reponse {
        Some(r) => {
            match r {
                TypeMessage::Valide(reponse) => {
                    debug!("emettre_cles_vers_ca Reponse confirmer cle sur CA : {:?}", reponse);
                    let reponse_cles_manquantes: ReponseConfirmerClesSurCa = reponse.message.get_msg().map_contenu(None)?;
                    let cles_manquantes = reponse_cles_manquantes.cles_manquantes;
                    traiter_cles_manquantes_ca(middleware, gestionnaire, &hachage_bytes, &cles_manquantes).await?;
                },
                _ => Err(format!("emettre_cles_vers_ca Recu mauvais type de reponse "))?
            }
        },
        None => info!("emettre_cles_vers_ca Aucune reponse du serveur")
    }

    cles.clear();  // Retirer toutes les cles pour prochaine page

    Ok(())
}

/// Marque les cles emises comme confirmees par le CA sauf si elles sont dans la liste de cles manquantes.
async fn traiter_cles_manquantes_ca<M>(
    middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition, cles_emises: &Vec<String>, cles_manquantes: &Vec<String>
)
    -> Result<(), Box<dyn Error>>
    where M: MongoDao + GenerateurMessages + Chiffreur<CipherMgs3, Mgs3CipherKeys>
{
    let collection = middleware.get_collection(gestionnaire.get_collection_cles().as_str())?;

    // Marquer cles emises comme confirmees par CA si pas dans la liste de manquantes
    {
        let cles_confirmees: Vec<&String> = cles_emises.iter()
            .filter(|c| !cles_manquantes.contains(c))
            .collect();
        debug!("traiter_cles_manquantes_ca Cles confirmees par le CA: {:?}", cles_confirmees);
        let filtre_confirmees = doc! {CHAMP_HACHAGE_BYTES: {"$in": cles_confirmees}};
        let ops = doc! {
            "$set": {CHAMP_CONFIRMATION_CA: true},
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        let resultat_confirmees = collection.update_many(filtre_confirmees, ops, None).await?;
        debug!("traiter_cles_manquantes_ca Resultat maj cles confirmees: {:?}", resultat_confirmees);
    }

    // Rechiffrer et emettre les cles manquantes.
    {
        let routage_commande = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE)
            .exchanges(vec![Securite::L4Secure])
            .build();

        let filtre_manquantes = doc! { CHAMP_HACHAGE_BYTES: {"$in": cles_manquantes} };
        let mut curseur = collection.find(filtre_manquantes, None).await?;
        while let Some(d) = curseur.next().await {
            let commande = match d {
                Ok(cle) => {
                    match convertir_bson_deserializable::<TransactionCle>(cle) {
                        Ok(c) => {
                            match rechiffrer_pour_maitredescles(middleware, &c) {
                                Ok(c) => c,
                                Err(e) => {
                                    error!("traiter_cles_manquantes_ca Erreur traitement rechiffrage cle : {:?}", e);
                                    continue
                                }
                            }
                        },
                        Err(e) => {
                            warn!("traiter_cles_manquantes_ca Erreur conversion document en cle : {:?}", e);
                            continue
                        }
                    }
                },
                Err(e) => Err(format!("maitredescles_partition.traiter_cles_manquantes_ca Erreur lecture curseur : {:?}", e))?
            };

            debug!("Emettre cles rechiffrees pour CA : {:?}", commande);
            middleware.transmettre_commande(routage_commande.clone(), &commande, false).await?;
        }
    }

    Ok(())
}

async fn evenement_cle_manquante<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + Chiffreur<CipherMgs3, Mgs3CipherKeys>
{
    debug!("evenement_cle_manquante Verifier si on peut transmettre la cle manquante {:?}", &m.message);
    let event_non_dechiffrables: ReponseSynchroniserCles = m.message.get_msg().map_contenu(None)?;

    let enveloppe = match m.message.certificat.clone() {
        Some(e) => {
            if e.verifier_roles(vec![RolesCertificats::MaitreDesCles]) {
                e
            } else {
                debug!("evenement_cle_manquante Certificat sans role maitredescles, on rejette la demande");
                return Ok(None)
            }
        },
        None => return Ok(None)  // Type certificat inconnu
    };

    // S'assurer que le certificat de maitre des cles recus est dans la liste de rechiffrage
    middleware.recevoir_certificat_chiffrage(&m.message).await?;

    let partition = enveloppe.fingerprint.as_str();
    let routage_commande = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE)
        .exchanges(vec![Securite::L4Secure])
        .partition(partition)
        .build();

    let hachages_bytes = event_non_dechiffrables.liste_hachage_bytes;
    let filtre = doc! { CHAMP_HACHAGE_BYTES: {"$in": hachages_bytes} };

    let collection = middleware.get_collection(gestionnaire.get_collection_cles().as_str())?;
    let mut curseur = collection.find(filtre, None).await?;

    let mut cles = Vec::new();
    while let Some(d) = curseur.next().await {
        let commande = match d {
            Ok(cle) => {
                match convertir_bson_deserializable::<TransactionCle>(cle) {
                    Ok(c) => {
                        match rechiffrer_pour_maitredescles(middleware, &c) {
                            Ok(c) => c,
                            Err(e) => {
                                error!("traiter_cles_manquantes_ca Erreur traitement rechiffrage cle : {:?}", e);
                                continue
                            }
                        }
                    },
                    Err(e) => {
                        warn!("traiter_cles_manquantes_ca Erreur conversion document en cle : {:?}", e);
                        continue
                    }
                }
            },
            Err(e) => Err(format!("maitredescles_partition.traiter_cles_manquantes_ca Erreur lecture curseur : {:?}", e))?
        };

        if commande.cles.len() > 0 {
            // debug!("evenement_cle_manquante Emettre cles rechiffrees pour partition : {:?}", partition);
            // middleware.transmettre_commande(routage_commande.clone(), &commande, false).await?;
            cles.push(commande);
        } else {
            debug!("evenement_cle_manquante Aucune cle manquante n'est connue localement");
        }
    }

    if cles.len() > 0 {
        let reponse = json!({
            "ok": true,
            "cles": cles,
        });

        debug!("evenement_cle_manquante Emettre reponse : {:?}", reponse);

        Ok(Some(middleware.formatter_reponse(reponse, None)?))
    } else {
        // Si on n'a aucune cle, ne pas repondre. Un autre maitre des cles pourrait le faire
        Ok(None)
    }
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
//     use millegrilles_common_rust::formatteur_messages::{MessageMilleGrille, MessageSerialise};
//     use millegrilles_common_rust::openssl::x509::store::X509Store;
//     use millegrilles_common_rust::openssl::x509::X509;
//     use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
//     use millegrilles_common_rust::recepteur_messages::MessageValideAction;
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
//         fn verifier_message(&self, message: &mut MessageSerialise, options: Option<&ValidationOptions>) -> Result<ResultatValidation, Box<dyn Error>> {
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
//     fn prep_mva<S>(enveloppe_privee: &EnveloppePrivee, contenu_message: &S) -> MessageValideAction
//         where S: Serialize
//     {
//         let message_millegrille = MessageMilleGrille::new_signer(
//             enveloppe_privee, contenu_message, Some("domaine"), Some("action"), None::<&str>, None).expect("mg");
//         let mut message_serialise = MessageSerialise::from_parsed(message_millegrille).expect("ms");
//         message_serialise.certificat = Some(enveloppe_privee.enveloppe.clone());
//         let message_valide_action = MessageValideAction::new(
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
//         // verifier_autorisation_dechiffrage_global<M>(middleware: &M, m: &MessageValideAction, requete: &RequeteDechiffrage)
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
//         // verifier_autorisation_dechiffrage_global<M>(middleware: &M, m: &MessageValideAction, requete: &RequeteDechiffrage)
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
//         let permission = MessageMilleGrille::new_signer(
//             enveloppe_privee.as_ref(), &contenu_permission, Some("domaine"), Some("action"), None::<&str>, None).expect("mg");
//
//         // Stub message requete
//         let requete = RequeteDechiffrage { liste_hachage_bytes: vec!["DUMMY".into()], permission: Some(permission), certificat_rechiffrage: None };
//
//         // Preparer message avec certificat "autre" (qui n'a pas exchange 4.secure)
//         let mut message_valide_action = prep_mva(enveloppe_privee_autre.as_ref(), &requete);
//
//         // verifier_autorisation_dechiffrage_global<M>(middleware: &M, m: &MessageValideAction, requete: &RequeteDechiffrage)
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
//         let permission = MessageMilleGrille::new_signer(
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
//         // verifier_autorisation_dechiffrage_global<M>(middleware: &M, m: &MessageValideAction, requete: &RequeteDechiffrage)
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
//             let message_mg = MessageMilleGrille::new_signer(
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
//             let mva = MessageValideAction::new(
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
