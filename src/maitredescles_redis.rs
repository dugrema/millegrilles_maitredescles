use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::error::Error;
use std::fs::read_dir;
use std::sync::Arc;

use log::{debug, error, info, warn};
use millegrilles_common_rust::{multibase, multibase::Base, serde_json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{EnveloppeCertificat, EnveloppePrivee, ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage::{Chiffreur, ChiffreurMgs3, CommandeSauvegarderCle, dechiffrer_asymetrique_multibase, rechiffrer_asymetrique_multibase};
use millegrilles_common_rust::chiffrage_chacha20poly1305::{CipherMgs3, Mgs3CipherKeys};
use millegrilles_common_rust::chiffrage_ed25519::dechiffrer_asymmetrique_ed25519;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::{FormatteurMessage, MessageMilleGrille, MessageSerialise};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::hachages::hacher_bytes;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, sauvegarder_transaction, sauvegarder_transaction_recue, RedisTrait};
use millegrilles_common_rust::mongo_dao::MongoDao;
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

const NOM_COLLECTION_RECHIFFRAGE: &str = "MaitreDesCles/rechiffrage";

// const NOM_Q_VOLATILS_GLOBAL: &str = "MaitreDesCles/volatils";

const REQUETE_CERTIFICAT_MAITREDESCLES: &str = COMMANDE_CERT_MAITREDESCLES;

const COMMANDE_RECHIFFRER_BATCH: &str = "rechiffrerBatch";

const INDEX_RECHIFFRAGE_PK: &str = "fingerprint_pk";
const INDEX_CONFIRMATION_CA: &str = "confirmation_ca";

const CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";
const CHAMP_CONFIRMATION_CA: &str = "confirmation_ca";

#[derive(Clone, Debug)]
pub struct GestionnaireMaitreDesClesRedis {
    pub fingerprint: String,
}

fn nom_collection_transactions<S>(_fingerprint: S) -> String
    where S: AsRef<str>
{
    panic!("nom_collection_transactions Non supporte")
}

impl GestionnaireMaitreDesClesRedis {
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

    // pub fn get_partition(&self) -> &str {
    //     self.fingerprint.as_str()
    // }

    fn get_q_sauvegarder_cle(&self) -> String {
        format!("MaitreDesCles/{}/sauvegarder", self.fingerprint)
    }

    fn get_collection_cles(&self) -> String {
        format!("MaitreDesCles/{}/cles", self.get_partition_tronquee())
    }

    /// Verifie si le CA a des cles qui ne sont pas connues localement
    pub async fn synchroniser_cles<M>(&self, middleware: &M) -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages + VerificateurMessage + Chiffreur<CipherMgs3, Mgs3CipherKeys> + RedisTrait
    {
        synchroniser_cles(middleware, self).await?;
        Ok(())
    }

    /// S'assure que le CA a toutes les cles presentes dans la partition
    pub async fn confirmer_cles_ca<M>(&self, middleware: &M) -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages +  RedisTrait + VerificateurMessage + Chiffreur<CipherMgs3, Mgs3CipherKeys>
    {
        confirmer_cles_ca(middleware, self).await?;
        Ok(())
    }

    pub async fn emettre_certificat_maitredescles<M>(&self, middleware: &M, m: Option<MessageValideAction>) -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages
    {
        emettre_certificat_maitredescles(middleware, m).await
    }

}

#[async_trait]
impl TraiterTransaction for GestionnaireMaitreDesClesRedis {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages
    {
        aiguillage_transaction(middleware, transaction, self).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireMaitreDesClesRedis {
    fn get_nom_domaine(&self) -> String { String::from(DOMAINE_NOM) }

    fn get_partition(&self) -> Option<String> {
        Some(self.fingerprint.clone())
    }

    fn get_collection_transactions(&self) -> String {
        // Utiliser le nom de la partition tronquee - evite que les noms de collections deviennent
        // trop long (cause un probleme lors de la creation d'index, max 127 chars sur path)
        format!("MaitreDesCles/{}", self.get_partition_tronquee())
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

        for sec in [Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure] {
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

        // Requetes de dechiffrage/preuve re-emise sur le bus 4.secure lorsque la cle est inconnue
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_DECHIFFRAGE), exchange: Securite::L4Secure });
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_VERIFIER_PREUVE), exchange: Securite::L4Secure });

        for sec in [Securite::L3Protege, Securite::L4Secure] {
            rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION), exchange: sec.clone() });
        }

        let commandes_protegees = vec![
            COMMANDE_RECHIFFRER_BATCH,
        ];
        for commande in commandes_protegees {
            rk_volatils.push(ConfigRoutingExchange {
                routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, nom_partition, commande),
                exchange: Securite::L3Protege });
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

        // Queue de transactions
        // queues.push(QueueType::ExchangeQueue(
        //     ConfigQueue {
        //         nom_queue: self.get_q_transactions(),
        //         routing_keys: rk_transactions,
        //         ttl: None,
        //         durable: false,
        //     }
        // ));

        // Queue de triggers
        queues.push(QueueType::Triggers(format!("MaitreDesCles.{}", self.fingerprint), Securite::L3Protege));

        queues
    }

    fn chiffrer_backup(&self) -> bool {
        false
    }

    async fn preparer_index_mongodb_custom<M>(&self, _middleware: &M) -> Result<(), String> where M: MongoDao {
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

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages, T: Transaction {
        aiguillage_transaction(middleware, transaction, self).await
    }
}

pub async fn preparer_index_mongodb_partition<M>(_middleware: &M, _gestionnaire: &GestionnaireMaitreDesClesRedis) -> Result<(), String>
    where M: ValidateurX509
{
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DocumentRechiffrage {
    fingerprint_pk: String,
    fingerprint: String,
    rechiffrage_complete: bool,
    collection_transactions: String,
}
impl DocumentRechiffrage {
    fn new<S, T>(fingerprint_pk: S, fingerprint: T) -> Self where S: Into<String>, T: Into<String> {
        let fp = fingerprint.into();
        DocumentRechiffrage {
            fingerprint_pk: fingerprint_pk.into(),
            fingerprint: fp.clone(),
            rechiffrage_complete: false,
            collection_transactions: nom_collection_transactions(&fp)
        }
    }
}

async fn consommer_requete<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesRedis) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + VerificateurMessage + RedisTrait
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
    where M: GenerateurMessages
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
    where M: GenerateurMessages
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

async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesRedis) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages
{
    debug!("maitredescles_ca.consommer_transaction Consommer transaction : {:?}", &m.message);

    // Autorisation : doit etre de niveau 4.secure
    match m.verifier_exchanges(vec![Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("maitredescles_ca.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    match m.action.as_str() {
        // TRANSACTION_CLE  => {
        //     sauvegarder_transaction_recue(middleware, m, gestionnaire.get_collection_transactions().as_str()).await?;
        //     Ok(None)
        // },
        _ => Err(format!("maitredescles_ca.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesRedis)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + RedisTrait
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

async fn consommer_evenement<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesRedis, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + RedisTrait + Chiffreur<CipherMgs3, Mgs3CipherKeys>
{
    debug!("consommer_evenement Consommer evenement : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("consommer_evenement: Evenement invalide (pas 3.protege ou 4.secure)")),
    }?;

    match m.action.as_str() {
        EVENEMENT_CLES_MANQUANTES_PARTITION => evenement_cle_manquante(middleware, gestionnaire, &m).await,
        _ => Err(format!("consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn commande_sauvegarder_cle<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesRedis)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + RedisTrait,
{
    debug!("commande_sauvegarder_cle Consommer commande : {:?}", & m.message);
    let commande: CommandeSauvegarderCle = m.message.get_msg().map_contenu(None)?;
    debug!("Commande sauvegarder cle parsed : {:?}", commande);

    let fingerprint = gestionnaire.fingerprint.as_str();

    let cle = match commande.cles.get(fingerprint) {
        Some(cle) => cle.as_str(),
        None => {
            let message = format!("maitredescles_ca.commande_sauvegarder_cle: Erreur validation - commande sauvegarder cles ne contient pas la cle locale ({}) : {:?}", fingerprint, commande);
            warn!("{}", message);
            let reponse_err = json!({"ok": false, "err": message});
            return Ok(Some(middleware.formatter_reponse(&reponse_err, None)?));
        }
    };

    // Sauvegarde cle dans redis
    let cle_redis = format!("{}.{}", middleware.get_enveloppe_privee().fingerprint(), commande.hachage_bytes);
    let doc_redis = json!({
        "cle": cle,
        "hachage_bytes": &commande.hachage_bytes,
        "domaine": &commande.domaine,
        "format": &commande.format,
        "identificateurs_document": &commande.identificateurs_document,
        "iv": &commande.iv,
        "tag": &commande.tag,
        // "confirmation_ca": false,
        // "dirty": false,
    });
    debug!("Conserver cle dans redis : {}", cle_redis);
    let redis_dao = middleware.get_redis();
    let enveloppe_privee = middleware.get_enveloppe_privee();
    let hachage_bytes = commande.hachage_bytes.as_str();
    redis_dao.save_cle_maitredescles(enveloppe_privee.as_ref(), hachage_bytes, &doc_redis).await?;

    Ok(middleware.reponse_ok()?)
}

async fn commande_rechiffrer_batch<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesRedis)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages
{
    debug!("commande_rechiffrer_batch Consommer commande : {:?}", & m.message);
    let commande: CommandeRechiffrerBatch = m.message.get_msg().map_contenu(None)?;
    debug!("commande_rechiffrer_batch Commande parsed : {:?}", commande);

    todo!("Fix me")

    // let fingerprint = gestionnaire.fingerprint.as_str();
    //
    // let collection = middleware.get_collection(gestionnaire.get_collection_cles().as_str())?;
    //
    // // Traiter chaque cle individuellement
    // let liste_hachage_bytes: Vec<String> = commande.cles.iter().map(|c| c.hachage_bytes.to_owned()).collect();
    // for cle in commande.cles {
    //     let mut doc_cle = convertir_to_bson(cle.clone())?;
    //     doc_cle.insert("dirty", true);
    //     doc_cle.insert("confirmation_ca", false);
    //     doc_cle.insert(CHAMP_CREATION, Utc::now());
    //     doc_cle.insert(CHAMP_MODIFICATION, Utc::now());
    //     let filtre = doc! { "hachage_bytes": cle.hachage_bytes.as_str() };
    //     let ops = doc! { "$setOnInsert": doc_cle };
    //     let opts = UpdateOptions::builder().upsert(true).build();
    //     let resultat = collection.update_one(filtre, ops, opts).await?;
    //
    //     if let Some(uid) = resultat.upserted_id {
    //         debug!("commande_rechiffrer_batch Nouvelle cle insere _id: {}, generer transaction", uid);
    //         let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_CLE)
    //             .partition(fingerprint)
    //             .exchanges(vec![Securite::L4Secure])
    //             .build();
    //         middleware.soumettre_transaction(routage, &cle, false).await?;
    //     }
    //
    // }
    //
    // // Emettre un evenement pour confirmer le traitement.
    // // Utilise par le CA (confirme que les cles sont dechiffrables) et par le client (batch traitee)
    // let routage_event = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_CLE_RECUE_PARTITION).build();
    // let event_contenu = json!({
    //     "correlation": &m.correlation_id,
    //     "liste_hachage_bytes": liste_hachage_bytes,
    // });
    // middleware.emettre_evenement(routage_event, &event_contenu).await?;
    //
    // Ok(middleware.reponse_ok()?)
}

async fn aiguillage_transaction<M, T>(_middleware: &M, transaction: T, _gestionnaire: &GestionnaireMaitreDesClesRedis) -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages,
        T: Transaction
{
    match transaction.get_action() {
        // TRANSACTION_CLE => transaction_cle(middleware, transaction, gestionnaire).await,
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

async fn requete_dechiffrage<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesRedis)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + RedisTrait + VerificateurMessage + ValidateurX509
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
    let cles = get_cles_redis_rechiffrees(
        middleware, &requete, enveloppe_privee, certificat.as_ref(),
        permission.as_ref(), domaines_permis.as_ref()).await?;

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
            "cles": cles,
        });
        middleware.formatter_reponse(reponse, None)?
    } else {
        if cles.len() > 0 {
            // On a trouve des cles mais aucunes n'ont ete rechiffrees (acces refuse)
            debug!("requete_dechiffrage Requete {:?} de dechiffrage {:?} refusee", m.correlation_id, &requete.liste_hachage_bytes);
            let refuse = json!({"ok": false, "err": "Autorisation refusee", "acces": CHAMP_ACCES_REFUSE, "code": 0});
            middleware.formatter_reponse(&refuse, None)?
        } else {
            // On n'a pas trouve de cles
            debug!("requete_dechiffrage Requete {:?} de dechiffrage {:?}, cles inconnues", m.correlation_id, &requete.liste_hachage_bytes);

            let cles_connues = cles.keys().map(|s|s.to_owned()).collect();
            emettre_cles_inconnues(middleware, requete, cles_connues).await?;

            let inconnu = json!({"ok": false, "err": "Cles inconnues", "acces": CHAMP_ACCES_CLE_INCONNUE, "code": 4});
            middleware.formatter_reponse(&inconnu, None)?
        }
    };

    Ok(Some(reponse))
}

/// Verifie que la requete contient des cles secretes qui correspondent aux cles stockees.
/// Confirme que le demandeur a bien en sa possession (via methode tierce) les cles secretes.
async fn requete_verifier_preuve<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireMaitreDesClesRedis)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + VerificateurMessage + ValidateurX509
{
    debug!("requete_verifier_preuve Consommer requete : {:?}", & m.message);
    let requete: RequeteVerifierPreuve = m.message.get_msg().map_contenu(None)?;
    debug!("requete_verifier_preuve cle parsed : {:?}", requete);

    todo!("requete_verifier_preuve Fix me")
    //
    // let domaines = match m.message.certificat.as_ref() {
    //     Some(c) => {
    //         match c.get_domaines()? {
    //             Some(d) => Ok(d.to_owned()),
    //             None => Err(format!("maitredescles_partition.requete_verifier_preuve Aucuns domaines dans certificat demandeur"))
    //         }
    //     },
    //     None => Err(format!("maitredescles_partition.requete_verifier_preuve Erreur chargement certificat"))
    // }?;
    //
    // let enveloppe_privee = middleware.get_enveloppe_privee();
    //
    // let liste_hachage_bytes: Vec<&str> = requete.cles.keys().map(|k| k.as_str()).collect();
    // let mut liste_verification: HashMap<String, bool> = HashMap::new();
    // for hachage in &liste_hachage_bytes {
    //     liste_verification.insert(hachage.to_string(), false);
    // }
    //
    // // Trouver les cles en reference
    // let mut filtre = doc! {
    //     CHAMP_HACHAGE_BYTES: {"$in": &liste_hachage_bytes},
    //     TRANSACTION_CHAMP_DOMAINE: {"$in": &domaines}
    // };
    // let nom_collection = gestionnaire.get_collection_cles();
    // debug!("requete_dechiffrage Filtre cles sur collection {} : {:?}", nom_collection, filtre);
    //
    // let collection = middleware.get_collection(nom_collection.as_str())?;
    // let mut curseur = collection.find(filtre, None).await?;
    //
    // let cle_privee = enveloppe_privee.cle_privee();
    // while let Some(rc) = curseur.next().await {
    //     let doc_cle = rc?;
    //     let mut cle_mongo_chiffree: TransactionCle = match convertir_bson_deserializable::<TransactionCle>(doc_cle) {
    //         Ok(c) => c,
    //         Err(e) => {
    //             error!("requete_verifier_preuve Erreur conversion bson vers TransactionCle : {:?}", e);
    //             continue
    //         }
    //     };
    //     let cle_mongo_dechiffree = dechiffrer_asymetrique_multibase(cle_privee, cle_mongo_chiffree.cle.as_str())?;
    //     let hachage_bytes = cle_mongo_chiffree.hachage_bytes.as_str();
    //     if let Some(cle_preuve) = requete.cles.get(hachage_bytes) {
    //         let cle_preuve_dechiffree = dechiffrer_asymetrique_multibase(cle_privee, cle_preuve.as_str())?;
    //         if cle_mongo_dechiffree == cle_preuve_dechiffree {
    //             // La cle preuve correspond a la cle dans la base de donnees, verification OK
    //             liste_verification.insert(hachage_bytes.into(), true);
    //         }
    //     }
    // }
    //
    // // Preparer la reponse
    // let reponse_json = json!({
    //     "verification": liste_verification,
    // });
    // let reponse = middleware.formatter_reponse(reponse_json, None)?;
    //
    // Ok(Some(reponse))
}

async fn get_cles_redis_rechiffrees<M>(
    middleware: &M,
    requete: &RequeteDechiffrage,
    enveloppe_privee: Arc<EnveloppePrivee>,
    certificat: &EnveloppeCertificat,
    permission: Option<&EnveloppePermission>,
    domaines_permis: Option<&Vec<String>>
)
    -> Result<HashMap<String, TransactionCle>, Box<dyn Error>>
    where M: RedisTrait + VerificateurMessage + FormatteurMessage
{
    let mut cles: HashMap<String, TransactionCle> = HashMap::new();

    let redis_dao = middleware.get_redis();
    let enveloppe_privee = middleware.get_enveloppe_privee();
    let fingerprint = enveloppe_privee.fingerprint().as_str();

    for hachage_bytes in &requete.liste_hachage_bytes {
        match redis_dao.get_cle(fingerprint, hachage_bytes).await? {
            Some(info_cle_str) => {
                // Cle trouvee
                let mut cle_transaction: TransactionCle = serde_json::from_str(info_cle_str.as_str())?;

                // Verifier autorisation du domaine
                match domaines_permis {
                    Some(domaines) => {
                        let domaine_cle = &cle_transaction.domaine;
                        if domaines.contains(domaine_cle) == false {
                            debug!("Demande de rechiffrage de {} refusee, certificat ne supporte pas domaine {}", hachage_bytes, domaine_cle);
                            continue
                        }
                    },
                    None => ()
                }

                // Rechiffrer
                rechiffrer_cle(&mut cle_transaction, enveloppe_privee.as_ref(), certificat)?;

                cles.insert(hachage_bytes.clone(), cle_transaction);
            },
            None => continue  // Pas trouve, skip
        }
    }

    debug!("Cles rechiffrees : {:?}", cles);

    Ok(cles)
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
            Ok(mut ms) => Ok(ms),
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteVerifierPreuve {
    cles: HashMap<String, String>,
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

    // Dechiffrer la cle secrete
    debug!("rechiffrer_pour_maitredescles Cle rechiffrage : {:?}", pk_chiffrage);

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
        fingerprint_partitions: Some(fingerprint_partitions)
    })
}

fn verifier_autorisation_dechiffrage_specifique(
    certificat_destination: &EnveloppeCertificat, permission: Option<&EnveloppePermission>, cle: &TransactionCle)
    -> Result<bool, Box<dyn Error>>
{
    let domaine_cle = &cle.domaine;

    // Verifier si le certificat est une delegation pour le domaine
    if let Some(d) = certificat_destination.get_delegation_domaines()? {
        if d.contains(domaine_cle) {
            return Ok(true)
        }
    }

    if let Some(p) = permission {
        // S'assurer que le hachage_bytes est inclus dans la permission
        let regles_permission = &p.permission;

        let hachage_bytes_permis = &regles_permission.permission_hachage_bytes;
        let hachage_bytes_demande = &cle.hachage_bytes;
        if ! hachage_bytes_permis.contains(hachage_bytes_demande) {
            debug!("verifier_autorisation_dechiffrage_specifique Hachage_bytes {} n'est pas inclus dans la permission", hachage_bytes_demande);
            return Ok(false)
        }

        let enveloppe_permission = p.enveloppe.as_ref();
        if enveloppe_permission.verifier_exchanges(vec![Securite::L4Secure]) {
            // Permission signee par un certificat 4.secure - autorisation globale

            // On verifie si le certificat correspond a un des criteres mis dans la permission
            if let Some(user_id) = &regles_permission.user_id {
                match certificat_destination.get_user_id()? {
                    Some(u) => {
                        if u != user_id {
                            debug!("verifier_autorisation_dechiffrage_specifique Mauvais user id {}", u);
                            return Ok(false)
                        }
                    },
                    None => return {
                        debug!("verifier_autorisation_dechiffrage_specifique Certificat sans user_id (requis = {:?}), acces refuse", user_id);
                        Ok(false)
                    }
                }
            }

            if let Some(domaine) = &regles_permission.domaines_permis {
                let domaine_cle = &cle.domaine;
                if ! domaine.contains(domaine_cle) {
                    debug!("verifier_autorisation_dechiffrage_specifique Cle n'est pas d'un domaine permis {}", domaine_cle);
                    return Ok(false)
                }
            }

            // Aucune regle n'as ete rejetee, acces permis
            return Ok(true)
        }
    }

    // Reponse par defaut - acces refuse
    Ok(false)
}

async fn synchroniser_cles<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesRedis) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + VerificateurMessage + RedisTrait
{
    // Requete vers CA pour obtenir la liste des cles connues
    let mut requete_sync = RequeteSynchroniserCles {page: 0, limite: 1000};
    let routage_sync = RoutageMessageAction::builder(DOMAINE_NOM, REQUETE_SYNCHRONISER_CLES)
        .exchanges(vec![Securite::L4Secure])
        .build();

    let routage_evenement_manquant = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION)
        .exchanges(vec![Securite::L4Secure])
        .build();

    let enveloppe_privee = middleware.get_enveloppe_privee();
    let fingerprint = enveloppe_privee.fingerprint().as_str();
    let redis_dao = middleware.get_redis();

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

        let mut cles_manquantes = HashSet::new();
        debug!("Recu liste_hachage_bytes a verifier : {:?}", liste_hachage_bytes);

        for hachage_bytes in liste_hachage_bytes.into_iter() {
            match redis_dao.get_cle(fingerprint, &hachage_bytes).await? {
                Some(c) => (),
                None => {
                    cles_manquantes.insert(hachage_bytes);
                }
            }
        }

        for cle_manquante in &cles_manquantes {
            redis_dao.ajouter_cle_manquante(enveloppe_privee.as_ref(), cle_manquante).await?;
        }

        if cles_manquantes.len() > 0 {
            let liste_cles: Vec<String> = cles_manquantes.iter().map(|m| String::from(m.as_str())).collect();
            let evenement_cles_manquantes = ReponseSynchroniserCles { liste_hachage_bytes: liste_cles };
            middleware.emettre_evenement(routage_evenement_manquant.clone(), &evenement_cles_manquantes).await?;
        }

    }

    Ok(())
}

/// S'assurer que le CA a toutes les cles de la partition. Permet aussi de resetter le flag non-dechiffrable.
async fn confirmer_cles_ca<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesRedis) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + RedisTrait + VerificateurMessage + Chiffreur<CipherMgs3, Mgs3CipherKeys>
{
    let batch_size = 50;

    debug!("confirmer_cles_ca Debut confirmation cles locales avec confirmation_ca=false");

    let limit_cles = 5000;

    // let mut curseur = {
    //     let limit_cles = 5000;
    //     let filtre = doc! { CHAMP_CONFIRMATION_CA: false };
    //     let opts = FindOptions::builder().limit(limit_cles).build();
    //     let collection = middleware.get_collection(gestionnaire.get_collection_cles().as_str())?;
    //     let curseur = collection.find(filtre, opts).await?;
    //     curseur
    // };
    let enveloppe_privee = middleware.get_enveloppe_privee();
    let fingerprint = enveloppe_privee.fingerprint().as_str();

    let redis_dao = middleware.get_redis();
    let cles_ca = redis_dao.get_cleversca_batch(fingerprint, Some(limit_cles)).await?;
    debug!("confirmer_cles_ca Batch cle a confirmer avec CA : {:?}", cles_ca);
    if cles_ca.len() == 0 {
        debug!("confirmer_cles_ca Aucune cle a transmettre vers CA");
        return Ok(())
    }

    let mut cles = Vec::new();

    // Traiter cles en batch
    for hachage_bytes in cles_ca {
        cles.push(hachage_bytes);
        if cles.len() == batch_size {
            emettre_cles_vers_ca(middleware, gestionnaire, &mut cles).await?;
            cles.clear();
        }
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
    middleware: &M, gestionnaire: &GestionnaireMaitreDesClesRedis, hachage_bytes: &mut Vec<String>)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + RedisTrait + VerificateurMessage + Chiffreur<CipherMgs3, Mgs3CipherKeys>
{
    // let hachage_bytes: Vec<String> = cles.keys().into_iter().map(|h| h.to_owned()).collect();
    debug!("emettre_cles_vers_ca Batch cles {:?}", hachage_bytes);

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

    Ok(())
}

/// Marque les cles emises comme confirmees par le CA sauf si elles sont dans la liste de cles manquantes.
async fn traiter_cles_manquantes_ca<M>(
    middleware: &M, gestionnaire: &GestionnaireMaitreDesClesRedis, cles_emises: &Vec<String>, cles_manquantes: &Vec<String>
)
    -> Result<(), Box<dyn Error>>
    where M: RedisTrait + GenerateurMessages + Chiffreur<CipherMgs3, Mgs3CipherKeys>
{
    let enveloppe_privee = middleware.get_enveloppe_privee();
    let fingerprint = enveloppe_privee.fingerprint().as_str();

    // Marquer cles emises comme confirmees par CA si pas dans la liste de manquantes
    let redis_dao = middleware.get_redis();
    {
        let cles_confirmees: Vec<&String> = cles_emises.iter()
            .filter(|c| !cles_manquantes.contains(c))
            .collect();
        debug!("traiter_cles_manquantes_ca Cles confirmees par le CA: {:?}", cles_confirmees);
        for hachage_bytes in cles_confirmees {
            redis_dao.retirer_cleca_manquante(fingerprint, hachage_bytes).await?;
        }
    }

    // Rechiffrer et emettre les cles manquantes.
    {
        let routage_commande = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE)
            .exchanges(vec![Securite::L4Secure])
            .build();

        for hachage_bytes in cles_manquantes {
            let cle_str = match redis_dao.get_cle(fingerprint, hachage_bytes).await {
                Ok(c) => match c {
                    Some(c)=> c,
                    None => {
                        debug!("cle manquante n'est pas presente localement : {}", hachage_bytes);
                        continue
                    }
                },
                Err(e) => {
                    error!("Erreur chargement cle manquant localement {} : {:?}", hachage_bytes, e);
                    continue
                }
            };

            let commande = match serde_json::from_str::<TransactionCle>(cle_str.as_str()) {
                Ok(cle) => {
                    match rechiffrer_pour_maitredescles(middleware, &cle) {
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
            };

            debug!("Emettre cles rechiffrees pour CA : {:?}", commande);
            middleware.transmettre_commande(routage_commande.clone(), &commande, false).await?;
        }
    }

    Ok(())
}

async fn evenement_cle_manquante<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesRedis, m: &MessageValideAction)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + RedisTrait + Chiffreur<CipherMgs3, Mgs3CipherKeys>,
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

    let partition = enveloppe.fingerprint.as_str();
    let routage_commande = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE)
        .exchanges(vec![Securite::L4Secure])
        .partition(partition)
        .build();

    let hachages_bytes_list = event_non_dechiffrables.liste_hachage_bytes;

    let enveloppe_privee = middleware.get_enveloppe_privee();
    let fingerprint = enveloppe_privee.fingerprint().as_str();
    let redis_dao = middleware.get_redis();
    for hachage_bytes in hachages_bytes_list {
        let cle_str = match redis_dao.get_cle(fingerprint, &hachage_bytes).await {
            Ok(c) => match c {
                Some(c)=> c,
                None => {
                    debug!("cle manquante n'est pas presente localement : {}", hachage_bytes);
                    continue
                }
            },
            Err(e) => {
                error!("Erreur chargement cle manquant localement {} : {:?}", hachage_bytes, e);
                continue
            }
        };

        let commande = match serde_json::from_str::<TransactionCle>(cle_str.as_str()) {
            Ok(cle) => {
                match rechiffrer_pour_maitredescles(middleware, &cle) {
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
        };

        debug!("Emettre cles rechiffrees pour CA : {:?}", commande);
        middleware.transmettre_commande(routage_commande.clone(), &commande, false).await?;
    }

    Ok(None)
}
