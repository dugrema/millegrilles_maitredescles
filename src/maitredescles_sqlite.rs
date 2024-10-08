use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::fs::read_dir;
use std::sync::{Arc, Mutex};

use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::{get_domaine_action, multibase, multibase::Base, redis, serde_json};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::common_messages::RequeteDechiffrage;
use millegrilles_common_rust::chiffrage_cle::{CleChiffrageCache, CommandeSauvegarderCle};
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::configuration::{ConfigMessages, IsConfigNoeud};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::FormatteurMessage;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::hachages::hacher_bytes;
use millegrilles_common_rust::messages_generiques::{CommandeCleRechiffree, CommandeDechiffrerCle, MessageCedule};
use millegrilles_common_rust::middleware::{sauvegarder_transaction, Middleware};
use millegrilles_common_rust::middleware_db::MiddlewareDb;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::FormatChiffrage;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::millegrilles_cryptographie::x509::{EnveloppeCertificat, EnveloppePrivee};
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::multihash::Code;
use millegrilles_common_rust::openssl::pkey::{PKey, Private};
use millegrilles_common_rust::openssl::rsa::Rsa;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, NamedQueue, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio::fs::File as File_tokio;
use millegrilles_common_rust::tokio::io::AsyncReadExt;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::sync::mpsc;
use millegrilles_common_rust::tokio::time::sleep;
use millegrilles_common_rust::tokio::time::Duration as Duration_tokio;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{marquer_transaction, EtatTransaction, TraiterTransaction, Transaction};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::millegrilles_cryptographie::x25519::{chiffrer_asymmetrique_ed25519, dechiffrer_asymmetrique_ed25519};

use sqlite::{Connection, State};
use crate::maitredescles_commun::*;
use crate::constants::*;
use crate::maitredescles_rechiffrage::{CleInterneChiffree, HandlerCleRechiffrage};
// use crate::maitredescles_volatil::{CleInterneChiffree, HandlerCleRechiffrage};
use crate::messages::{MessageReponseChiffree, RequeteVerifierPreuve};
use crate::tokio;

// const NOM_COLLECTION_RECHIFFRAGE: &str = "MaitreDesCles/rechiffrage";
//
// // const NOM_Q_VOLATILS_GLOBAL: &str = "MaitreDesCles/volatils";
//
// const REQUETE_CERTIFICAT_MAITREDESCLES: &str = COMMANDE_CERT_MAITREDESCLES;
//
// const COMMANDE_RECHIFFRER_BATCH: &str = "rechiffrerBatch";
//
// const INDEX_RECHIFFRAGE_PK: &str = "fingerprint_pk";
// const INDEX_CONFIRMATION_CA: &str = "confirmation_ca";
//
// const CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";
// const CHAMP_CONFIRMATION_CA: &str = "confirmation_ca";


#[derive(Debug)]
pub enum ErreurMaitreDesClesSqlite {
    CommonError(Error),
    SqliteError(sqlite::Error)
}

impl fmt::Display for ErreurMaitreDesClesSqlite {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ErreurMaitreDesClesSqlite {
}

impl Into<Error> for ErreurMaitreDesClesSqlite {
    fn into(self) -> Error {
        match self {
            ErreurMaitreDesClesSqlite::CommonError(e) => e,
            ErreurMaitreDesClesSqlite::SqliteError(e) => {
                Error::String(format!("SQLiteError : {:?}", e))
            }
        }
    }
}

impl From<sqlite::Error> for ErreurMaitreDesClesSqlite {
    fn from(value: sqlite::Error) -> Self {
        ErreurMaitreDesClesSqlite::SqliteError(value)
    }
}

impl From<Error> for ErreurMaitreDesClesSqlite {
    fn from(value: Error) -> Self {
        ErreurMaitreDesClesSqlite::CommonError(value)
    }
}

impl From<millegrilles_common_rust::millegrilles_cryptographie::error::Error> for ErreurMaitreDesClesSqlite {
    fn from(value: millegrilles_common_rust::millegrilles_cryptographie::error::Error) -> Self {
        ErreurMaitreDesClesSqlite::CommonError(value.into())
    }
}

impl From<String> for ErreurMaitreDesClesSqlite {
    fn from(value: String) -> Self {
        ErreurMaitreDesClesSqlite::CommonError(Error::String(value))
    }
}

impl From<&str> for ErreurMaitreDesClesSqlite {
    fn from(value: &str) -> Self {
        ErreurMaitreDesClesSqlite::CommonError(Error::String(value.to_string()))
    }
}

impl From<serde_json::Error> for ErreurMaitreDesClesSqlite {
    fn from(value: serde_json::Error) -> Self {
        ErreurMaitreDesClesSqlite::CommonError(Error::SerdeJson(value))
    }
}

impl From<multibase::Error> for ErreurMaitreDesClesSqlite {
    fn from(value: multibase::Error) -> Self {
        ErreurMaitreDesClesSqlite::CommonError(Error::Multibase(value))
    }
}

impl From<millegrilles_common_rust::openssl::error::ErrorStack> for ErreurMaitreDesClesSqlite {
    fn from(value: millegrilles_common_rust::openssl::error::ErrorStack) -> Self {
        ErreurMaitreDesClesSqlite::CommonError(Error::Openssl(value))
    }
}


pub struct GestionnaireMaitreDesClesSQLite {
    // pub fingerprint: String,
    pub handler_rechiffrage: HandlerCleRechiffrage,
    connexion_read_only: Mutex<Option<Connection>>,
    connexion_sauvegarder_cle: Mutex<Option<Connection>>,
}

impl Clone for GestionnaireMaitreDesClesSQLite {
    fn clone(&self) -> Self {
        GestionnaireMaitreDesClesSQLite {
            // fingerprint: self.fingerprint.clone(),
            handler_rechiffrage: self.handler_rechiffrage.clone(),
            connexion_read_only: Mutex::new(None),
            connexion_sauvegarder_cle: Mutex::new(None),
        }
    }
}

impl Debug for GestionnaireMaitreDesClesSQLite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let fingerprint = match self.handler_rechiffrage.fingerprint() {
            Ok(inner) => inner,
            Err(_) => Err(std::fmt::Error)?
        };
        f.write_str(format!("GestionnaireMaitreDesClesSQLite fingerprint {}", fingerprint).as_str())
    }
}

fn nom_collection_transactions<S>(_fingerprint: S) -> String
    where S: AsRef<str>
{
    panic!("nom_collection_transactions Non supporte")
}

impl GestionnaireMaitreDesClesSQLite {
    pub fn new(handler_rechiffrage: HandlerCleRechiffrage) -> Self {
        Self {
            handler_rechiffrage,
            connexion_read_only: Mutex::new(None),
            connexion_sauvegarder_cle: Mutex::new(None),
        }
    }

    fn ouvrir_connection<M>(&self, middleware: &M, read_only: bool) -> Connection where M: IsConfigNoeud {
        let fingerprint = self.handler_rechiffrage.fingerprint();

        let sqlite_path = middleware.get_configuration_noeud().sqlite_path.as_ref().expect("preparer_database sqlite");
        let db_path = format!("{}/maitredescles.sqlite", sqlite_path);
        info!("Ouverture fichier sqlite : {}", db_path);
        if read_only {
            let flags = sqlite::OpenFlags::new().set_read_only();
            Connection::open_with_flags(db_path, flags).expect("preparer_database open sqlite")
        } else {
            sqlite::open(db_path).expect("preparer_database open sqlite")
        }
    }

    fn ouvrir_connection_readonly<M>(&self, middleware: &M) -> &Mutex<Option<Connection>> where M: IsConfigNoeud {
        let mut guard = self.connexion_read_only.lock().expect("ouvrir_connection_readonly lock");

        if guard.is_none() {
            let connexion = self.ouvrir_connection(middleware, true);
            *guard = Some(connexion);
        }

        &self.connexion_read_only
    }

    fn ouvrir_connection_sauvegardercle<M>(&self, middleware: &M) -> &Mutex<Option<Connection>> where M: IsConfigNoeud {
        let mut guard = self.connexion_sauvegarder_cle.lock().expect("ouvrir_connection_sauvegardercle lock");

        if guard.is_none() {
            let connexion = self.ouvrir_connection(middleware, false);
            *guard = Some(connexion);
        }

        &self.connexion_sauvegarder_cle
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

    fn get_collection_cles(&self) -> Option<String> {
        None  // Aucune collection MongoDB (SQLite fonctionne avec des tables)
    }

    /// Verifie si le CA a des cles qui ne sont pas connues localement
    pub async fn synchroniser_cles<M>(&self, middleware: &M) -> Result<(), ErreurMaitreDesClesSqlite>
        where M: GenerateurMessages + CleChiffrageHandler + IsConfigNoeud
    {
        synchroniser_cles(middleware, self).await?;
        Ok(())
    }

    /// S'assure que le CA a toutes les cles presentes dans la partition
    pub async fn confirmer_cles_ca<M>(&'static self, middleware: Arc<M>, reset_flag: Option<bool>) -> Result<(), ErreurMaitreDesClesSqlite>
        where M: Middleware + 'static
    {
        confirmer_cles_ca(middleware, self, reset_flag).await?;
        Ok(())
    }

    pub async fn emettre_certificat_maitredescles<M>(&self, middleware: &M, m: Option<MessageValide>) -> Result<(), Error>
        where M: GenerateurMessages
    {
        emettre_certificat_maitredescles(middleware, m).await
    }

}

#[async_trait]
impl TraiterTransaction for GestionnaireMaitreDesClesSQLite {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: ValidateurX509 + GenerateurMessages
    {
        aiguillage_transaction(middleware, transaction, self).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireMaitreDesClesSQLite {
    fn get_nom_domaine(&self) -> String { String::from(DOMAINE_NOM) }

    fn get_partition(&self) -> Result<Option<String>, Error> {
        Ok(Some(self.handler_rechiffrage.fingerprint()?))
    }

    fn get_collection_transactions(&self) -> Option<String> {
        None  // Aucune collection MongoDB
    }

    fn get_collections_documents(&self) -> Result<Vec<String>, Error> {
        Ok(vec![])  // Aucune collection MongoDB
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

        // Aucunes Q a l'initialisation, ajoutees

        Ok(queues)
    }

    fn chiffrer_backup(&self) -> bool {
        false
    }

    async fn preparer_database<M>(&self, middleware: &M) -> Result<(), Error> where M: Middleware + 'static {
        // Preparer la base de donnees sqlite
        let connection = self.ouvrir_connection(middleware, false);
        connection.execute(
                "
                CREATE TABLE IF NOT EXISTS configuration (
                    type_cle TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    cle TEXT NOT NULL,
                    nonce TEXT,
                    CONSTRAINT configuration_pk PRIMARY KEY (type_cle, fingerprint, instance_id)
                    );

                CREATE TABLE IF NOT EXISTS cles (
                    cle_ref TEXT PRIMARY KEY NOT NULL,
                    hachage_bytes TEXT,
                    cle TEXT NOT NULL,
                    iv TEXT,
                    tag TEXT,
                    header TEXT,
                    cle_symmetrique TEXT NOT NULL,
                    nonce_symmetrique TEXT NOT NULL,
                    format TEXT NOT NULL,
                    domaine TEXT NOT NULL,
                    confirmation_ca INT NOT NULL,
                    signature_identite TEXT NOT NULL
                    );

                CREATE INDEX IF NOT EXISTS index_hachage_domaines ON cles (hachage_bytes, domaine);

                CREATE TABLE IF NOT EXISTS identificateurs_document (
                    cle_ref TEXT NOT NULL,
                    cle TEXT NOT NULL,
                    valeur TEXT NOT NULL,
                    CONSTRAINT identificateurs_document_pk PRIMARY KEY (cle_ref, cle),
                    CONSTRAINT cles_fk FOREIGN KEY (cle_ref) REFERENCES cles (cle_ref) ON DELETE CASCADE
                );
                ",
            ).expect("execute creer table");

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
        entretien(self, middleware).await
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule) -> Result<(), Error> where M: Middleware + 'static {
        traiter_cedule(middleware, trigger).await
    }

    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: ValidateurX509 + GenerateurMessages
    {
        aiguillage_transaction(middleware, transaction, self).await
    }
}

impl GestionnaireMaitreDesClesSQLite {

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

        let commandes: Vec<&str> = vec![
            COMMANDE_SAUVEGARDER_CLE,
        ];
        let fingerprint = self.handler_rechiffrage.fingerprint()?;
        let nom_partition = fingerprint.as_str();

        for sec in [Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure] {

            if dechiffrer {
                rk_dechiffrage.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_DECHIFFRAGE), exchange: sec.clone() });
                rk_dechiffrage.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_VERIFIER_PREUVE), exchange: sec.clone() });
                // rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}.{}", DOMAINE_NOM, nom_partition, REQUETE_VERIFIER_PREUVE), exchange: sec.clone() });
            }

            rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_CERTIFICAT_MAITREDESCLES), exchange: sec.clone() });

            // Commande volatile
            rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_CERT_MAITREDESCLES), exchange: sec.clone() });

            // Commande sauvegarder cles
            for commande in &commandes {
                rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.*.{}", DOMAINE_NOM, commande), exchange: sec.clone() });
            }
        }

        // Commande sauvegarder cle 4.secure pour redistribution des cles
        rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE), exchange: Securite::L4Secure });
        rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.*.{}", DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE), exchange: Securite::L4Secure });

        // Rotation des cles
        rk_commande_cle.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, nom_partition, COMMANDE_ROTATION_CERTIFICAT), exchange: Securite::L3Protege });

        // Requetes de dechiffrage/preuve re-emise sur le bus 4.secure lorsque la cle est inconnue
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_DECHIFFRAGE), exchange: Securite::L4Secure });
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_VERIFIER_PREUVE), exchange: Securite::L4Secure });

        for sec in [Securite::L3Protege, Securite::L4Secure] {
            rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION), exchange: sec.clone() });
            rk_volatils.push(ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION), exchange: sec.clone() });
        }
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, EVENEMENT_CLES_RECHIFFRAGE), exchange: Securite::L4Secure });
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, nom_partition, COMMANDE_DECHIFFRER_CLE), exchange: Securite::L4Secure });

        let commandes_protegees = vec![
            COMMANDE_RECHIFFRER_BATCH,
            COMMANDE_VERIFIER_CLE_SYMMETRIQUE,
        ];
        for commande in commandes_protegees {
            rk_volatils.push(ConfigRoutingExchange {
                routing_key: format!("commande.{}.{}", DOMAINE_NOM, commande),
                exchange: Securite::L3Protege
            });
        }

        let mut queues = Vec::new();

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
                    autodelete: false,
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
                    autodelete: false,
                }
            ));
        }

        // Queue de triggers
        let fingerprint = self.handler_rechiffrage.fingerprint().expect("fingerprint");
        queues.push(QueueType::Triggers(format!("MaitreDesCles.{}", fingerprint), Securite::L3Protege));

        Ok(queues)
    }
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

/// Helper pour mapper une ErreurMaitreDesClesSqlite vers CommonError
fn map_error(e: ErreurMaitreDesClesSqlite) -> Error {
    e.into()
}

async fn consommer_requete<M>(middleware: &M, message: MessageValide, gestionnaire: &GestionnaireMaitreDesClesSQLite)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + IsConfigNoeud + CleChiffrageHandler + CleChiffrageCache + ConfigMessages
{
    debug!("Consommer requete : {:?}", &message.message);

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

    let (domaine, action) = match &message.type_message {
        TypeMessageOut::Requete(r) => (r.domaine.clone(), r.action.clone()),
        _ => Err(Error::Str("consommer_requete Mauvais type message - doit etre requete"))?
    };

    // Note : aucune verification d'autorisation - tant que le certificat est valide (deja verifie), on repond.

    match domaine.as_str() {
        DOMAINE_NOM => {
            match action.as_str() {
                REQUETE_CERTIFICAT_MAITREDESCLES => requete_certificat_maitredescles(middleware, message).await.map_err(map_error),
                REQUETE_DECHIFFRAGE => requete_dechiffrage(middleware, message, gestionnaire).await.map_err(map_error),
                REQUETE_VERIFIER_PREUVE => requete_verifier_preuve(middleware, message, gestionnaire).await.map_err(map_error),
                EVENEMENT_CLES_MANQUANTES_PARTITION => evenement_cle_manquante(middleware, gestionnaire, &message).await.map_err(map_error),
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
    -> Result<Option<MessageMilleGrillesBufferDefault>, ErreurMaitreDesClesSqlite>
    where M: GenerateurMessages
{
    debug!("emettre_certificat_maitredescles: {:?}", &m.message);
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let chaine_pem = enveloppe_privee.enveloppe_pub.chaine_pem()?;

    let reponse = json!({ "certificat": chaine_pem });

    let message_reponse = middleware.build_reponse(&reponse)?.0;
    Ok(Some(message_reponse))
}

async fn consommer_transaction<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesSQLite) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where
    M: ValidateurX509 + GenerateurMessages
{
    debug!("maitredescles_ca.consommer_transaction Consommer transaction : {:?}", &m.message);

    // Autorisation : doit etre de niveau 4.secure
    match m.certificat.verifier_exchanges(vec![Securite::L4Secure])? {
        true => Ok(()),
        false => Err(format!("maitredescles_ca.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    let action = {
        match &m.type_message {
            TypeMessageOut::Commande(r) |
            TypeMessageOut::Transaction(r) => r.action.clone(),
            _ => Err(Error::Str("maitredescles_ca.consommer_transaction: Mauvais type de message - doit etre transaction"))?,
        }
    };

    match action.as_str() {
        _ => Err(format!("maitredescles_ca.consommer_transaction: Mauvais type d'action pour une transaction : {}", action))?,
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesSQLite)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + IsConfigNoeud + CleChiffrageHandler + ValidateurX509
{
    debug!("consommer_commande : {:?}", &m.message);

    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    let (_, action) = get_domaine_action!(m.type_message);

    if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        match action.as_str() {
            // Commandes standard
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire).await.map_err(map_error),
            COMMANDE_CERT_MAITREDESCLES => {emettre_certificat_maitredescles(middleware, Some(m)).await?; Ok(None)},

            COMMANDE_RECHIFFRER_BATCH => commande_rechiffrer_batch(middleware, m, gestionnaire).await.map_err(map_error),
            COMMANDE_CLE_SYMMETRIQUE => commande_cle_symmetrique(middleware, m, gestionnaire).await.map_err(map_error),
            // Commandes inconnues
            _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else if role_prive == true && user_id.is_some() {
        match action.as_str() {
            // Commandes standard
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire).await.map_err(map_error),
            COMMANDE_CERT_MAITREDESCLES => {emettre_certificat_maitredescles(middleware, Some(m)).await?; Ok(None)},
            COMMANDE_VERIFIER_CLE_SYMMETRIQUE => commande_verifier_cle_symmetrique(middleware, gestionnaire, &m).await.map_err(map_error),

            // Commandes inconnues
            _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else if m.certificat.verifier_exchanges(vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])? {
        match action.as_str() {
            // Commandes standard
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire).await.map_err(map_error),
            COMMANDE_CERT_MAITREDESCLES => {emettre_certificat_maitredescles(middleware, Some(m)).await?; Ok(None)},
            COMMANDE_ROTATION_CERTIFICAT => commande_rotation_certificat(middleware, m, gestionnaire).await.map_err(map_error),
            COMMANDE_CLE_SYMMETRIQUE => commande_cle_symmetrique(middleware, m, gestionnaire).await.map_err(map_error),
            COMMANDE_DECHIFFRER_CLE => commande_dechiffrer_cle(middleware, m, gestionnaire).await,
            // Commandes inconnues
            _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else {
        Err(Error::Str("Autorisation commande invalide, acces refuse"))?
    }
}

async fn consommer_evenement<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesSQLite, m: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + IsConfigNoeud + CleChiffrageHandler + CleChiffrageCache + ConfigMessages
{
    debug!("consommer_evenement Consommer evenement : {:?}", &m.message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
        true => Ok(()),
        false => Err(format!("consommer_evenement: Evenement invalide (pas 3.protege ou 4.secure)")),
    }?;

    let (_, action) = get_domaine_action!(m.type_message);

    match action.as_str() {
        EVENEMENT_CLES_MANQUANTES_PARTITION => evenement_cle_manquante(middleware, gestionnaire, &m).await.map_err(map_error),
        EVENEMENT_CLES_RECHIFFRAGE => evenement_cle_rechiffrage(middleware, m, gestionnaire).await.map_err(map_error),
        _ => Err(Error::String(format!("consommer_transaction: Mauvais type d'action pour une transaction : {}", action)))?,
    }
}

async fn commande_sauvegarder_cle<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesSQLite)
    -> Result<Option<MessageMilleGrillesBufferDefault>, ErreurMaitreDesClesSqlite>
    where M: GenerateurMessages + IsConfigNoeud + CleChiffrageHandler
{
    debug!("commande_sauvegarder_cle Consommer commande : {:?}", & m.message);
    let fingerprint = gestionnaire.handler_rechiffrage.fingerprint()?;

    let commande: CommandeSauvegarderCle = deser_message_buffer!(m.message);
    debug!("Commande sauvegarder cle parsed : {:?}", commande);

    let partition_message = match &m.type_message {
        TypeMessageOut::Commande(r) => r.partition.clone(),
        _ => Err(Error::Str("commande_sauvegarder_cle Mauvais type de message, doit etre commande"))?
    };

    let cle = match commande.cles.get(fingerprint.as_str()) {
        Some(cle) => cle.as_str(),
        None => {
            // La cle locale n'est pas presente. Verifier si le message de sauvegarde etait
            // adresse a cette partition.
            let reponse = if Some(fingerprint) == partition_message {
                let message = format!("maitredescles_sqlite1.commande_sauvegarder_cle: Erreur validation - commande sauvegarder cles ne contient pas la cle CA : {:?}", commande);
                warn!("{}", message);
                // let reponse_err = json!({"ok": false, "err": message});
                // Ok(Some(middleware.formatter_reponse(&reponse_err, None)?))
                Ok(Some(middleware.reponse_err(None, None, Some(message.as_str()))?))
            } else {
                // Rien a faire, message ne concerne pas cette partition
                Ok(None)
            };
            return reponse;
        }
    };

    let enveloppe_privee = middleware.get_enveloppe_signature();
    let cle_tierce_vec: Vec<u8> = multibase::decode(cle)?.1;
    let cle_dechiffree = dechiffrer_asymmetrique_ed25519(
        &cle_tierce_vec[..], &enveloppe_privee.cle_privee)?;

    let cle_rechiffrage = CleSecreteRechiffrage::from_commande(&cle_dechiffree, commande.clone())?;

    {
        let connexion_guard = gestionnaire.ouvrir_connection_sauvegardercle(middleware)
            .lock().expect("requete_dechiffrage connection lock");
        let connexion = connexion_guard.as_ref().expect("requete_dechiffrage connection Some");
        connexion.execute("BEGIN;")?;
        match sauvegarder_cle(middleware, &gestionnaire, connexion, cle_rechiffrage) {
            Ok(()) => connexion.execute("COMMIT;")?,
            Err(e) => {
                connexion.execute("ROLLBACK;")?;
                Err(e)?
            }
        }
    }

    if Some(fingerprint) == partition_message {
        // Le message etait adresse a cette partition
        Ok(Some(middleware.reponse_ok(None, None)?))
    } else {
        // Cle sauvegardee mais aucune reponse requise
        Ok(None)
    }
}

async fn commande_rechiffrer_batch<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesSQLite)
    -> Result<Option<MessageMilleGrillesBufferDefault>, ErreurMaitreDesClesSqlite>
    where M: GenerateurMessages + IsConfigNoeud + CleChiffrageHandler
{
    debug!("commande_rechiffrer_batch Consommer commande : {:?}", & m.message);
    let message_ref = m.message.parse()?;
    let correlation_id = match &m.type_message {
        TypeMessageOut::Commande(r) => {
            match r.correlation_id.as_ref() { Some(inner) => inner.clone(), None => message_ref.id.to_owned() }
        },
        _ => {
            Err(Error::Str("commande_rechiffrer_batch Mauvais type message - doit etre commande"))?
        }
    };
    let message_chiffre = MessageReponseChiffree::try_from(message_ref)?;
    let message_dechiffre = message_chiffre.dechiffrer(middleware)?;
    let commande: CommandeRechiffrerBatch = serde_json::from_slice(&message_dechiffre.data_dechiffre[..])?;

    let connexion = gestionnaire.ouvrir_connection(middleware, false);

    let enveloppe_privee = middleware.get_enveloppe_signature();
    let fingerprint_ca = enveloppe_privee.enveloppe_ca.fingerprint()?;
    let fingerprint = enveloppe_privee.fingerprint()?;

    let routage_commande = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE, vec![Securite::L4Secure])
        .build();

    todo!("Fix me")
    // // Traiter chaque cle individuellement
    // let liste_hachage_bytes: Vec<String> = commande.cles.iter().map(|c| c.hachage_bytes.to_owned()).collect();
    // let mut liste_cle_ref: Vec<String> = Vec::new();
    // connexion.execute("BEGIN TRANSACTION;")?;
    //
    // for info_cle in commande.cles {
    //     debug!("commande_rechiffrer_batch Cle {:?}", info_cle);
    //
    //     let cle_ref = info_cle.get_cle_ref()?;
    //     sauvegarder_cle(middleware, &gestionnaire, &connexion, info_cle)?;
    //
    //     liste_cle_ref.push(cle_ref);
    // }
    // connexion.execute("COMMIT;")?;
    //
    // // Emettre un evenement pour confirmer le traitement.
    // // Utilise par le CA (confirme que les cles sont dechiffrables) et par le client (batch traitee)
    // let routage_event = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_CLE_RECUE_PARTITION, vec![Securite::L4Secure]).build();
    // let event_contenu = json!({
    //     "correlation": correlation_id,
    //     "liste_hachage_bytes": liste_hachage_bytes,
    //     CHAMP_LISTE_CLE_REF: liste_cle_ref,
    // });
    // middleware.emettre_evenement(routage_event, &event_contenu).await?;
    //
    // Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn aiguillage_transaction<M>(_middleware: &M, transaction: TransactionValide, _gestionnaire: &GestionnaireMaitreDesClesSQLite)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages
{
    // let action = match transaction.get_routage().action.as_ref() {
    //     Some(inner) => inner.as_str(),
    //     None => Err(Error::String(format!("core_backup.aiguillage_transaction: Transaction {} n'a pas d'action", transaction.get_uuid_transaction())))?
    // };
    // match action {
        // TRANSACTION_CLE => transaction_cle(middleware, transaction, gestionnaire).await,
        Err(Error::Str("maitredescles_sqlite.aiguillage_transaction: Ce module ne supporte pas les transactions"))
    // }
}

async fn entretien<M>(gestionnaire: &'static GestionnaireMaitreDesClesSQLite, middleware: Arc<M>)
    where M: Middleware + 'static
{
    // Preparer la collection avec index
    gestionnaire.preparer_database(middleware.as_ref()).await.expect("preparer_database");

    let mut q_preparation_completee = false;

    loop {
        if !gestionnaire.handler_rechiffrage.is_ready() || q_preparation_completee == false {

            if q_preparation_completee == true {
                panic!("handler rechiffrage is_ready() == false et q_preparation_completee == true");
            }

            info!("entretien_rechiffreur Aucun certificat configure, on demande de generer un certificat volatil");
            let resultat = match preparer_rechiffreur_sqlite(middleware.as_ref(), gestionnaire).await {
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
                let queues = gestionnaire.preparer_queues_rechiffrage().expect("preparer_queues_rechiffrage");
                for queue in queues {

                    let queue_name = match &queue {
                        QueueType::ExchangeQueue(q) => q.nom_queue.clone(),
                        QueueType::ReplyQueue(_) => { continue },
                        QueueType::Triggers(d,s) => format!("{}.{:?}", d, s)
                    };

                    // Creer thread de traitement
                    let (tx, rx) = mpsc::channel::<TypeMessage>(1);
                    let mut futures_consumer = FuturesUnordered::new();
                    futures_consumer.push(spawn(gestionnaire.consommer_messages(middleware.clone(), rx)));

                    // Ajouter nouvelle queue
                    let named_queue = NamedQueue::new(queue, tx, Some(1), Some(futures_consumer));
                    middleware.ajouter_named_queue(queue_name, named_queue);

                    q_preparation_completee = true;
                }
            }
        }

        debug!("Cycle entretien {}", DOMAINE_NOM);
        middleware.entretien_validateur().await;

        // Sleep cycle
        sleep(Duration_tokio::new(30, 0)).await;
    }
}

pub async fn preparer_rechiffreur_sqlite<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesSQLite)
    -> Result<(), ErreurMaitreDesClesSqlite>
    where M: GenerateurMessages + ValidateurX509 + IsConfigNoeud
{
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let instance_id = enveloppe_privee.enveloppe_pub.get_common_name()?;
    let fingerprint = enveloppe_privee.fingerprint()?;
    let handler_rechiffrage = &gestionnaire.handler_rechiffrage;

    let mut cle_ca = None;

    {
        let connexion = gestionnaire.ouvrir_connection(middleware, false);
        let cle_ca_trouvee = charger_cle_configuration(middleware, &connexion, "CA")?;
        match cle_ca_trouvee {
            Some(inner) => {
                info!("preparer_rechiffreur_sqlite Cle CA existe");
                match charger_cle_configuration(middleware, &connexion, "local")? {
                    Some(cle_locale) => {
                        handler_rechiffrage.set_cle_symmetrique(cle_locale)?;
                        info!("preparer_rechiffreur_sqlite Cle de rechiffrage locale est chargee");
                    },
                    None => {
                        info!("demander rechiffrage cle locale");
                        cle_ca = Some(inner)
                    }
                }
            },
            None => {
                info!("preparer_rechiffreur_sqlite Initialiser cle symmetrique locale");
                preparer_rechiffreur(middleware, handler_rechiffrage).await?;
                // Conserver la cle de rechiffrage
                let cle_secrete_chiffree_ca = handler_rechiffrage.get_cle_symmetrique_chiffree(&enveloppe_privee.enveloppe_ca.certificat.public_key()?)?;
                let cle_secrete_chiffree_local = handler_rechiffrage.get_cle_symmetrique_chiffree(&enveloppe_privee.enveloppe_pub.certificat.public_key()?)?;
                debug!("Cle secrete chiffree pour instance {} :\nCA = {}\n local = {}", instance_id, cle_secrete_chiffree_ca, cle_secrete_chiffree_local);

                // Sauvegarder la cle symmetrique
                sauvegarder_cle_configuration(
                    middleware, &connexion, "CA",
                    instance_id.as_str(), "CA", cle_secrete_chiffree_ca, None)?;
                sauvegarder_cle_configuration(
                    middleware, &connexion, "local",
                    instance_id.as_str(), fingerprint, cle_secrete_chiffree_local, None)?;
            }
        }
    };

    if let Some(cle_ca) = cle_ca {
        emettre_demande_cle_symmetrique(middleware, cle_ca).await?;
        Err(Error::Str("preparer_rechiffreur_mongo Attente cle de rechiffrage"))?;
    }

    Ok(())
}

async fn requete_dechiffrage<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesSQLite)
    -> Result<Option<MessageMilleGrillesBufferDefault>, ErreurMaitreDesClesSqlite>
    where M: GenerateurMessages + IsConfigNoeud + ValidateurX509 + CleChiffrageHandler
{
    debug!("requete_dechiffrage Consommer requete : {:?}", & m.message);
    let message_ref = m.message.parse()?;
    let requete: RequeteDechiffrage = match message_ref.contenu()?.deserialize() {
        Ok(inner) => inner,
        Err(e) => {
            info!("requete_dechiffrage Erreur mapping ParametresGetPermissionMessages : {:?}", e);
            //return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": format!("Erreur mapping requete : {:?}", e)}), None)?))
            return Ok(Some(middleware.reponse_err(None, None, Some(format!("Erreur mapping requete : {:?}", e).as_str()))?))
        }
    };
    debug!("requete_dechiffrage cle parsed : {:?}", requete);

    let enveloppe_privee = middleware.get_enveloppe_signature();
    let fingerprint = enveloppe_privee.fingerprint()?;

    let certificat_requete = m.certificat.as_ref();
    let extensions = certificat_requete.extensions()?;
    let domaines_permis = extensions.domaines;

    // Trouver le certificat de rechiffrage
    let certificat = match requete.certificat_rechiffrage.as_ref() {
        Some(cr) => {
            debug!("Utilisation certificat dans la requete de dechiffrage");
            middleware.charger_enveloppe(cr, None, None).await?
        },
        None => {
            m.certificat.clone()
            // match &m.certificat {
            //     Some(c) => c.clone(),
            //     None => {
            //         debug!("requete_dechiffrage Requete {:?} de dechiffrage {:?} refusee, certificat manquant", m.correlation_id, &requete.liste_hachage_bytes);
            //         let refuse = json!({"ok": false, "err": "Autorisation refusee - certificat manquant ou introuvable", "acces": "0.refuse", "code": 0});
            //         return Ok(Some(middleware.formatter_reponse(&refuse, None)?))
            //     }
            // }
        }
    };

    let certificat_valide = middleware.valider_chaine(certificat.as_ref(), None, true).unwrap_or_else(|e| {
        error!("requete_dechiffrage Erreur de validation du certificat : {:?}", e);
        false
    });
    if ! certificat_valide {
        let refuse = json!({"ok": false, "err": "Autorisation refusee - certificat de rechiffrage n'est pas presentement valide", "acces": "0.refuse", "code": 0});
        return Ok(Some(middleware.build_reponse(&refuse)?.0))
    }

    // Verifier si on a une autorisation de dechiffrage global
    let (requete_autorisee_globalement, permission) = verifier_autorisation_dechiffrage_global(
        middleware, &m, &requete).await?;

    // Rejeter si global false et permission absente
    if ! requete_autorisee_globalement && permission.is_none() && domaines_permis.is_none() {
        debug!("requete_dechiffrage Requete {:?} de dechiffrage {:?} refusee, permission manquante ou aucuns domaines inclus dans le certificat",
            m.type_message, &requete.liste_hachage_bytes);
        let refuse = json!({"ok": false, "err": "Autorisation refusee - permission manquante", "acces": "0.refuse", "code": 0});
        return Ok(Some(middleware.build_reponse(&refuse)?.0))
    }

    // Trouver les cles demandees et rechiffrer
    // let mut connection = gestionnaire.ouvrir_connection(middleware, true);
    let mut cles = {
        let mut connection_guard = gestionnaire.ouvrir_connection_readonly(middleware)
            .lock().expect("requete_dechiffrage connection lock");
        let connection = connection_guard.as_mut().expect("requete_dechiffrage connection Some");

        get_cles_sqlite_rechiffrees(
            middleware, gestionnaire, connection, &requete, enveloppe_privee.clone(), certificat.as_ref(),
            permission.as_ref(), domaines_permis.as_ref())?
    };

    todo!("Combiner avec code de partition si possible")
    // // Verifier si on a des cles inconnues
    // if cles.len() < requete.liste_hachage_bytes.len() {
    //     debug!("requete_dechiffrage Cles manquantes, on a {} trouvees sur {} demandees", cles.len(), requete.liste_hachage_bytes.len());
    //
    //     let cles_connues = cles.keys().map(|s|s.to_owned()).collect();
    //     match requete_cles_inconnues(middleware, &requete, cles_connues).await {
    //         Ok(mut reponse) => {
    //             debug!("Reponse cle manquantes recue : {:?}", reponse.cles);
    //             let connexion = gestionnaire.ouvrir_connection(middleware, false);
    //             for cle in reponse.cles.into_iter() {
    //                 let hachage_bytes = cle.hachage_bytes.clone();
    //
    //                 let cle_secrete = cle.get_cle_secrete()?;
    //                 let (_, cle_rechiffree) = cle.rechiffrer_cle(&gestionnaire.handler_rechiffrage)?;
    //
    //                 let mut doc_cle: RowClePartition = cle.try_into()?;
    //                 doc_cle.cle_symmetrique = Some(cle_rechiffree.cle);
    //                 doc_cle.nonce_symmetrique = Some(cle_rechiffree.nonce);
    //
    //                 let cle_interne = CleSecreteRechiffrage::from_doc_cle(cle_secrete, doc_cle.clone())?;
    //                 sauvegarder_cle(middleware, &gestionnaire, &connexion, cle_interne)?;
    //
    //                 match rechiffrer_cle(&mut doc_cle, &gestionnaire.handler_rechiffrage, certificat.as_ref()) {
    //                     Ok(()) => {
    //                         cles.insert(hachage_bytes, doc_cle);
    //                     },
    //                     Err(e) => {
    //                         error!("rechiffrer_cles Erreur rechiffrage cle {:?}", e);
    //                         continue;  // Skip cette cle
    //                     }
    //                 }
    //             }
    //         },
    //         Err(e) => {
    //             error!("requete_dechiffrage Erreur requete_cles_inconnues, skip : {:?}", e)
    //         }
    //     }
    // }
    //
    // // Preparer la reponse
    // // Verifier si on a au moins une cle dans la reponse
    // let reponse = if cles.len() > 0 {
    //     let reponse = json!({
    //         "acces": CHAMP_ACCES_PERMIS,
    //         "code": 1,
    //         "cles": cles,
    //     });
    //     middleware.build_reponse(reponse)?.0
    // } else {
    //     // On n'a pas trouve de cles
    //     debug!("requete_dechiffrage Requete {:?} de dechiffrage {:?}, cles inconnues", m.type_message, &requete.liste_hachage_bytes);
    //     let inconnu = json!({"ok": false, "err": "Cles inconnues", "acces": CHAMP_ACCES_CLE_INCONNUE, "code": 4});
    //     middleware.build_reponse(&inconnu)?.0
    // };
    //
    // Ok(Some(reponse))
}

/// Verifie que la requete contient des cles secretes qui correspondent aux cles stockees.
/// Confirme que le demandeur a bien en sa possession (via methode tierce) les cles secretes.
async fn requete_verifier_preuve<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesSQLite)
    -> Result<Option<MessageMilleGrillesBufferDefault>, ErreurMaitreDesClesSqlite>
    where M: GenerateurMessages + ValidateurX509 + IsConfigNoeud + CleChiffrageHandler
{
    todo!("fix me")

    // debug!("requete_verifier_preuve Consommer requete : {:?}", & m.message);
    // let requete: RequeteVerifierPreuve = m.message.get_msg().map_contenu()?;
    // debug!("requete_verifier_preuve cle parsed : {:?}", requete);
    //
    // // La preuve doit etre recente (moins de 5 minutes)
    // {
    //     let estampille = &m.message.parsed.estampille;
    //     let datetime_estampille = estampille.get_datetime();
    //     let date_expiration = Utc::now() - Duration::minutes(5);
    //     if datetime_estampille < &date_expiration {
    //         Err(format!("maitredescles_partition.requete_verifier_preuve Demande preuve est expiree ({:?})", datetime_estampille))?;
    //     }
    // }

    // // Preparer une liste de verification pour chaque cle par hachage_bytes
    // let mut map_hachage_bytes = HashMap::new();
    // for cle in requete.cles.into_iter() {
    //     map_hachage_bytes.insert(cle.hachage_bytes.clone(), cle);
    // }
    //
    // let mut liste_hachage_bytes = Vec::new();
    // let mut liste_verification: HashMap<String, Option<String>> = HashMap::new();
    // for (hachage_bytes, _) in map_hachage_bytes.iter() {
    //     let hachage_bytes = hachage_bytes.as_str();
    //     liste_hachage_bytes.push(hachage_bytes);
    //     liste_verification.insert(hachage_bytes.to_owned(), None);
    // }
    //
    // // Trouver les cles en reference
    // let connexion = gestionnaire.ouvrir_connection(middleware, true);
    // let enveloppe_privee = middleware.get_enveloppe_signature();
    // let cle_privee = enveloppe_privee.cle_privee();
    //
    // for hachage_bytes in liste_hachage_bytes {
    //     let transaction_cle = match charger_cle(&connexion, hachage_bytes) {
    //         Ok(c) => match c{
    //             Some(c) => c,
    //             None => continue
    //         },
    //         Err(e) => {
    //             error!("requete_verifier_preuve Erreur chargement cle {} : {:?}", hachage_bytes, e);
    //             continue
    //         }
    //     };
    //
    //     let cle_db_dechiffree = extraire_cle_secrete(cle_privee, transaction_cle.cle.as_str())?;
    //     let hachage_bytes_db = transaction_cle.hachage_bytes.as_str();
    //     if let Some(cle_preuve) = map_hachage_bytes.get(hachage_bytes_db) {
    //         todo!("Fix me");
    //         // match dechiffrer_asymetrique_multibase(cle_privee, cle_preuve.cle.as_str()){
    //         //     Ok(cle_preuve_dechiffree) => {
    //         //         if cle_db_dechiffree == cle_preuve_dechiffree {
    //         //             // La cle preuve correspond a la cle dans la base de donnees, verification OK
    //         //             liste_verification.insert(hachage_bytes_db.into(), Some(true));
    //         //         } else {
    //         //             liste_verification.insert(hachage_bytes_db.into(), Some(false));
    //         //         }
    //         //     },
    //         //     Err(e) => {
    //         //         error!("requete_verifier_preuve Erreur dechiffrage cle {} : {:?}", hachage_bytes_db, e);
    //         //         liste_verification.insert(hachage_bytes_db.into(), Some(false));
    //         //     }
    //         // }
    //     }
    // }

    // // Verifier toutes les cles qui n'ont pas ete identifiees dans la base de donnees (inconnues)
    // let liste_inconnues: Vec<String> = liste_verification.iter().filter(|(k, v)| match v {
    //     Some(_) => false,
    //     None => true
    // }).map(|(k,_)| k.to_owned()).collect();
    // for hachage_bytes in liste_inconnues.into_iter() {
    //     if let Some(info_cle) = map_hachage_bytes.remove(&hachage_bytes) {
    //         debug!("requete_verifier_preuve Conserver nouvelle cle {}", hachage_bytes);
    //
    //         let commande_cle = rechiffrer_pour_maitredescles(middleware, &info_cle)?;
    //         // Conserver la cle via commande
    //         let partition = gestionnaire.fingerprint.as_str();
    //         let routage = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE)
    //             .partition(partition)
    //             .build();
    //         // Conserver la cle
    //         // let commande_cle = info_cle.into_commande(partition);
    //         // Transmettre commande de sauvegarde - on n'attend pas la reponse (deadlock)
    //         middleware.transmettre_commande(routage, &commande_cle, false).await?;
    //
    //         // Indiquer que la cle est autorisee (c'est l'usager qui vient de la pousser)
    //         liste_verification.insert(hachage_bytes, Some(true));
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

fn get_cles_sqlite_rechiffrees<M>(
    middleware: &M,
    gestionnaire: &GestionnaireMaitreDesClesSQLite,
    connexion: &mut Connection,
    requete: &RequeteDechiffrage,
    enveloppe_privee: Arc<EnveloppePrivee>,
    certificat: &EnveloppeCertificat,
    permission: Option<&EnveloppePermission>,
    domaines_permis: Option<&Vec<String>>
)
    -> Result<HashMap<String, RowClePartition>, Error>
    where M: FormatteurMessage
{
    let mut cles: HashMap<String, RowClePartition> = HashMap::new();
    todo!("fix me")
    // for hachage_bytes in &requete.liste_hachage_bytes {
    //     let mut cle_transaction = match charger_cle(connexion, requete.domaine.as_str(), hachage_bytes) {
    //         Ok(c) => match c{
    //             Some(c) => c,
    //             None => {
    //                 warn!("get_cles_sqlite_rechiffrees Cle inconnue : {}", hachage_bytes);
    //                 continue
    //             }
    //         },
    //         Err(e) => {
    //             error!("get_cles_sqlite_rechiffrees Erreur chargement cle {} : {:?}", hachage_bytes, e);
    //             continue;
    //         }
    //     };
    //
    //     debug!("get_cles_sqlite_rechiffrees Rechiffrer cle : {:?}", cle_transaction);
    //
    //     // Verifier autorisation du domaine
    //     match domaines_permis {
    //         Some(domaines) => {
    //             let domaine_cle = &cle_transaction.domaine;
    //             if domaines.contains(domaine_cle) == false {
    //                 debug!("get_cles_sqlite_rechiffrees Demande de rechiffrage de {} refusee, certificat ne supporte pas domaine {}", hachage_bytes, domaine_cle);
    //                 continue
    //             }
    //         },
    //         None => ()
    //     }
    //
    //     // Rechiffrer
    //     // rechiffrer_cle(&mut cle_transaction, enveloppe_privee.as_ref(), certificat)?;
    //     rechiffrer_cle(&mut cle_transaction, &gestionnaire.handler_rechiffrage, certificat)?;
    //     todo!("fix me")
    //     // cles.insert(hachage_bytes.clone(), cle_transaction);
    // }
    //
    // debug!("Cles rechiffrees : {:?}", cles);
    //
    // Ok(cles)
}

/// Verifier si la requete de dechiffrage est valide (autorisee) de maniere globale
/// Les certificats 4.secure et delegations globales proprietaire donnent acces a toutes les cles
async fn verifier_autorisation_dechiffrage_global<M>(middleware: &M, m: &MessageValide, requete: &RequeteDechiffrage)
    -> Result<(bool, Option<EnveloppePermission>), Error>
    where M: ValidateurX509
{
    // Verifier si le certificat est une delegation globale
    if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        debug!("verifier_autorisation_dechiffrage Certificat delegation globale proprietaire - toujours autorise");
        return Ok((true, None))
    }

    // Acces global refuse.
    // On verifie la presence et validite d'une permission

    let mut permission: Option<EnveloppePermission> = None;

    Ok((false, None))
}

async fn synchroniser_cles<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesSQLite) -> Result<(), ErreurMaitreDesClesSqlite>
    where M: GenerateurMessages + IsConfigNoeud + CleChiffrageHandler
{
    let fingerprint = gestionnaire.handler_rechiffrage.fingerprint();

    // Requete vers CA pour obtenir la liste des cles connues
    let mut requete_sync = RequeteSynchroniserCles {page: 0, limite: 250};
    let routage_sync = RoutageMessageAction::builder(DOMAINE_NOM, REQUETE_SYNCHRONISER_CLES, vec![Securite::L4Secure])
        .timeout_blocking(30000)
        .build();

    let routage_evenement_manquant = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION, vec![Securite::L4Secure])
        .ajouter_reply_q(true)
        .timeout_blocking(20000)
        .build();

    let enveloppe_privee = middleware.get_enveloppe_signature();
    let fingerprint = enveloppe_privee.fingerprint()?;
    let connexion = gestionnaire.ouvrir_connection(middleware, false);

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

        let liste_cles = reponse.liste_cle_id;
        if liste_cles.len() == 0 {
            debug!("synchroniser_cles Traitement sync termine");
            break
        }

        todo!("fix me")
        // let mut cles_manquantes = HashSet::new();
        // debug!("synchroniser_cles Recu liste_hachage_bytes a verifier : {}", liste_cles.len());
        //
        // {
        //     let mut prepared_statement_checkcle = connexion.prepare(
        //         "SELECT domaine, hachage_bytes FROM cles WHERE domaine = ? AND hachage_bytes = ?")?;
        //     for cle_synchronisation in liste_cles.iter() {
        //         prepared_statement_checkcle.bind((1, cle_synchronisation.domaine.as_str()))?;
        //         prepared_statement_checkcle.bind((2, cle_synchronisation.hachage_bytes.as_str()))?;
        //         let resultat = prepared_statement_checkcle.next()?;
        //         match resultat {
        //             State::Row => (),
        //             State::Done => { cles_manquantes.insert(cle_synchronisation); }
        //         }
        //         prepared_statement_checkcle.reset()?;
        //     }
        // }
        //
        // if cles_manquantes.len() > 0 {
        //     info!("Cles manquantes nb: {}", cles_manquantes.len());
        //     let evenement_cles_manquantes = ReponseSynchroniserCles { liste_cles };
        //     let reponse = middleware.transmettre_requete(routage_evenement_manquant.clone(), &evenement_cles_manquantes).await?;
        //     // debug!("Reponse  {:?}", reponse);
        //     let data_reponse = match reponse {
        //         Some(inner) => match inner {
        //             TypeMessage::Valide(mut inner) => {
        //                 debug!("Reponse demande cles manquantes : {:?}", inner);
        //                 let message_ref = inner.message.parse()?;
        //                 match MessageReponseChiffree::try_from(message_ref) {
        //                     Ok(inner) => inner.dechiffrer(middleware)?,
        //                     Err(e) => {
        //                         warn!("maitredescles_sqlite.synchroniser_cles Erreur dechiffrage reponse : {:?}", e);
        //                         continue;
        //                     }
        //                 }
        //             },
        //             _ => {
        //                 warn!("maitredescles_sqlite.synchroniser_cles Erreur reception reponse cles manquantes, mauvais type reponse.");
        //                 continue;
        //             }
        //         },
        //         None => {
        //             warn!("maitredescles_sqlite.synchroniser_cles Erreur reception reponse cles manquantes, aucune reponse.");
        //             continue;
        //         }
        //     };
        //
        //     let reponse: MessageListeCles = serde_json::from_slice(&data_reponse.data_dechiffre[..])?;
        //     debug!("Reponse {:?}", reponse.cles);
        //     connexion.execute("BEGIN TRANSACTION;")?;
        //     for cle_rechiffree in reponse.cles.into_iter() {
        //         sauvegarder_cle(middleware, &gestionnaire, &connexion, cle_rechiffree)?;
        //     }
        //     connexion.execute("COMMIT;")?;
        // }

    }

    Ok(())
}

async fn confirmer_cles_ca<M>(middleware: Arc<M>, gestionnaire: &'static GestionnaireMaitreDesClesSQLite, reset_flag: Option<bool>)
    -> Result<(), ErreurMaitreDesClesSqlite>
    where M: Middleware + 'static
{
    let batch_size = 250;

    debug!("confirmer_cles_ca Debut confirmation cles locales avec confirmation_ca=0");

    let connexion = gestionnaire.ouvrir_connection(middleware.as_ref(), false);

    if let Some(true) = reset_flag {
        debug!("confirmer_cles_ca Reset flag confirmation_ca = 0");
        connexion.execute("UPDATE cles SET confirmation_ca = 0;")?;
    }

    // Boucle de traitement, le break survient quand il ne reste aucun row avec confirmation_ca = 0
    todo!("fix me")
    // loop {
    //     // Lire une batch de cles
    //     let batch_cles = {
    //         let mut prepared_statement = connexion.prepare("SELECT domaine, hachage_bytes FROM cles WHERE confirmation_ca = 0 LIMIT ?")?;
    //         prepared_statement.bind((1, batch_size))?;
    //         let mut batch_cles = Vec::new();
    //
    //         let mut cursor = prepared_statement.into_iter();
    //         while let Some(row_result) = cursor.next() {
    //             let row = row_result?;
    //             // let domaine: String = row[0].as_string().expect("__curseur_lire_cles domaine").to_owned();
    //             // let hachage_bytes: String = row[1].as_string().expect("__curseur_lire_cles hachage_bytes").to_owned();
    //             let domaine: String = row.read::<&str, _>("domaine").to_string();
    //             let hachage_bytes: String = row.read::<&str, _>("hachage_bytes").to_string();
    //             batch_cles.push(CleSynchronisation { hachage_bytes, domaine });
    //         }
    //
    //         batch_cles
    //     };
    //
    //     // Condition de fin, aucunes cles restantes.
    //     if batch_cles.len() == 0 {
    //         break;
    //     }
    //
    //     match emettre_cles_vers_ca(middleware.as_ref(), gestionnaire, &batch_cles).await {
    //         Ok(()) => (),
    //         Err(e) => error!("emettre_batch_cles_versca Erreur traitement batch cles : {:?}", e)
    //     }
    //
    //     // Marquer les cles restantes comme non confirmees
    //     {
    //         let mut prepared_statement = connexion.prepare(
    //             "UPDATE cles SET confirmation_ca = 2 WHERE domaine = ? AND hachage_bytes = ? AND confirmation_ca = 0")?;
    //         connexion.execute("BEGIN")?;
    //         for cle in &batch_cles {
    //             prepared_statement.bind((1, cle.domaine.as_str()))?;
    //             prepared_statement.bind((2, cle.hachage_bytes.as_str()))?;
    //             prepared_statement.next()?;
    //             prepared_statement.reset()?;
    //         }
    //         connexion.execute("COMMIT")?;
    //     }
    // }
    //
    // // Reset les cles non confirmees (2) a l'etat non traite (0)
    // connexion.execute("UPDATE cles SET confirmation_ca = 0 WHERE confirmation_ca = 2")?;
    //
    // debug!("confirmer_cles_ca Traitement cles CA termine");
    //
    // Ok(())
}

/// Emet un message vers CA pour verifier quels cles sont manquantes (sur le CA)
/// Marque les cles presentes sur la partition et CA comme confirmation_ca=true
/// Rechiffre et emet vers le CA les cles manquantes
async fn emettre_cles_vers_ca<M>(
    middleware: &M, gestionnaire: &GestionnaireMaitreDesClesSQLite, cles_synchronisation: &Vec<CleSynchronisation>)
    -> Result<(), ErreurMaitreDesClesSqlite>
    where M: GenerateurMessages + IsConfigNoeud + CleChiffrageHandler
{
    debug!("emettre_cles_vers_ca Batch cles {:?}", cles_synchronisation);

    let liste_cle_id: Vec<String> = cles_synchronisation.iter().map(|v| v.cle_id.clone()).collect();

    let commande = ReponseSynchroniserCles { liste_cle_id: liste_cle_id.clone() };
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_CONFIRMER_CLES_SUR_CA, vec![Securite::L4Secure])
        .build();
    let option_reponse = middleware.transmettre_commande(routage, &commande).await?;
    match option_reponse {
        Some(r) => {
            match r {
                TypeMessage::Valide(reponse) => {
                    debug!("emettre_cles_vers_ca Reponse confirmer cle sur CA : {:?}", reponse);
                    let reponse_cles_manquantes: ReponseConfirmerClesSurCa = deser_message_buffer!(reponse.message);
                    let cles_manquantes = reponse_cles_manquantes.cles_manquantes;
                    traiter_cles_manquantes_ca(middleware, gestionnaire, &liste_cle_id, &cles_manquantes).await?;
                },
                _ => Err(Error::Str("emettre_cles_vers_ca Recu mauvais type de reponse "))?
            }
        },
        None => info!("emettre_cles_vers_ca Aucune reponse du serveur")
    }

    Ok(())
}

/// Marque les cles emises comme confirmees par le CA sauf si elles sont dans la liste de cles manquantes.
async fn traiter_cles_manquantes_ca<M>(
    middleware: &M, gestionnaire: &GestionnaireMaitreDesClesSQLite,
    cles_emises: &Vec<String>,
    cles_manquantes: &Vec<String>
)
    -> Result<(), ErreurMaitreDesClesSqlite>
    where M: IsConfigNoeud + GenerateurMessages + CleChiffrageHandler
{
    todo!("Fix me")
    // {
    //     // Marquer cles emises comme confirmees par CA si pas dans la liste de manquantes
    //     let connexion = gestionnaire.ouvrir_connection(middleware, false);
    //
    //     let cles_confirmees: Vec<&CleSynchronisation> = cles_emises.iter()
    //         .filter(|c| !cles_manquantes.contains(c))
    //         .collect();
    //     debug!("traiter_cles_manquantes_ca Cles confirmees par le CA: {:?}", cles_confirmees);
    //     connexion.execute("BEGIN;")?;
    //     let mut statement = connexion.prepare(
    //         "UPDATE cles SET confirmation_ca = 1 WHERE domaine = ? AND hachage_bytes = ?")?;
    //     for cle in cles_confirmees {
    //         // redis_dao.retirer_cleca_manquante(fingerprint, hachage_bytes).await?;
    //         statement.bind((1, cle.domaine.as_str()))?;
    //         statement.bind((2, cle.hachage_bytes.as_str()))?;
    //         statement.next()?;
    //         statement.reset()?;
    //     }
    //     connexion.execute("COMMIT;")?;
    // }
    //
    // // Rechiffrer et emettre les cles manquantes.
    // {
    //     let routage_commande = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE, vec![Securite::L4Secure])
    //         .blocking(false)
    //         .build();
    //
    //     for cle_manquante in cles_manquantes {
    //         let commande = {
    //             let mut connection_guard = gestionnaire.ouvrir_connection_readonly(middleware)
    //                 .lock().expect("requete_dechiffrage connection lock");
    //             let connexion = connection_guard.as_ref().expect("requete_dechiffrage connection Some");
    //
    //             match charger_cle(connexion, cle_manquante.domaine.as_str(), cle_manquante.hachage_bytes.as_str()) {
    //                 Ok(c) => match c {
    //                     Some(cle) => {
    //                         match rechiffrer_pour_maitredescles_ca(
    //                             middleware, &gestionnaire.handler_rechiffrage, cle) {
    //                             Ok(c) => c,
    //                             Err(e) => {
    //                                 error!("traiter_cles_manquantes_ca Erreur traitement rechiffrage cle : {:?}", e);
    //                                 continue;
    //                             }
    //                         }
    //                     },
    //                     None => continue
    //                 },
    //                 Err(e) => {
    //                     error!("traiter_cles_manquantes_ca Erreur conversion sqlite en cle : {:?}", e);
    //                     continue;
    //                 }
    //             }
    //         };
    //
    //         debug!("Emettre cles rechiffrees pour CA : {:?}", commande);
    //         middleware.transmettre_commande(routage_commande.clone(), &commande).await?;
    //     }
    // }
    //
    // Ok(())
}

async fn evenement_cle_rechiffrage<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesSQLite)
    -> Result<Option<MessageMilleGrillesBufferDefault>, ErreurMaitreDesClesSqlite>
    where M: ValidateurX509 + GenerateurMessages + CleChiffrageHandler + ConfigMessages
{
    debug!("evenement_cle_rechiffrage Conserver cles de rechiffrage {:?}", &m.message);

    let enveloppe_signature = middleware.get_enveloppe_signature();
    let fingerprint_local = enveloppe_signature.fingerprint()?;

    let instance_id = m.certificat.get_common_name()?;
    let fingerprint = m.certificat.fingerprint()?;
    // let (instance_id, fingerprint) = match m.certificat.as_ref() {
    //     Some(inner) => (inner.get_common_name()?, inner.fingerprint.to_owned()),
    //     None => Err(Error::Str("evenement_cle_rechiffrage Certificat absent"))?
    // };

    if fingerprint_local.as_str() == fingerprint.as_str() {
        debug!("evenement_cle_rechiffrage Evenement pour cle locale (fingerprint {}), skip", fingerprint);
        return Ok(None);
    }

    let connexion = gestionnaire.ouvrir_connection(middleware, false);

    // Mapper evenement
    let evenement: EvenementClesRechiffrage = deser_message_buffer!(m.message);

    sauvegarder_cle_configuration(
        middleware, &connexion,
        "CA", instance_id.as_str(), "CA-tiers", evenement.cle_ca, None)?;

    // Dechiffrer cle du tiers, rechiffrer en symmetrique local
    if let Some(cle_tierce) = evenement.cles_dechiffrage.get(fingerprint_local.as_str()) {

        let cle_tierce_vec = multibase::decode(cle_tierce)?;
        let cle_dechiffree = dechiffrer_asymmetrique_ed25519(
            &cle_tierce_vec.1[..], &enveloppe_signature.cle_privee)?;
        let cle_chiffree = gestionnaire.handler_rechiffrage.chiffrer_cle_secrete(&cle_dechiffree.0[..])?;

        sauvegarder_cle_configuration(
            middleware, &connexion,
            "tiers", instance_id, "tiers", cle_chiffree.cle, Some(cle_chiffree.nonce.as_str()))?;

    }

    Ok(None)
}

async fn evenement_cle_manquante<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesSQLite, m: &MessageValide)
                                    -> Result<Option<MessageMilleGrillesBufferDefault>, ErreurMaitreDesClesSqlite>
    where M: ValidateurX509 + GenerateurMessages + IsConfigNoeud + CleChiffrageHandler + CleChiffrageCache + ConfigMessages
{
    debug!("evenement_cle_manquante Verifier si on peut transmettre la cle manquante {:?}", &m.message);
    let event_non_dechiffrables: ReponseSynchroniserCles = deser_message_buffer!(m.message);

    let est_evenement = match &m.type_message {
        TypeMessageOut::Evenement(_) => true,
        _ => false
    };

    if ! m.certificat.verifier_roles(vec![RolesCertificats::MaitreDesCles])? {
        debug!("evenement_cle_manquante Certificat sans role maitredescles, on rejette la demande");
        return Ok(None)
    }

    let partition = m.certificat.fingerprint()?;
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let partition_locale = enveloppe_privee.fingerprint()?;

    if partition == partition_locale {
        debug!("evenement_cle_manquante Evenement emis par la partition locale, on l'ignore");
        return Ok(None)
    }

    // S'assurer que le certificat de maitre des cles recus est dans la liste de rechiffrage
    // middleware.recevoir_certificat_chiffrage(middleware, &m.message).await?;
    middleware.ajouter_certificat_chiffrage(m.certificat.clone())?;

    let routage_commande = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE, vec![Securite::L4Secure])
        .partition(partition)
        .build();

    let hachages_bytes_list = event_non_dechiffrables.liste_cle_id;

    let connexion = gestionnaire.ouvrir_connection(middleware, true);

    todo!("Fix me")
    // let mut cles = Vec::new();
    // for cle_synchronisation in hachages_bytes_list {
    //     let commande = match charger_cle(&connexion, cle_synchronisation.domaine.as_str(), cle_synchronisation.hachage_bytes.as_str()) {
    //         Ok(cle) => {
    //             match cle {
    //                 Some(cle) => {
    //                     let cle_interne = CleInterneChiffree::try_from(cle.clone())?;
    //                     let cle_secrete = gestionnaire.handler_rechiffrage.dechiffer_cle_secrete(cle_interne)?;
    //                     CleSecreteRechiffrage::from_doc_cle(cle_secrete, cle)?
    //                 },
    //                 None => {
    //                     warn!("evenement_cle_manquante Cle inconnue : {:?}", cle_synchronisation);
    //                     continue
    //                 }
    //             }
    //         },
    //         Err(e) => {
    //             warn!("evenement_cle_manquante Erreur conversion document en cle : {:?}", e);
    //             continue
    //         }
    //     };
    //
    //     cles.push(commande);
    // }
    //
    // if cles.len() > 0 {
    //
    //     if est_evenement {
    //         todo!("obsolete")
    //     } else {
    //         // Repondre
    //         let reponse = json!({
    //             "ok": true,
    //             "cles": cles,
    //         });
    //
    //         debug!("evenement_cle_manquante Emettre reponse avec {} cles", cles.len());
    //         let reponse = middleware.build_reponse_chiffree(
    //             reponse, enveloppe_privee.as_ref(), m.certificat.as_ref())?.0;
    //         Ok(Some(reponse))
    //     }
    // } else {
    //     // Si on n'a aucune cle, ne pas repondre. Un autre maitre des cles pourrait le faire
    //     debug!("evenement_cle_manquante On n'a aucune des cles demandees");
    //     Ok(None)
    // }
}

async fn commande_verifier_cle_symmetrique<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesSQLite, m: &MessageValide)
                                              -> Result<Option<MessageMilleGrillesBufferDefault>, ErreurMaitreDesClesSqlite>
    where M: GenerateurMessages + ValidateurX509 + IsConfigNoeud
{
    debug!("evenement_verifier_cle_symmetrique Verifier si la cle symmetrique est chargee");

    if gestionnaire.handler_rechiffrage.is_ready() == false {
        // Cle symmetrique manquante, on l'emet
        debug!("evenement_verifier_cle_symmetrique Cle symmetrique manquante");
        preparer_rechiffreur_sqlite(middleware, gestionnaire).await?;
    } else {
        debug!("evenement_verifier_cle_symmetrique Cle symmetrique OK");
    }

    Ok(None)
}

// fn sauvegarder_cle<M,S,T>(
//     middleware: &M, gestionnaire: &GestionnaireMaitreDesClesSQLite, connection: &Connection,
//     fingerprint_: S, cle_: T, commande: &CommandeSauvegarderCle
// )
//     -> Result<(), Error>
//     where M: FormatteurMessage, S: AsRef<str>, T: AsRef<str>
fn sauvegarder_cle<M>(
    middleware: &M, gestionnaire: &GestionnaireMaitreDesClesSQLite, connection: &Connection,
    info_cle: CleSecreteRechiffrage
)
    -> Result<(), ErreurMaitreDesClesSqlite>
    where M: FormatteurMessage
{
    let hachage_bytes = info_cle.signature.signature.as_str();
    let (cle_ref, cle_chiffree) = info_cle.rechiffrer_cle(
        &gestionnaire.handler_rechiffrage)?;

    {
        let mut prepared_statement_verifier = connection
            .prepare("SELECT cle_ref FROM cles WHERE cle_ref = ?")?;
        prepared_statement_verifier.bind((1, cle_ref.as_str()))?;
        if State::Row == prepared_statement_verifier.next()? {
            // Skip, la cle existe deja
            debug!("sauvegarder_cle Skip cle existante {}", hachage_bytes);
            return Ok(())
        }
    }

    // Sauvegarde cle dans sqlite
    let mut prepared_statement_cle = connection
        .prepare("
            INSERT INTO cles
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ")?;
    let mut prepared_statement_identificateurs = connection
        .prepare("
            INSERT INTO identificateurs_document
            VALUES(?, ?, ?)
        ")?;

    let format_str: String = serde_json::to_string(&info_cle.format)?.replace("\"", "");

    todo!("Fix me")
    // let iv_str = None::<&str>;
    // let tag_str = None::<&str>;
    // let header_str = info_cle.header.as_str();
    //
    // prepared_statement_cle.bind((1, cle_ref.as_str()))?;
    // prepared_statement_cle.bind((2, hachage_bytes))?;
    // prepared_statement_cle.bind((3, ""))?;  // Cle asymmetrique (obsolete)
    // prepared_statement_cle.bind((4, iv_str))?;
    // prepared_statement_cle.bind((5, tag_str))?;
    // prepared_statement_cle.bind((6, header_str))?;
    // prepared_statement_cle.bind((7, cle_chiffree.cle.as_str()))?;
    // prepared_statement_cle.bind((8, cle_chiffree.nonce.as_str()))?;
    // prepared_statement_cle.bind((9, format_str.as_str()))?;
    // prepared_statement_cle.bind((10, info_cle.domaine.as_str()))?;
    // prepared_statement_cle.bind((11, 0))?;
    // // prepared_statement_cle.bind(12, info_cle.signature_identite.as_str())?;
    // prepared_statement_cle.bind((12, ""))?;
    //
    // trace!("Conserver cle dans sqlite : {}", hachage_bytes);
    // let resultat = prepared_statement_cle.next()?;
    // trace!("Resultat ajout cle dans sqlite : {:?}", resultat);
    //
    // if State::Done != resultat {
    //     Err(Error::String(format!("Erreur insertion cle {:?} (Resultat {:?})", hachage_bytes, resultat)))?
    // }
    //
    // for (cle, valeur) in &info_cle.identificateurs_document {
    //     prepared_statement_identificateurs.bind((1, cle_ref.as_str()))?;
    //     prepared_statement_identificateurs.bind((2, cle.as_str()))?;
    //     prepared_statement_identificateurs.bind((3, valeur.as_str()))?;
    //     let resultat = prepared_statement_identificateurs.next()?;
    //     prepared_statement_identificateurs.reset()?;
    // }
    //
    // Ok(())
}

fn charger_cle<D,S>(connexion: &Connection, domaine: D, hachage_bytes: S)
    -> Result<Option<RowClePartition>, ErreurMaitreDesClesSqlite>
    where D: AsRef<str>, S: AsRef<str>
{
    let domaine = domaine.as_ref();
    let hachage_bytes = hachage_bytes.as_ref();

    let mut statement = connexion.prepare(
        "\
        SELECT cle_ref, hachage_bytes, cle, iv, tag, header, format, domaine, signature_identite, \
               cle_symmetrique, nonce_symmetrique \
        FROM cles WHERE domaine = ? AND hachage_bytes = ?"
    )?;
    statement.bind((1, domaine))?;
    statement.bind((2, hachage_bytes))?;
    match statement.next()? {
        State::Row => (),
        State::Done => return Ok(None)
    }

    let cle_ref: String = statement.read(0)?;

    let mut statement_id = connexion.prepare(
        "SELECT cle, valeur FROM identificateurs_document WHERE cle_ref = ?")?;
    statement_id.bind((1, cle_ref.as_str()))?;
    let mut identificateurs_document = HashMap::new();
    while State::Done != statement_id.next()? {
        let cle: String = statement_id.read(0)?;
        let valeur: String = statement_id.read(1)?;
        identificateurs_document.insert(cle, valeur);
    }

    let mut cles: HashMap<String, String> = HashMap::new();
    cles.insert(hachage_bytes.to_owned(), statement.read(1)?);

    let format_str: String = statement.read(6)?;
    let format_chiffrage = match format_str.as_str() {
        "mgs4" => FormatChiffrage::MGS4,
        _ => Err(Error::String(format!("Format chiffrage inconnu : {}", format_str)))?
    };

    todo!("fix me")
    // let document_cle = RowClePartition {
    //     cle_ref: statement.read(0)?,
    //     hachage_bytes: hachage_bytes.to_owned(),
    //     domaine: statement.read(7)?,
    //     identificateurs_document,
    //     // signature_identite: statement.read(8)?,
    //     cle: statement.read(2)?,
    //     cle_symmetrique: Some(statement.read(9)?),
    //     nonce_symmetrique: Some(statement.read(10)?),
    //     format: format_chiffrage,
    //     iv: statement.read(3)?,
    //     tag: statement.read(4)?,
    //     header: statement.read(5)?,
    // };
    //
    // Ok(Some(document_cle))
}

fn charger_cle_configuration<M,S>(middleware: &M, connexion: &Connection, type_cle: S)
    -> Result<Option<String>, ErreurMaitreDesClesSqlite>
    where
        M: FormatteurMessage,
        S: AsRef<str>
{
    let type_cle = type_cle.as_ref();

    let cle_privee = middleware.get_enveloppe_signature();
    let instance_id = cle_privee.enveloppe_pub.get_common_name()?;

    let mut statement = match type_cle {
        "CA" => {
            let mut statement = connexion.prepare(
                "\
                SELECT cle \
                FROM configuration \
                WHERE type_cle = ? AND instance_id = ? \
                "
            )?;
            statement.bind((1, type_cle))?;
            statement.bind((2, instance_id.as_str()))?;

            statement
        },
        _ => {
            let fingerprint = cle_privee.fingerprint()?;

            let mut statement = connexion.prepare(
                "\
                SELECT cle \
                FROM configuration \
                WHERE type_cle = ? AND instance_id = ? and fingerprint = ? \
                "
            )?;
            statement.bind((1, type_cle))?;
            statement.bind((2, instance_id.as_str()))?;
            statement.bind((3, fingerprint.as_str()))?;

            statement
        }
    };

    match statement.next()? {
        State::Row => (),
        State::Done => return Ok(None)
    }

    let cle_chiffree: String = statement.read(0)?;
    Ok(Some(cle_chiffree))
}

fn sauvegarder_cle_configuration<M,S,I,T,F>(middleware: &M, connection: &Connection, type_cle: S, instance_id: I, fingerprint: F, cle: T, nonce: Option<&str>)
    -> Result<(), ErreurMaitreDesClesSqlite>
    where M: FormatteurMessage, S: AsRef<str>, I: AsRef<str>, T: AsRef<str>, F: AsRef<str>
{
    let instance_id = instance_id.as_ref();
    let fingerprint = fingerprint.as_ref();
    let type_cle = type_cle.as_ref();
    let cle = cle.as_ref();

    let cle_privee = middleware.get_enveloppe_signature();

    // Sauvegarde cle dans sqlite
    let mut prepared_statement_configuration = connection
        .prepare("
            INSERT OR REPLACE INTO configuration
            VALUES(?, ?, ?, ?, ?)
        ")?;

    prepared_statement_configuration.bind((1, type_cle))?;
    prepared_statement_configuration.bind((2, fingerprint))?;
    prepared_statement_configuration.bind((3, instance_id))?;
    prepared_statement_configuration.bind((4, cle))?;
    prepared_statement_configuration.bind((5, nonce))?;

    debug!("Conserver config cle dans sqlite : {}", fingerprint);
    let resultat = match prepared_statement_configuration.next() {
        Ok(inner) => inner,
        Err(e) => {
            match e.code.as_ref() {
                Some(inner) => {
                    if *inner == 19 {
                        // Ok, duplication
                        debug!("Cle configuration {}:{} dupliquee (OK)", instance_id, fingerprint);
                        return Ok(())
                    } else {
                        Err(e)?  // Re-throw
                    }
                },
                None => Err(e)?  // Re-throw
            }
        }
    };
    debug!("Resultat ajout cle dans sqlite : {:?}", resultat);

    if State::Done != resultat {
        Err(Error::String(format!("Erreur insertion cle Resultat {:?}", resultat)))?
    }

    Ok(())
}

async fn commande_rotation_certificat<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesSQLite)
    -> Result<Option<MessageMilleGrillesBufferDefault>, ErreurMaitreDesClesSqlite>
    where M: GenerateurMessages + ValidateurX509 + IsConfigNoeud
{
    debug!("commande_rotation_certificat Consommer commande : {:?}", & m.message);
    let commande: CommandeRotationCertificat = deser_message_buffer!(m.message);

    // Verifier que le certificat est pour l'instance locale
    // (note : pas garanti - confusion entre plusieurs certificats locaux possible, e.g. mongo et sqlite)
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let instance_id = enveloppe_privee.enveloppe_pub.get_common_name()?;
    let certificat = middleware.charger_enveloppe(
        &commande.certificat, None, None).await?;
    let certificat_instance_id = certificat.get_common_name()?;

    if certificat_instance_id.as_str() == instance_id {
        debug!("commande_rotation_certificat Recu commande de rotation de certificat MaitreDesCles local");
        // let public_keys = certificat.fingerprint_cert_publickeys()?;
        // let public_key = &public_keys[0];
        let public_key = certificat.certificat.public_key()?;

        let cle_secrete_chiffree_local = gestionnaire.handler_rechiffrage.get_cle_symmetrique_chiffree(&public_key)?;
        debug!("Cle secrete chiffree pour instance {}:\n local = {}", instance_id, cle_secrete_chiffree_local);

        // Sauvegarder la cle symmetrique
        let connexion = gestionnaire.ouvrir_connection(middleware, false);
        sauvegarder_cle_configuration(
            middleware, &connexion, "local",
            instance_id.as_str(), certificat.fingerprint()?.as_str(),
            cle_secrete_chiffree_local, None)?;

        Ok(Some(middleware.reponse_ok(None, None)?))
    } else {
        debug!("commande_rotation_certificat Recu commande de rotation de certificat MaitreDesCles tiers - skip");
        Ok(None)
    }
}

async fn commande_cle_symmetrique<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesSQLite)
    -> Result<Option<MessageMilleGrillesBufferDefault>, ErreurMaitreDesClesSqlite>
    where M: GenerateurMessages + ValidateurX509 + IsConfigNoeud
{
    debug!("commande_cle_symmetrique Consommer commande : {:?}", & m.type_message);
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

    let connexion = gestionnaire.ouvrir_connection(middleware, false);

    sauvegarder_cle_configuration(
        middleware, &connexion, "local",
        instance_id.as_str(), fingerprint, commande.cle.as_str(), None)?;

    // let cle_locale = doc! {
    //     "type": "local",
    //     "instance_id": instance_id,
    //     "fingerprint": fingerprint.as_str(),
    //     "cle": commande.cle.as_str(),
    // };

    debug!("commande_cle_symmetrique Inserer cle configuration locale {:?}", commande.cle);

    // let collection = middleware.get_collection(NOM_COLLECTION_CONFIGURATION)?;
    // collection.insert_one(cle_locale, None).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

pub async fn commande_dechiffrer_cle<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesSQLite)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages
{
    debug!("commande_dechiffrer_cle Dechiffrer cle {:?}", &m.message);
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
    let cle_rechiffree = chiffrer_asymmetrique_ed25519(&cle_secrete.0[..], &enveloppe_destinataire.certificat.public_key()?)?;
    let cle_rechiffree_str: String = multibase::encode(Base::Base64, cle_rechiffree);

    let cle_reponse = CommandeCleRechiffree { ok: true, cle: Some(cle_rechiffree_str) };

    Ok(Some(middleware.build_reponse(&cle_reponse)?.0))
}
