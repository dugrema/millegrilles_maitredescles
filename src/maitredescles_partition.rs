use std::alloc::handle_alloc_error;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter, Write};
use std::fs::read_dir;
use std::str::from_utf8;
use std::sync::{Arc, Mutex};

use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::base64::{engine::general_purpose::STANDARD_NO_PAD as base64_nopad, Engine as _};
use millegrilles_common_rust::multibase::Base;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage_cle::{CleChiffrageCache, CommandeAjouterCleDomaine, CommandeSauvegarderCle};
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::common_messages::{ReponseRequeteDechiffrageV2, RequeteDechiffrage, RequeteDechiffrageMessage, ResponseRequestDechiffrageV2Cle};
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::futures_util::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::hachages::hacher_bytes;
use millegrilles_common_rust::messages_generiques::{CommandeCleRechiffree, CommandeDechiffrerCle, MessageCedule};
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction_serializable, sauvegarder_transaction, Middleware};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, verifier_erreur_duplication_mongo, ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::mongodb::{Collection, Cursor};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions, FindOptions, Hint, InsertOneOptions, UpdateOptions};
use millegrilles_common_rust::{get_domaine_action, millegrilles_cryptographie, multibase, serde_json};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::{CleChiffrageHandler, CleDechiffrage, CleSecreteSerialisee};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::millegrilles_cryptographie::x509::{EnveloppeCertificat, EnveloppePrivee};
use millegrilles_common_rust::multihash::Code;
use millegrilles_common_rust::openssl::pkey::{PKey, Private};
use millegrilles_common_rust::openssl::rsa::Rsa;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, NamedQueue, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio::fs::File as File_tokio;
use millegrilles_common_rust::tokio::{io::AsyncReadExt, spawn};
use millegrilles_common_rust::tokio::time::{sleep, Duration as Duration_tokio};
use millegrilles_common_rust::tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{marquer_transaction, EtatTransaction, TraiterTransaction, Transaction};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::millegrilles_cryptographie::{deser_message_buffer, heapless};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::FormatChiffrage;
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::{SignatureDomaines, SignatureDomainesVersion};
use millegrilles_common_rust::millegrilles_cryptographie::x25519::{chiffrer_asymmetrique_ed25519, dechiffrer_asymmetrique_ed25519, CleSecreteX25519};
use crate::commands::{commande_dechiffrer_cle, commande_verifier_cle_symmetrique};
use crate::maitredescles_ca::{GestionnaireMaitreDesClesCa};

use crate::constants::*;
use crate::maitredescles_commun::*;
use crate::maitredescles_mongodb::{commande_ajouter_cle_domaines, commande_cle_symmetrique, commande_rechiffrer_batch, commande_rotation_certificat, commande_transfert_cle, confirmer_cles_ca, evenement_cle_rechiffrage, preparer_index_mongodb_custom, preparer_index_mongodb_partition, preparer_rechiffreur_mongo, requete_dechiffrage_v2, requete_transfert_cles, sauvegarder_cle_rechiffrage, sauvegarder_cle_secrete, sauvegarder_cle_transfert, synchroniser_cles, NOM_COLLECTION_CA_CLES};
use crate::maitredescles_rechiffrage::{CleInterneChiffree, HandlerCleRechiffrage};
use crate::messages::{MessageReponseChiffree, RequeteVerifierPreuve};
use crate::requests::{requete_certificat_maitredescles, requete_dechiffrage_message};

pub struct GestionnaireMaitreDesClesPartition {
    pub handler_rechiffrage: Arc<HandlerCleRechiffrage>,
    pub ressources: Mutex<Option<Arc<GestionnaireRessources>>>,
}

impl Debug for GestionnaireMaitreDesClesPartition {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.handler_rechiffrage.fingerprint() {
            Ok(fingerprint) => f.write_str(format!("GestionnaireMaitreDesClesPartition {}", fingerprint).as_str()),
            Err(_) => f.write_str("GestionnaireMaitreDesClesPartition Erreur calcul fingerprint")
        }
    }
}

impl Clone for GestionnaireMaitreDesClesPartition {
    fn clone(&self) -> Self {
        Self {
            handler_rechiffrage: self.handler_rechiffrage.clone(),
            ressources: Mutex::new(self.ressources.lock().expect("lock").clone())
        }
    }
}

impl GestionnaireMaitreDesClesPartition {

    pub fn new(handler_rechiffrage: HandlerCleRechiffrage) -> Self {
        Self { handler_rechiffrage: Arc::new(handler_rechiffrage), ressources: Mutex::new(None) }
    }

    /// Retourne une version tronquee du nom de partition
    /// Utilise pour nommer certaines ressources (e.g. collections Mongo)
    pub fn get_partition_tronquee(&self) -> Result<Option<String>, Error> {
        let fingerprint = self.handler_rechiffrage.fingerprint()?;
        Ok(Some(String::from(&fingerprint[35..])))
    }

    pub fn get_q_sauvegarder_cle(&self) -> Result<Option<String>, Error> {
        let fingerprint = self.handler_rechiffrage.fingerprint()?;
        Ok(Some(format!("MaitreDesCles/{}/sauvegarder", fingerprint)))
    }

    pub fn get_collection_cles(&self) -> Result<Option<String>, Error> {
        match self.get_partition_tronquee()? {
            Some(p) => Ok(Some("MaitreDesCles/cles".to_string())),
            None => Ok(None)
        }
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

    pub async fn emettre_certificat_maitredescles<M>(&self, middleware: &M, m: Option<MessageValide>) -> Result<(), Error>
        where M: GenerateurMessages + MongoDao
    {
        if self.handler_rechiffrage.is_ready() {
            emettre_certificat_maitredescles(middleware, m).await
        } else {
            Ok(())
        }
    }

    /// Preparer les Qs une fois le certificat pret
    pub fn preparer_queues_rechiffrage(&self) -> Result<Vec<QueueType>, Error> {
        let mut rk_dechiffrage = Vec::new();
        let mut rk_commande_cle = Vec::new();
        let mut rk_volatils = Vec::new();

        let dechiffrer = if let Ok(v) = std::env::var("DESACTIVER_DECHIFFRAGE") {
            info!("Desactiver rechiffrage public/prive/protege");
            false
        } else {
            true
        };

        let fingerprint = self.handler_rechiffrage.fingerprint()?;

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
        if let Some(nom_queue) = self.get_q_sauvegarder_cle()? {
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
        if let Some(nom_queue) = self.get_q_volatils()? {
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
}

#[async_trait]
impl TraiterTransaction for GestionnaireMaitreDesClesPartition {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction, self).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireMaitreDesClesPartition {
    fn get_nom_domaine(&self) -> String { String::from(DOMAINE_NOM) }

    fn get_partition(&self) -> Result<Option<String>, Error> {
        Ok(Some(self.handler_rechiffrage.fingerprint()?))
    }

    fn get_collection_transactions(&self) -> Option<String> {
        // Aucunes transactions pour un maitre des cles autre que CA
        None
    }

    fn get_collections_documents(&self) -> Result<Vec<String>, Error> {
        // Utiliser le nom de la partition tronquee - evite que les noms de collections deviennent
        // trop long (cause un probleme lors de la creation d'index, max 127 chars sur path)
        match self.get_partition_tronquee()? {
            Some(p) => Ok(vec![format!("MaitreDesCles/{}/cles", p)]),
            None => Ok(vec![])
        }
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

        Ok(queues)
    }

    async fn preparer_database<M>(&self, middleware: &M) -> Result<(), Error>
        where M: Middleware + 'static
    {
        if let Some(nom_collection_cles) = self.get_collection_cles()? {
            debug!("preparer_database Ajouter index pour collection {}", nom_collection_cles);
            preparer_index_mongodb_custom(middleware, nom_collection_cles.as_str(), false).await?;
            preparer_index_mongodb_partition(middleware).await?;
        } else {
            debug!("preparer_database Aucun fingerprint / partition");
        }
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
        let mut q_preparation_completee = false;
        loop {
            if !self.handler_rechiffrage.is_ready() || q_preparation_completee == false {

                if q_preparation_completee == true {
                    panic!("handler rechiffrage is_ready() == false et q_preparation_completee == true");
                }

                info!("entretien_rechiffreur Aucun certificat configure, on demande de generer un certificat volatil");
                let resultat = match preparer_rechiffreur_mongo(
                    middleware.as_ref(), self.handler_rechiffrage.as_ref()).await {
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
                    // Preparer la collection avec index
                    self.preparer_database(middleware.as_ref()).await.expect("preparer_database");

                    let queues = self.preparer_queues_rechiffrage().expect("queues");
                    for queue in queues {

                        let queue_name = match &queue {
                            QueueType::ExchangeQueue(q) => q.nom_queue.clone(),
                            QueueType::ReplyQueue(_) => { continue },
                            QueueType::Triggers(d,s) => format!("{}.{:?}", d, s)
                        };

                        // Creer thread de traitement
                        let (tx, rx) = mpsc::channel::<TypeMessage>(1);
                        let mut futures_consumer = FuturesUnordered::new();
                        futures_consumer.push(spawn(self.consommer_messages(middleware.clone(), rx)));

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
            sleep(Duration_tokio::new(30, 0)).await;
        }
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule) -> Result<(), Error> where M: Middleware + 'static {
        traiter_cedule(middleware, trigger).await
    }

    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction, self).await
    }
}


async fn consommer_requete<M>(middleware: &M, message: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
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
                REQUETE_DECHIFFRAGE => requete_dechiffrage(middleware, message, gestionnaire).await,
                REQUETE_DECHIFFRAGE_V2 => requete_dechiffrage_v2(middleware, message, &gestionnaire.handler_rechiffrage).await,
                MAITREDESCLES_REQUETE_DECHIFFRAGE_MESSAGE => requete_dechiffrage_message(middleware, message).await,
                REQUETE_VERIFIER_PREUVE => requete_verifier_preuve(middleware, message, gestionnaire).await,
                REQUETE_TRANSFERT_CLES => requete_transfert_cles(middleware, message, &gestionnaire.handler_rechiffrage).await,
                EVENEMENT_CLES_MANQUANTES_PARTITION => evenement_cle_manquante(middleware, message, gestionnaire).await,
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

async fn consommer_transaction<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    Err(format!("maitredescles_ca.consommer_transaction: Aucun type de transactions n'est supporte par partition. Recu : {:?}", m.type_message))?
}

async fn consommer_evenement<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition, m: MessageValide)
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
        EVENEMENT_CLES_MANQUANTES_PARTITION => evenement_cle_manquante(middleware, m, gestionnaire).await,
        EVENEMENT_CLES_RECHIFFRAGE => evenement_cle_rechiffrage(middleware, m, &gestionnaire.handler_rechiffrage).await,
        _ => Err(format!("consommer_evenement: Mauvais type d'action pour un evenement : {}", action))?,
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
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
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire).await,
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
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire).await,
            COMMANDE_AJOUTER_CLE_DOMAINES => commande_ajouter_cle_domaines(middleware, m, &gestionnaire.handler_rechiffrage).await,
            COMMANDE_CERT_MAITREDESCLES => {emettre_certificat_maitredescles(middleware, Some(m)).await?; Ok(None)},
            // Commandes inconnues
            _ => Err(format!("maitredescles_partition.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else if m.certificat.verifier_exchanges(vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])? {
        match action.as_str() {
            // Commandes standard
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire).await,
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

async fn commande_sauvegarder_cle<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + CleChiffrageHandler
{
    error!("sauvegarder_cle Recu cle ancien format, **REJETE**\n{}", from_utf8(m.message.buffer.as_slice())?);
    Ok(Some(middleware.reponse_err(99, None, Some("Commande sauvegarderCle obsolete et retiree"))?))
}

async fn aiguillage_transaction<M>(middleware: &M, transaction: TransactionValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let action = match transaction.transaction.routage.as_ref() {
        Some(inner) => match inner.action.as_ref() {
            Some(inner) => inner.clone(),
            None => Err(Error::String(format!("core_backup.aiguillage_transaction: Transaction {} n'a pas d'action", transaction.transaction.id)))?
        },
        None => Err(Error::String(format!("core_backup.aiguillage_transaction: Transaction {} n'a pas de routage", transaction.transaction.id)))?
    };

    match action {
        _ => Err(Error::String(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.transaction.id, action))),
    }
}

async fn requete_dechiffrage<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + CleChiffrageHandler
{
    warn!("requete_dechiffrage Consommer requete OBSOLETE : {:?}", & m.message);
    Ok(Some(middleware.reponse_err(99, None, Some("obsolete"))?))
}

/// Verifie que la requete contient des cles secretes qui correspondent aux cles stockees.
/// Confirme que le demandeur a bien en sa possession (via methode tierce) les cles secretes.
async fn requete_verifier_preuve<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao +  ValidateurX509 + CleChiffrageHandler
{
    let reponse = middleware.reponse_err(None, None, Some("Obsolete"))?;
    Ok(Some(reponse))

    // let nom_collection = match gestionnaire.get_collection_cles()? {
    //     Some(n) => n,
    //     None => Err(Error::Str("maitredescles_partition.requete_verifier_preuve Collection cles n'est pas definie"))?
    // };
    //
    // debug!("requete_verifier_preuve Consommer requete : {:?}", & m.message);
    // let message_ref = m.message.parse()?;
    // let requete: RequeteVerifierPreuve = message_ref.contenu()?.deserialize()?;
    // debug!("requete_verifier_preuve cle parsed : {:?}", requete);
    //
    // let certificat = m.certificat.as_ref();
    // let extensions = certificat.extensions()?;
    // let domaines = match extensions.domaines {
    //     Some(inner) => inner,
    //     None => Err(Error::Str("maitredescles_partition.requete_verifier_preuve Certificat sans domaines"))?
    // };
    //
    // // La preuve doit etre recente (moins de 5 minutes)
    // let date_now = Utc::now();
    // let date_valid_min = date_now - Duration::minutes(5);  // Expiration
    // let date_valid_max = date_now + Duration::minutes(2);  // Futur - systime sync issue
    // {
    //     let datetime_estampille = &message_ref.estampille;
    //     // let datetime_estampille = estampille.get_datetime();
    //     if &date_valid_min > datetime_estampille || &date_valid_max < datetime_estampille {
    //         Err(format!("maitredescles_partition.requete_verifier_preuve Demande preuve est expiree ({:?})", datetime_estampille))?;
    //     }
    // }
    //
    // let enveloppe_privee = middleware.get_enveloppe_signature();
    //
    // // Preparer une liste de verification pour chaque cle par hachage_bytes
    // let mut map_validite_fuuid = HashMap::new();  // fuuid = valide(true/false)
    // let mut liste_hachage_bytes = Vec::new();
    // for (cle, _) in requete.preuves.iter() {
    //     map_validite_fuuid.insert(cle.clone(), false);
    //     liste_hachage_bytes.push(cle);
    // }
    //
    // // Trouver les cles en reference
    // let filtre = doc! {
    //     "domaine": {"$in": domaines},
    //     CHAMP_HACHAGE_BYTES: {"$in": liste_hachage_bytes}
    // };
    // debug!("requete_verifier_preuve Filtre cles sur collection {} : {:?}", nom_collection, filtre);
    //
    // let collection = middleware.get_collection_typed::<RowClePartition>(nom_collection.as_str())?;
    // let mut curseur = collection.find(filtre, None).await?;
    //
    // let cle_privee = &enveloppe_privee.cle_privee;
    // while let Some(rc) = curseur.next().await {
    //     let cle_mongo_chiffree = rc?;
    //
    //     let cle_interne_chiffree = CleInterneChiffree::try_from(cle_mongo_chiffree.clone())?;
    //     let cle_mongo_dechiffree = gestionnaire.handler_rechiffrage.dechiffer_cle_secrete(cle_interne_chiffree)?;
    //     // let cle_mongo_dechiffree = extraire_cle_secrete(cle_privee, cle_mongo_chiffree.cle.as_str())?;
    //     todo!("fix me")
    //     // let hachage_bytes_mongo = cle_mongo_chiffree.hachage_bytes.as_str();
    //     //
    //     // debug!("requete_verifier_preuve Resultat mongo hachage_bytes {}", hachage_bytes_mongo);
    //     //
    //     // if let Some(cle_preuve) = requete.preuves.get(hachage_bytes_mongo) {
    //     //     let date_preuve = cle_preuve.date;
    //     //     if &date_valid_min > &date_preuve || &date_valid_max < &date_preuve {
    //     //         warn!("requete_verifier_preuve Date preuve {} invalide : {:?}", hachage_bytes_mongo, date_preuve);
    //     //         continue;  // Skip
    //     //     }
    //     //
    //     //     // Valider la preuve (hachage)
    //     //     let valide = match cle_preuve.verifier_preuve(requete.fingerprint.as_str(), &cle_mongo_dechiffree) {
    //     //         Ok(inner) => inner,
    //     //         Err(e) => {
    //     //             error!("Erreur verification preuve : {:?}", e);
    //     //             false
    //     //         }
    //     //     };
    //     //
    //     //     map_validite_fuuid.insert(hachage_bytes_mongo.to_string(), valide);
    //     // }
    // }
    //
    // debug!("Resultat verification preuve : {:?}", map_validite_fuuid);
    //
    // // // Verifier toutes les cles qui n'ont pas ete identifiees dans la base de donnees (inconnues)
    // // let liste_inconnues: Vec<String> = liste_verification.iter().filter(|(k, v)| match v {
    // //     Some(_) => false,
    // //     None => true
    // // }).map(|(k,_)| k.to_owned()).collect();
    // // for hachage_bytes in liste_inconnues.into_iter() {
    // //     if let Some(info_cle) = map_hachage_bytes.remove(&hachage_bytes) {
    // //         debug!("requete_verifier_preuve Conserver nouvelle cle {}", hachage_bytes);
    // //
    // //         todo!("Fix me");
    // //         // let commande_cle = rechiffrer_pour_maitredescles(middleware, &info_cle)?;
    // //         //
    // //         // // Conserver la cle via commande
    // //         // let partition = gestionnaire.fingerprint.as_str();
    // //         // let routage = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_SAUVEGARDER_CLE)
    // //         //     .partition(partition)
    // //         //     .build();
    // //         // // Conserver la cle
    // //         // // let commande_cle = info_cle.into_commande(partition);
    // //         // // Transmettre commande de sauvegarde - on n'attend pas la reponse (deadlock)
    // //         // middleware.transmettre_commande(routage, &commande_cle, false).await?;
    // //         //
    // //         // // Indiquer que la cle est autorisee (c'est l'usager qui vient de la pousser)
    // //         // liste_verification.insert(hachage_bytes, Some(true));
    // //     }
    // // }
    //
    // // Preparer la reponse
    // let reponse_json = json!({
    //     "verification": map_validite_fuuid,
    // });
    // let reponse = middleware.build_reponse(reponse_json)?.0;
    //
    // Ok(Some(reponse))
}

// async fn rechiffrer_cles<M>(
//     _middleware: &M,
//     gestionnaire: &GestionnaireMaitreDesClesPartition,
//     _m: &MessageValide,
//     _requete: &RequeteDechiffrage,
//     enveloppe_privee: Arc<EnveloppePrivee>,
//     certificat: &EnveloppeCertificat,
//     _requete_autorisee_globalement: bool,
//     // _permission: Option<EnveloppePermission>,
//     curseur: &mut Cursor<Document>
// )
//     -> Result<(HashMap<String, RowClePartition>, bool), Error>
//     where M: ValidateurX509
// {
//     let mut cles: HashMap<String, RowClePartition> = HashMap::new();
//     let mut cles_trouvees = false;  // Flag pour dire qu'on a matche au moins 1 cle
//
//     let rechiffreur = &gestionnaire.handler_rechiffrage;
//
//     while let Some(rc) = curseur.next().await {
//         debug!("rechiffrer_cles document {:?}", rc);
//         cles_trouvees = true;  // On a trouve au moins une cle
//         match rc {
//             Ok(doc_cle) => {
//                 let mut cle: RowClePartition = match convertir_bson_deserializable(doc_cle) {
//                     Ok(c) => c,
//                     Err(e) => {
//                         error!("rechiffrer_cles Erreur conversion bson vers TransactionCle : {:?}", e);
//                         continue
//                     }
//                 };
//                 todo!("fix me")
//                 // let hachage_bytes = cle.hachage_bytes.clone();
//                 //
//                 // // match rechiffrer_cle(&mut cle, enveloppe_privee.as_ref(), certificat) {
//                 // match rechiffrer_cle(&mut cle, rechiffreur, certificat) {
//                 //     Ok(()) => {
//                 //         cles.insert(hachage_bytes, cle);
//                 //     },
//                 //     Err(e) => {
//                 //         error!("rechiffrer_cles Erreur rechiffrage cle {:?}", e);
//                 //         continue;  // Skip cette cle
//                 //     }
//                 // }
//             },
//             Err(e) => error!("rechiffrer_cles: Erreur lecture curseur cle : {:?}", e)
//         }
//     }
//
//     Ok((cles, cles_trouvees))
// }

// /// Prepare le curseur sur les cles demandees
// async fn preparer_curseur_cles<M>(
//     middleware: &M,
//     gestionnaire: &GestionnaireMaitreDesClesPartition,
//     requete: &RequeteDechiffrage,
//     // permission: Option<&EnveloppePermission>,
//     domaines_permis: Option<&Vec<String>>
// )
//     -> Result<Cursor<Document>, Error>
//     where M: MongoDao
// {
//     let nom_collection = match gestionnaire.get_collection_cles()? {
//         Some(n) => n,
//         None => Err(Error::Str("maitredescles_partition.preparer_curseur_cles Collection cles n'est pas definie"))?
//     };
//
//     // if permission.is_some() {
//     //     Err(format!("Permission non supporte - FIX ME"))?;
//     // }
//
//     let mut filtre = doc! {CHAMP_HACHAGE_BYTES: {"$in": &requete.liste_hachage_bytes}};
//     if let Some(d) = domaines_permis {
//         filtre.insert("domaine", doc!{"$in": d});
//     }
//     debug!("requete_dechiffrage Filtre cles sur collection {} : {:?}", nom_collection, filtre);
//
//     let collection = middleware.get_collection(nom_collection.as_str())?;
//     Ok(collection.find(filtre, None).await?)
// }

async fn evenement_cle_manquante<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesPartition)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler + CleChiffrageCache + ConfigMessages
{
    error!("evenement_cle_manquante Evenement obsolete");
    Ok(None)
}

