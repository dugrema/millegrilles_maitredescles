use std::collections::{HashMap, HashSet};
use std::str::from_utf8;
use std::sync::Arc;

use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{doc, DateTime, Document};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage_cle::{CommandeAjouterCleDomaine, CommandeSauvegarderCle};
use millegrilles_common_rust::{chrono, get_domaine_action, serde_json};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{sauvegarder_traiter_transaction, sauvegarder_traiter_transaction_serializable, Middleware};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, MongoDao};
use millegrilles_common_rust::mongodb::options::{CountOptions, FindOneOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{TraiterTransaction, Transaction};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::optionepochseconds;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::millegrilles_cryptographie::{deser_message_buffer, heapless};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::{optionformatchiffragestr, FormatChiffrage};
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::{SignatureDomaines, SignatureDomainesVersion};
use crate::constants::*;
use crate::maitredescles_commun::*;
use crate::maitredescles_mongodb::{commande_confirmer_cles_sur_ca, commande_reset_non_dechiffrable_ca, evenement_cle_manquante, evenement_cle_recue_partition, preparer_index_mongodb_custom, requete_cles_non_dechiffrables, requete_compter_cles_non_dechiffrables_ca, requete_synchronizer_cles, transaction_cle, transaction_cle_v2, NOM_COLLECTION_CA_CLES, NOM_COLLECTION_TRANSACTIONS};
use crate::messages::{RecupererCleCa, RequeteClesNonDechiffrable};
// pub const NOM_COLLECTION_CLES: &str = "MaitreDesCles/CA/cles";
// pub const NOM_COLLECTION_TRANSACTIONS: &str = "MaitreDesCles/CA";
//
// // const NOM_Q_VOLATILS_GLOBAL: &str = "MaitreDesCles/volatils";
// const NOM_Q_TRANSACTIONS: &str = "MaitreDesCles/CA/transactions";
// const NOM_Q_VOLATILS: &str = "MaitreDesCles/CA/volatils";
// const NOM_Q_TRIGGERS: &str = "MaitreDesCles/CA/triggers";
//
// const REQUETE_CLES_NON_DECHIFFRABLES: &str = "clesNonDechiffrables";
// const REQUETE_COMPTER_CLES_NON_DECHIFFRABLES: &str = "compterClesNonDechiffrables";
//
// const COMMANDE_RESET_NON_DECHIFFRABLE: &str = "resetNonDechiffrable";

#[derive(Clone, Debug)]
pub struct GestionnaireMaitreDesClesCa {
    pub fingerprint: String,
}

#[async_trait]
impl TraiterTransaction for GestionnaireMaitreDesClesCa {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireMaitreDesClesCa {
    fn get_nom_domaine(&self) -> String { String::from(DOMAINE_NOM) }

    fn get_collection_transactions(&self) -> Option<String> { Some(String::from(NOM_COLLECTION_TRANSACTIONS)) }

    fn get_collections_documents(&self) -> Result<Vec<String>, Error> { Ok(vec![String::from(NOM_COLLECTION_CA_CLES)]) }

    fn get_q_transactions(&self) -> Result<Option<String>, Error> { Ok(Some(String::from(NOM_Q_CA_TRANSACTIONS))) }

    fn get_q_volatils(&self) -> Result<Option<String>, Error> { Ok(Some(String::from(NOM_Q_CA_VOLATILS))) }

    fn get_q_triggers(&self) -> Result<Option<String>, Error> { Ok(Some(String::from(NOM_Q_CA_TRIGGERS))) }

    fn preparer_queues(&self) -> Result<Vec<QueueType>, Error> { Ok(preparer_queues()) }

    fn chiffrer_backup(&self) -> bool {
        false
    }

    async fn preparer_database<M>(&self, middleware: &M) -> Result<(), Error> where M: Middleware + 'static {
        preparer_index_mongodb_custom(middleware, NOM_COLLECTION_CA_CLES, true).await
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error> where M: Middleware + 'static {
        consommer_requete(middleware, message, &self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error> where M: Middleware + 'static {
        consommer_commande(middleware, message, &self).await
    }

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error> where M: Middleware + 'static {
        consommer_transaction(middleware, message, self).await
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error> where M: Middleware + 'static {
        consommer_evenement(middleware, message).await
    }

    async fn entretien<M>(self: &'static Self, middleware: Arc<M>) where M: Middleware + 'static {
        entretien(middleware).await
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule) -> Result<(), Error> where M: Middleware + 'static {
        traiter_cedule(middleware, trigger).await
    }

    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
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

    let mut rk_transactions = Vec::new();
    rk_transactions.push(ConfigRoutingExchange {
        routing_key: format!("transaction.{}.{}", DOMAINE_NOM, TRANSACTION_CLE).into(),
        exchange: Securite::L4Secure
    });

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

    // Queue de transactions
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_CA_TRANSACTIONS.into(),
            routing_keys: rk_transactions,
            ttl: None,
            durable: true,
            autodelete: false,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (DOMAINE_NOM.into(), Securite::L3Protege));

    queues
}

async fn consommer_requete<M>(middleware: &M, message: MessageValide, gestionnaire: &GestionnaireMaitreDesClesCa) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consommer requete {:?}", message.type_message);

    // Autorisation : On accepte les requetes de 3.protege ou 4.secure
    match message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        true => (),
        false => match message.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
            true => (),
            false => Err(Error::Str("Trigger cedule autorisation invalide (pas d'un exchange reconnu)"))?,
        }
    }

    let (domaine, action) = get_domaine_action!(message.type_message);

    match domaine.as_str() {
        DOMAINE_NOM => {
            match action.as_str() {
                REQUETE_COMPTER_CLES_NON_DECHIFFRABLES => requete_compter_cles_non_dechiffrables_ca(middleware, message).await,
                REQUETE_CLES_NON_DECHIFFRABLES => requete_cles_non_dechiffrables(middleware, message).await,
                REQUETE_SYNCHRONISER_CLES => requete_synchronizer_cles(middleware, message).await,
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

async fn consommer_evenement<M>(middleware: &M, m: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("maitredescles_ca.consommer_evenement Consommer evenement {:?}", m.type_message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
        true => Ok(()),
        false => Err(format!("maitredescles_ca.consommer_evenement: Evenement invalide (pas 3.protege ou 4.secure)")),
    }?;

    let (_, action) = get_domaine_action!(m.type_message);

    match action.as_str() {
        EVENEMENT_CLES_MANQUANTES_PARTITION => evenement_cle_manquante(middleware, &m).await,
        EVENEMENT_CLE_RECUE_PARTITION => evenement_cle_recue_partition(middleware, &m).await,
        _ => Err(format!("maitredescles_ca.consommer_transaction: Mauvais type d'action pour une transaction : {}", action))?,
    }
}


async fn consommer_transaction<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesCa) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("maitredescles_ca.consommer_transaction Consommer transaction {:?}", m.type_message);

    // Autorisation : doit etre de niveau 3.protege ou 4.secure
    match m.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
        true => Ok(()),
        false => Err(format!("maitredescles_ca.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure)")),
    }?;

    let (_, action) = get_domaine_action!(m.type_message);

    match action.as_str() {
        TRANSACTION_CLE  => {
            Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
        },
        _ => Err(format!("maitredescles_ca.consommer_transaction: Mauvais type d'action pour une transaction : {}", action))?,
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValide, gestionnaire_ca: &GestionnaireMaitreDesClesCa)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("consommer_commande {:?}", m.type_message);

    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    let (_, action) = get_domaine_action!(m.type_message);

    if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Delegation proprietaire
        match action.as_str() {
            // Commandes standard
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire_ca).await,
            COMMANDE_AJOUTER_CLE_DOMAINES => commande_ajouter_cle_domaines(middleware, m, gestionnaire_ca).await,
            COMMANDE_RESET_NON_DECHIFFRABLE => commande_reset_non_dechiffrable_ca(middleware, m).await,

            // Commandes inconnues
            _ => Err(format!("maitredescles_ca.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else if m.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
        // Exchanges, serveur protege
        match action.as_str() {
            // Commandes standard
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire_ca).await,
            COMMANDE_AJOUTER_CLE_DOMAINES => commande_ajouter_cle_domaines(middleware, m, gestionnaire_ca).await,
            COMMANDE_CONFIRMER_CLES_SUR_CA => commande_confirmer_cles_sur_ca(middleware, m).await,
            COMMANDE_TRANSFERT_CLE_CA => commande_transfert_cle_ca(middleware, m, gestionnaire_ca).await,

            // Commandes inconnues
            _ => Err(format!("maitredescles_ca.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else if m.certificat.verifier_exchanges(vec![Securite::L1Public, Securite::L2Prive])? {
        // Tous exchanges, serveur
        match action.as_str() {
            // Commandes standard
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire_ca).await,
            COMMANDE_AJOUTER_CLE_DOMAINES => commande_ajouter_cle_domaines(middleware, m, gestionnaire_ca).await,

            // Commandes inconnues
            _ => Err(format!("maitredescles_ca.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else if role_prive == true && user_id.is_some() {
        // Usagers prives
        match action.as_str() {
            // Commandes standard
            COMMANDE_SAUVEGARDER_CLE => commande_sauvegarder_cle(middleware, m, gestionnaire_ca).await,
            COMMANDE_AJOUTER_CLE_DOMAINES => commande_ajouter_cle_domaines(middleware, m, gestionnaire_ca).await,

            // Commandes inconnues
            _ => Err(format!("maitredescles_ca.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else {
        Err(format!("maitredescles_ca.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?
    }

}

async fn commande_sauvegarder_cle<M>(middleware: &M, m: MessageValide, gestionnaire_ca: &GestionnaireMaitreDesClesCa)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    error!("sauvegarder_cle Recu cle ancien format, **REJETE**\n{}", from_utf8(m.message.buffer.as_slice())?);
    Ok(Some(middleware.reponse_err(99, None, Some("Commande sauvegarderCle obsolete et retiree"))?))
    // debug!("commande_sauvegarder_cle Consommer commande : {:?}", & m.type_message);
    // let commande: CommandeSauvegarderCle = deser_message_buffer!(m.message);
    //
    // let fingerprint = gestionnaire_ca.fingerprint.as_str();
    // let mut doc_bson: Document = commande.clone().into();
    //
    // // // Sauvegarder pour partition CA, on retire la partition recue
    // // let _ = doc_bson.remove("partition");
    //
    // // Retirer cles, on re-insere la cle necessaire uniquement
    // doc_bson.remove("cles");
    //
    // let cle = match commande.cles.get(fingerprint) {
    //     Some(cle) => cle.as_str(),
    //     None => {
    //         let message = format!("maitredescles_ca.commande_sauvegarder_cle: Erreur validation - commande sauvegarder cles ne contient pas la cle CA ({}) : {:?}", fingerprint, commande);
    //         warn!("{}", message);
    //         // let reponse_err = json!({"ok": false, "err": message});
    //         // return Ok(Some(middleware.formatter_reponse(&reponse_err, None)?));
    //         return Ok(Some(middleware.reponse_err(None, None, Some(message.as_str()))?))
    //     }
    // };
    //
    // doc_bson.insert("dirty", true);
    // doc_bson.insert("cle", cle);
    // doc_bson.insert(CHAMP_CREATION, Utc::now());
    // doc_bson.insert(CHAMP_MODIFICATION, Utc::now());
    //
    // let nb_cles = commande.cles.len();
    // let non_dechiffrable = nb_cles < 2;
    // debug!("commande_sauvegarder_cle: On a recu {} cles, non-dechiffables (presume) : {}", nb_cles, non_dechiffrable);
    // doc_bson.insert("non_dechiffrable", non_dechiffrable);
    //
    // let mut ops = doc! { "$setOnInsert": doc_bson };
    //
    // debug!("commande_sauvegarder_cle: Ops bson : {:?}", ops);
    //
    // let filtre = doc! { "hachage_bytes": &commande.hachage_bytes, "domaine": &commande.domaine };
    // let opts = UpdateOptions::builder().upsert(true).build();
    //
    // let collection = middleware.get_collection(NOM_COLLECTION_CLES)?;
    // let resultat = collection.update_one(filtre, ops, opts).await?;
    // debug!("commande_sauvegarder_cle Resultat update : {:?}", resultat);
    //
    // if let Some(uid) = resultat.upserted_id {
    //     debug!("commande_sauvegarder_cle Nouvelle cle insere _id: {}, generer transaction", uid);
    //     let transaction = TransactionCle::new_from_commande(&commande, fingerprint)?;
    //     // let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_CLE, vec![Securite::L4Secure])
    //     //     .blocking(false)
    //     //     .build();
    //     // middleware.soumettre_transaction(routage, &transaction).await?;
    //     sauvegarder_traiter_transaction_serializable(
    //         middleware, &transaction, gestionnaire_ca, DOMAINE_NOM, TRANSACTION_CLE).await?;
    // }
    //
    // Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn commande_ajouter_cle_domaines<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesCa)
                                          -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_ajouter_cle_domaines Consommer commande : {:?}", &m.type_message);
    let commande: CommandeAjouterCleDomaine = deser_message_buffer!(m.message);

    // Verifier si on a deja la cle - sinon, creer une nouvelle transaction
    let cle_id = commande.signature.get_cle_ref()?.to_string();

    let filtre = doc! { CHAMP_CLE_ID: &cle_id };
    let options = FindOneOptions::builder()
        .hint(Hint::Name("index_cle_id".to_string()))
        .projection(doc!{CHAMP_CLE_ID: 1})
        .build();
    let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
    let resultat = collection.find_one(filtre, options).await?;

    if resultat.is_none() {
        let transaction_cle = TransactionCleV2 { signature: commande.signature };
        debug!("commande_ajouter_cle_domaines Sauvegarder transaction nouvelle cle {}", cle_id);
        sauvegarder_traiter_transaction_serializable(
            middleware, &transaction_cle, gestionnaire, DOMAINE_NOM, TRANSACTION_CLE_V2).await?;
    }

    // Confirmer le traitement de la cle
    Ok(Some(middleware.reponse_ok(None, None)?))
}

async fn commande_transfert_cle_ca<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireMaitreDesClesCa)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_transfert_cle Consommer commande : {:?}", &m.type_message);
    if !m.certificat.verifier_exchanges(vec![Securite::L3Protege])? ||
        !m.certificat.verifier_roles(vec![RolesCertificats::MaitreDesCles])?
    {
        Err(Error::Str("commande_transfert_cle Exchange/Role non autorise"))?
    }
    let commande: CommandeTransfertClesCaV2 = deser_message_buffer!(m.message);

    for cle in commande.cles {
        // Verifier si on a deja la cle - sinon, creer une nouvelle transaction
        let cle_id = cle.signature.get_cle_ref()?.to_string();

        let filtre = doc! { CHAMP_CLE_ID: &cle_id };
        let options = FindOneOptions::builder()
            .hint(Hint::Name("index_cle_id".to_string()))
            .projection(doc! {CHAMP_CLE_ID: 1})
            .build();
        let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
        let resultat = collection.find_one(filtre, options).await?;

        if resultat.is_none() {
            match cle.signature.version {
                SignatureDomainesVersion::NonSigne => {
                    // Ancienne version
                    let cle_id = cle.signature.signature.to_string();

                    let cle_ca = match cle.signature.ca.as_ref() {
                        Some(inner) => format!("m{}", inner),  // Ajoute 'm' multibase base64 no pad
                        None => Err(Error::Str("commande_transfert_cle Cle pour le CA manquante"))?
                    };

                    let domaine = match cle.signature.domaines.get(0) {
                        Some(inner) => inner.to_string(),
                        None => Err(Error::Str("Domaine manquant"))?
                    };

                    debug!("commande_transfert_cle Sauvegarder cle transferee {}", cle_id);
                    let transaction_cle = TransactionCle {
                        hachage_bytes: cle_id,
                        domaine,
                        identificateurs_document: Default::default(),
                        cle: cle_ca,
                        format: cle.format.clone(),
                        iv: None,
                        tag: cle.verification.clone(),
                        header: cle.nonce.clone(),
                        partition: None,
                    };
                    sauvegarder_traiter_transaction_serializable(
                        middleware, &transaction_cle, gestionnaire, DOMAINE_NOM, TRANSACTION_CLE).await?;
                },
                _ => {
                    // Version courante
                    let transaction_cle = TransactionCleV2 { signature: cle.signature.clone() };
                    debug!("commande_ajouter_cle_domaines Sauvegarder transaction nouvelle cle {}", cle_id);
                    sauvegarder_traiter_transaction_serializable(
                        middleware, &transaction_cle, gestionnaire, DOMAINE_NOM, TRANSACTION_CLE_V2).await?;
                }
            }
        }
    }

    Ok(None)
}

async fn aiguillage_transaction<M>(middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let routage = match transaction.transaction.routage.as_ref() {
        Some(inner) => inner,
        None => Err(Error::Str("aiguillage_transaction Transaction sans routage"))?
    };

    let action = match routage.action.as_ref() {
        Some(inner) => inner.as_str(),
        None => Err(format!("core_backup.aiguillage_transaction: Transaction {:?} n'a pas d'action", routage))?
    };

    match action {
        TRANSACTION_CLE => transaction_cle(middleware, transaction).await,
        TRANSACTION_CLE_V2 => transaction_cle_v2(middleware, transaction).await,
        _ => Err(Error::String(format!("maitredescles.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.transaction.id, action))),
    }
}

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
//     async fn test_requete_compte_non_dechiffrable() {
//         setup("test_requete_compte_non_dechiffrable");
//         let (middleware, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
//         let enveloppe_privee = middleware.get_enveloppe_privee();
//         let fingerprint = enveloppe_privee.fingerprint().as_str();
//
//         let gestionnaire = GestionnaireMaitreDesClesCa {fingerprint: fingerprint.into()};
//         futures.push(tokio::spawn(async move {
//
//             let contenu = json!({});
//             let message_mg = MessageMilleGrillesBufferDefault::new_signer(
//                 enveloppe_privee.as_ref(),
//                 &contenu,
//                 DOMAINE_NOM.into(),
//                 REQUETE_COMPTER_CLES_NON_DECHIFFRABLES.into(),
//                 None::<&str>,
//                 None
//             ).expect("message");
//             let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");
//
//             // Injecter certificat utilise pour signer
//             message.certificat = Some(enveloppe_privee.enveloppe.clone());
//
//             let mva = MessageValide::new(
//                 message, "dummy_q", "routing_key", "domaine", "action", TypeMessageOut::Requete);
//
//             let reponse = requete_compter_cles_non_dechiffrables(middleware.as_ref(), mva, &gestionnaire).await.expect("dechiffrage");
//             debug!("Reponse requete compte cles non dechiffrables : {:?}", reponse);
//
//         }));
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
//
//     #[tokio::test]
//     async fn test_requete_cles_non_dechiffrable() {
//         setup("test_requete_cles_non_dechiffrable");
//         let (middleware, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
//         let enveloppe_privee = middleware.get_enveloppe_privee();
//         let fingerprint = enveloppe_privee.fingerprint().as_str();
//
//         let gestionnaire = GestionnaireMaitreDesClesCa {fingerprint: fingerprint.into()};
//         futures.push(tokio::spawn(async move {
//
//             let contenu = json!({
//                 "limite": 5,
//                 "page": 0,
//             });
//             let message_mg = MessageMilleGrillesBufferDefault::new_signer(
//                 enveloppe_privee.as_ref(),
//                 &contenu,
//                 DOMAINE_NOM.into(),
//                 REQUETE_COMPTER_CLES_NON_DECHIFFRABLES.into(),
//                 None::<&str>,
//                 None
//             ).expect("message");
//             let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");
//
//             // Injecter certificat utilise pour signer
//             message.certificat = Some(enveloppe_privee.enveloppe.clone());
//
//             let mva = MessageValide::new(
//                 message, "dummy_q", "routing_key", "domaine", "action", TypeMessageOut::Requete);
//
//             let reponse = requete_cles_non_dechiffrables(middleware.as_ref(), mva, &gestionnaire).await.expect("dechiffrage");
//             debug!("Reponse requete compte cles non dechiffrables : {:?}", reponse);
//
//         }));
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
//
//     #[tokio::test]
//     async fn test_requete_synchronizer_cles() {
//         setup("test_requete_synchronizer_cles");
//         let (middleware, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
//         let enveloppe_privee = middleware.get_enveloppe_privee();
//         let fingerprint = enveloppe_privee.fingerprint().as_str();
//
//         let gestionnaire = GestionnaireMaitreDesClesCa {fingerprint: fingerprint.into()};
//         futures.push(tokio::spawn(async move {
//
//             let contenu = json!({
//                 "limite": 5,
//                 "page": 0,
//             });
//             let message_mg = MessageMilleGrillesBufferDefault::new_signer(
//                 enveloppe_privee.as_ref(),
//                 &contenu,
//                 DOMAINE_NOM.into(),
//                 REQUETE_COMPTER_CLES_NON_DECHIFFRABLES.into(),
//                 None::<&str>,
//                 None
//             ).expect("message");
//             let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");
//
//             // Injecter certificat utilise pour signer
//             message.certificat = Some(enveloppe_privee.enveloppe.clone());
//
//             let mva = MessageValide::new(
//                 message, "dummy_q", "routing_key", "domaine", "action", TypeMessageOut::Requete);
//
//             let reponse = requete_synchronizer_cles(middleware.as_ref(), mva, &gestionnaire).await.expect("dechiffrage");
//             debug!("test_requete_synchronizer_cles Reponse : {:?}", reponse);
//
//         }));
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
// }
