use log::{debug, error};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::BackupStarter;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{RolesCertificats, Securite, COMMANDE_AJOUTER_CLE_DOMAINES, COMMANDE_SAUVEGARDER_CLE, COMMANDE_TRANSFERT_CLE, COMMANDE_TRANSFERT_CLE_CA, DEFAULT_Q_TTL, DELEGATION_GLOBALE_PROPRIETAIRE};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, ConsommateurMessagesBus, GestionnaireBusMillegrilles, GestionnaireDomaineV2};
use millegrilles_common_rust::domaines_v2::{prepare_mongodb_domain_indexes, GestionnaireDomaineSimple};
use millegrilles_common_rust::error::{Error as CommonError, Error};
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::get_domaine_action;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, MiddlewareMessages};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{start_transaction_regular, MongoDao};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType, TypeMessageOut};
use millegrilles_common_rust::recepteur_messages::MessageValide;

use crate::constants::*;
use crate::maintenance::maintenance_ca;
use crate::maitredescles_mongodb::*;


#[derive(Clone)]
pub struct MaitreDesClesCaManager {}

impl MaitreDesClesCaManager {}

impl GestionnaireDomaineV2 for MaitreDesClesCaManager {
    fn get_collection_transactions(&self) -> Option<String> {
        Some(String::from(NOM_COLLECTION_TRANSACTIONS_CA))
    }

    fn get_collections_volatiles(&self) -> Result<Vec<String>, CommonError> {
        Ok(vec![String::from(NOM_COLLECTION_CA_CLES)])
    }
}

impl GestionnaireBusMillegrilles for MaitreDesClesCaManager {
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
        preparer_queues()
    }
}

#[async_trait]
impl ConsommateurMessagesBus for MaitreDesClesCaManager {
    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_requete(middleware, message).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_commande(middleware, message, self).await
    }

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_evenement(middleware, message).await
    }
}

#[async_trait]
impl AiguillageTransactions for MaitreDesClesCaManager {
    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
        -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction, session).await
    }
}

#[async_trait]
impl GestionnaireDomaineSimple for MaitreDesClesCaManager {
    async fn preparer_database_mongodb<M>(&self, middleware: &M) -> Result<(), CommonError>
    where
        M: MongoDao + ConfigMessages
    {
        if let Some(nom_collection_transactions) = self.get_collection_transactions() {
            prepare_mongodb_domain_indexes(middleware, nom_collection_transactions).await?;
            preparer_index_mongodb_ca(middleware).await?;
        }
        Ok(())
    }

    async fn traiter_cedule<M>(&self, middleware: &M, trigger: &MessageCedule) -> Result<(), CommonError>
    where
        M: MiddlewareMessages + BackupStarter + MongoDao
    {
        maintenance_ca(middleware, self, trigger).await
    }
}

fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();
    let mut rk_sauvegarder_cle = Vec::new();

    // RK 3.protege et 4.secure
    let requetes_protegees: Vec<&str> = vec![
        // REQUETE_CLES_NON_DECHIFFRABLES,
        REQUETE_CLES_NON_DECHIFFRABLES_V2,
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

    // Queue commande de sauvegarde de cle
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: String::from(format!("{}/sauvegarder", DOMAINE_NOM)),
            routing_keys: rk_sauvegarder_cle,
            ttl: None,
            durable: true,
            autodelete: false,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (DOMAINE_NOM.into(), Securite::L3Protege));

    queues
}

pub async fn preparer_index_mongodb_ca<M>(middleware: &M) -> Result<(), CommonError>
where M: MongoDao + ConfigMessages
{
    preparer_index_mongodb_custom(middleware, NOM_COLLECTION_CA_CLES, true).await
}

async fn consommer_requete<M>(middleware: &M, message: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
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

    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    let result = match domaine.as_str() {
        DOMAINE_NOM => {
            match action.as_str() {
                REQUETE_COMPTER_CLES_NON_DECHIFFRABLES => requete_compter_cles_non_dechiffrables_ca(middleware, message).await,
                // REQUETE_CLES_NON_DECHIFFRABLES => requete_cles_non_dechiffrables(middleware, message, &mut session).await,
                REQUETE_SYNCHRONISER_CLES => requete_synchronizer_cles(middleware, message, &mut session).await,
                REQUETE_CLES_NON_DECHIFFRABLES_V2 => requete_cles_non_dechiffrables_v2(middleware, message, &mut session).await,
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
    };

    match result {
        Ok(result) => {
            session.commit_transaction().await?;
            Ok(result)
        }
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)
        }
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValide, gestionnaire_ca: &MaitreDesClesCaManager)
                               -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: ConfigMessages + GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("consommer_commande {:?}", m.type_message);

    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    let (_, action) = get_domaine_action!(m.type_message);

    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    let result = if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Delegation proprietaire
        match action.as_str() {
            // Commandes standard
            COMMANDE_AJOUTER_CLE_DOMAINES => commande_ajouter_cle_domaines_ca(middleware, m, gestionnaire_ca, &mut session).await,
            COMMANDE_RESET_NON_DECHIFFRABLE => commande_reset_non_dechiffrable_ca(middleware, m, &mut session).await,

            // Commandes inconnues
            _ => Err(format!("maitredescles_ca.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else if m.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
        // Exchanges, serveur protege
        match action.as_str() {
            // Commandes standard
            COMMANDE_AJOUTER_CLE_DOMAINES => commande_ajouter_cle_domaines_ca(middleware, m, gestionnaire_ca, &mut session).await,
            COMMANDE_CONFIRMER_CLES_SUR_CA => commande_confirmer_cles_sur_ca(middleware, m, &mut session).await,
            COMMANDE_TRANSFERT_CLE_CA => commande_transfert_cle_ca(middleware, m, gestionnaire_ca, &mut session).await,

            // Commandes inconnues
            _ => Err(format!("maitredescles_ca.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else if m.certificat.verifier_exchanges(vec![Securite::L1Public, Securite::L2Prive])? {
        // Tous exchanges, serveur
        match action.as_str() {
            // Commandes standard
            COMMANDE_AJOUTER_CLE_DOMAINES => commande_ajouter_cle_domaines_ca(middleware, m, gestionnaire_ca, &mut session).await,

            // Commandes inconnues
            _ => Err(format!("maitredescles_ca.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else if role_prive == true && user_id.is_some() {
        // Usagers prives
        match action.as_str() {
            // Commandes standard
            COMMANDE_AJOUTER_CLE_DOMAINES => commande_ajouter_cle_domaines_ca(middleware, m, gestionnaire_ca, &mut session).await,

            // Commandes inconnues
            _ => Err(format!("maitredescles_ca.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
        }
    } else {
        Err(format!("maitredescles_ca.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?
    };

    match result {
        Ok(result) => {
            session.commit_transaction().await?;
            Ok(result)
        }
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)
        }
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

    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;

    let result = match action.as_str() {
        EVENEMENT_CLES_MANQUANTES_PARTITION => evenement_cle_manquante(middleware, &m, &mut session).await,
        EVENEMENT_CLE_RECUE_PARTITION => evenement_cle_recue_partition(middleware, &m, &mut session).await,
        _ => Err(format!("maitredescles_ca.consommer_transaction: Mauvais type d'action pour une transaction : {}", action))?,
    };

    match result {
        Ok(result) => {
            session.commit_transaction().await?;
            Ok(result)
        }
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)
        }
    }
}

async fn aiguillage_transaction<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession)
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
        TRANSACTION_CLE => transaction_cle(middleware, transaction, session).await,
        TRANSACTION_CLE_V2 => transaction_cle_v2(middleware, transaction, session).await,
        _ => Err(Error::String(format!("maitredescles.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.transaction.id, action))),
    }
}
