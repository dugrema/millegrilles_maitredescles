use std::sync::Arc;
use log::{debug, error, info, warn};
use millegrilles_common_rust::{chrono, tokio};
use millegrilles_common_rust::certificats::{calculer_fingerprint, ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::configuration::{charger_configuration, ConfigMessages, IsConfigNoeud};
use millegrilles_common_rust::constantes::RolesCertificats;
use millegrilles_common_rust::domaines_v2::GestionnaireDomaineSimple;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::middleware_db_v2::preparer as preparer_middleware;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::static_cell::StaticCell;
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::error::{Error as CommonError, Error};
use millegrilles_common_rust::middleware::{charger_certificats_chiffrage, Middleware};
use millegrilles_common_rust::tokio::time::sleep;
use millegrilles_common_rust::transactions::resoumettre_transactions;
use crate::ca_manager::{preparer_index_mongodb_ca, MaitreDesClesCaManager};
use crate::domaines_maitredescles::TypeGestionnaire;
use crate::maitredescles_ca::GestionnaireMaitreDesClesCa;
use crate::maitredescles_commun::emettre_cles_symmetriques;
use crate::maitredescles_partition::GestionnaireMaitreDesClesPartition;
use crate::maitredescles_rechiffrage::HandlerCleRechiffrage;
use crate::maitredescles_sqlite::GestionnaireMaitreDesClesSQLite;
use crate::mongodb_manager::{preparer_index_mongodb, MaitreDesClesMongoDbManager};
use crate::sqlite_manager::MaitreDesClesSqliteManager;

pub trait MaitreDesClesSymmetricManagerTrait {}

/// Enum pour distinguer les types de gestionnaires.
pub enum MaitreDesClesSymmetricManager {
    MongoDb(MaitreDesClesMongoDbManager),
    SQLite(MaitreDesClesSqliteManager),
    None
}

struct MaitreDesClesManager {
    ca: Option<MaitreDesClesCaManager>,
    symmetric: MaitreDesClesSymmetricManager
}

static DOMAIN_MANAGER: StaticCell<MaitreDesClesManager> = StaticCell::new();

pub async fn run() {

    let (middleware, futures_middleware) = preparer_middleware()
        .expect("preparer middleware");

    let (gestionnaire, futures_domaine) = initialiser(middleware).await
        .expect("initialiser domaine");

    // Test redis connection
    if let Some(redis) = middleware.redis.as_ref() {
        match redis.liste_certificats_fingerprints().await {
            Ok(fingerprints_redis) => {
                debug!("run redis.liste_certificats_fingerprints Result : {:?}", fingerprints_redis);
            },
            Err(e) => warn!("run redis.liste_certificats_fingerprints Error testing redis connection : {:?}", e)
        }
    }

    // Combiner les JoinHandles recus
    let mut futures = FuturesUnordered::new();
    futures.extend(futures_middleware);
    futures.extend(futures_domaine);

    // Demarrer thread d'entretien.
    futures.push(spawn(thread_entretien(gestionnaire, middleware)));

    // Le "await" maintien l'application ouverte. Des qu'une task termine, l'application arrete.
    futures.next().await;

    for f in &futures {
        f.abort()
    }

    info!("domaine_messages Attendre {} tasks restantes", futures.len());
    while futures.len() > 0 {
        futures.next().await;
    }

    info!("domaine_messages Fin execution");
}

/// Initialise le gestionnaire. Retourne les spawned tasks dans une liste de futures
/// (peut servir a canceller).
async fn initialiser<M>(middleware: &'static M) -> Result<(&'static MaitreDesClesManager, FuturesUnordered<JoinHandle<()>>), CommonError>
where M: Middleware + IsConfigNoeud
{
    let ca_manager = charger_gestionnaire_ca();
    let symmetric_manager = charger_gestionnaire();

    let manager = MaitreDesClesManager {ca: ca_manager, symmetric: symmetric_manager};
    let gestionnaire = DOMAIN_MANAGER.try_init(manager)
        .expect("gestionnaire init");

    // Initialize resources and create threads
    let mut futures = FuturesUnordered::new();

    if let Some(ca) = &gestionnaire.ca {
        futures.extend(ca.initialiser(middleware).await.expect("initialiser ca"));
        preparer_index_mongodb_ca(middleware).await.expect("index mongodb ca");
    }

    match &gestionnaire.symmetric {
        MaitreDesClesSymmetricManager::MongoDb(manager) => {
            futures.extend(manager.initialiser(middleware).await.expect("initialize mongodb"));
            preparer_index_mongodb(middleware).await.expect("index mongodb ca");
        },
        MaitreDesClesSymmetricManager::SQLite(manager) => {
            futures.extend(manager.initialiser(middleware).await.expect("initialize sqlite"));
        },
        MaitreDesClesSymmetricManager::None => ()
    }

    Ok((gestionnaire, futures))
}

/// Fonction qui lit le certificat local et extrait les fingerprints idmg et de partition
/// Conserve les gestionnaires dans la variable GESTIONNAIRES 'static
fn charger_gestionnaire_ca() -> Option<MaitreDesClesCaManager> {

    match std::env::var("MG_MAITREDESCLES_MODE") {
        Ok(s) => match s.as_str() {
            "CA" | "CA_partition" => (),
            _ => { return None; }  // Pas de gestionnaire CA
        },
        Err(e) => panic!("charger_gestionnaire_ca Erreur lecture mode maitre des cles (CA) : {:?}", e)
    }

    // Charger une version simplifiee de la configuration - on veut le certificat associe a l'enveloppe privee
    let config = charger_configuration().expect("config");

    // Root - dernier certificat
    let validateur = config.get_configuration_pki().get_validateur();
    let cert_ca = validateur.ca_cert();
    let fp_ca = calculer_fingerprint(cert_ca).expect("fingerprint cert ca");

    info!("Configuration du maitre des cles avec CA {}", fp_ca);
    Some(MaitreDesClesCaManager { fingerprint: fp_ca.into() })
}

fn charger_gestionnaire() -> MaitreDesClesSymmetricManager {
    let handler_rechiffrage = preprarer_handler_rechiffrage().expect("handler_rechiffrage");

    info!("Configuration du maitre des cles avec rechiffreur");

    match std::env::var("MG_MAITREDESCLES_MODE") {
        Ok(val) => {
            match val.as_str() {
                "partition" | "CA_partition" | "mongodb" | "CA_mongodb" => {
                    MaitreDesClesSymmetricManager::MongoDb(MaitreDesClesMongoDbManager::new(handler_rechiffrage))
                },
                "sqlite" => {
                    MaitreDesClesSymmetricManager::SQLite(MaitreDesClesSqliteManager::new(handler_rechiffrage))
                },
                _ => MaitreDesClesSymmetricManager::None
            }
        },
        Err(e) => panic!("Erreur configuration type maitre des cles : {:?}", e)
    }
}

fn preprarer_handler_rechiffrage() -> Result<HandlerCleRechiffrage, Error> {
    // Charger une version simplifiee de la configuration - on veut le certificat associe a l'enveloppe privee
    let config = charger_configuration().expect("config");
    let enveloppe_privee = config.get_configuration_pki().get_enveloppe_privee();
    let certificat = enveloppe_privee.enveloppe_pub.clone();

    if certificat.verifier_roles(vec![RolesCertificats::MaitreDesCles])? {
        // On a un certificat MaitreDesCles, utiliser directement
        Ok(HandlerCleRechiffrage::with_certificat(enveloppe_privee))
    } else if certificat.verifier_roles(vec![RolesCertificats::MaitreDesClesConnexion])? {
        // HandlerCleRechiffrage::new_volatil_memoire().expect("HandlerCleRechiffrageCle")
        panic!("Mode volatil obsolete");
    } else {
        panic!("domaines_maitredescles.charger_gestionnaires Type de certificat non supporte pour Maitre des cles");
    }
}

async fn thread_entretien<M>(_gestionnaire: &MaitreDesClesManager, middleware: &M)
where M: Middleware
{
    warn!("TODO - Implement thread_entretien");  // TODO
    // let intervalle_entretien: chrono::Duration = chrono::Duration::minutes(5);
    //
    // let mut certificat_emis = false;
    //
    // // Liste de collections de transactions pour tous les domaines geres par Core
    // let collections_transaction = {
    //     let mut coll_docs_strings = Vec::new();
    //
    //     // Si on a un CA, conserver la collection de transactions
    //     if let Some(gestionnaire) = unsafe{&crate::domaines_maitredescles::GESTIONNAIRE_CA } {
    //         if let Some(collection) = gestionnaire.get_collection_transactions() {
    //             coll_docs_strings.push(collection);
    //         }
    //     }
    //
    //     // Note : Il n'y a pas de collection de transaction pour les autres types
    //
    //     coll_docs_strings
    // };
    //
    // let mut rechiffrage_complete = false;
    // let mut prochain_entretien_transactions = chrono::Utc::now();
    //
    // // Intervalle sync certificats avec CA et autres maitre des cles
    // let mut prochain_sync = chrono::Utc::now();
    // let intervalle_sync = chrono::Duration::hours(6);
    //
    // let mut prochaine_confirmation_ca = chrono::Utc::now();
    // let mut reset_flag_confirmation_ca = true;
    //
    // let mut prochain_chargement_certificats_autres = chrono::Utc::now();
    //
    // info!("domaines_maitredescles.entretien : Debut thread dans 5 secondes");
    //
    // // Donner 5 secondes pour que les Q soient pretes (e.g. Q reponse)
    // sleep(DurationTokio::new(5, 0)).await;
    //
    // loop {
    //     let maintenant = chrono::Utc::now();
    //     debug!("domaines_maitredescles.entretien  Execution task d'entretien Core {:?}", maintenant);
    //
    //     // Sleep jusqu'au prochain entretien ou evenement MQ (e.g. connexion)
    //     debug!("domaines_maitredescles.entretien Fin cycle, sleep {} secondes", DUREE_ATTENTE / 1000);
    //     let duration = DurationTokio::from_millis(crate::domaines_maitredescles::DUREE_ATTENTE);
    //
    //     middleware.entretien_validateur().await;
    //
    //     if prochain_chargement_certificats_autres < maintenant {
    //         match charger_certificats_chiffrage(middleware.as_ref()).await {
    //             Ok(()) => {
    //                 prochain_chargement_certificats_autres = maintenant + intervalle_entretien;
    //                 debug!("domaines_maitredescles.entretien Prochain chargement cert maitredescles: {:?}", prochain_chargement_certificats_autres);
    //             },
    //             Err(e) => warn!("domaines_maitredescles.entretien Erreur chargement certificats de maitre des cles : {:?}", e)
    //         }
    //         // match middleware.charger_certificats_chiffrage(middleware.as_ref()).await {
    //         //     Ok(()) => {
    //         //         prochain_chargement_certificats_autres = maintenant + intervalle_entretien;
    //         //     },
    //         //     Err(e) => info!("Erreur chargement certificats de maitre des cles tiers : {:?}", e)
    //         // }
    //     }
    //
    //     if prochain_entretien_transactions < maintenant {
    //         let resultat = resoumettre_transactions(
    //             middleware.as_ref(),
    //             &collections_transaction
    //         ).await;
    //
    //         match resultat {
    //             Ok(_) => {
    //                 prochain_entretien_transactions = maintenant + intervalle_entretien;
    //             },
    //             Err(e) => {
    //                 warn!("domaines_maitredescles.entretien Erreur resoumission transactions (entretien) : {:?}", e);
    //             }
    //         }
    //     }
    //
    //     if certificat_emis == false {
    //         debug!("domaines_maitredescles.entretien Emettre certificat");
    //         match middleware.emettre_certificat(middleware.as_ref()).await {
    //             Ok(()) => certificat_emis = true,
    //             Err(e) => error!("Erreur emission certificat local : {:?}", e),
    //         }
    //         debug!("domaines_maitredescles.entretien Fin emission traitement certificat local, resultat : {}", certificat_emis);
    //     }
    //
    //     match unsafe{&crate::domaines_maitredescles::GESTIONNAIRE } {
    //         TypeGestionnaire::Partition(g) => {
    //
    //             if prochain_sync < maintenant {
    //                 debug!("entretien Effectuer sync des cles du CA non disponibles localement");
    //                 match g.synchroniser_cles(middleware.as_ref()).await {
    //                     Ok(()) => {
    //                         prochain_sync = maintenant + intervalle_sync;
    //                     },
    //                     Err(e) => {
    //                         prochain_sync = maintenant + intervalle_entretien;  // Reessayer dans 5 minutes
    //                         warn!("entretien Partition Erreur syncrhonization cles avec CA : {:?}", e)
    //                     }
    //                 }
    //             }
    //
    //             if prochaine_confirmation_ca < maintenant {
    //                 // Emettre certificat local (pas vraiment a la bonne place)
    //                 match g.emettre_certificat_maitredescles(middleware.as_ref(), None).await {
    //                     Ok(()) => (),
    //                     Err(e) => error!("entretien Partition Erreur emission certificat de maitre des cles : {:?}", e)
    //                 }
    //
    //                 match emettre_cles_symmetriques(middleware.as_ref(), g.handler_rechiffrage.as_ref()).await {
    //                     Ok(()) => (),
    //                     Err(e) => error!("entretien Partition Erreur emission evenement cles rechiffrage : {:?}", e)
    //                 }
    //
    //                 debug!("entretien Pousser les cles locales vers le CA");
    //                 match g.confirmer_cles_ca(middleware.as_ref(), Some(reset_flag_confirmation_ca)).await {
    //                     Ok(()) => {
    //                         reset_flag_confirmation_ca = false;
    //                         prochaine_confirmation_ca = maintenant + intervalle_entretien;
    //                     },
    //                     Err(e) => {
    //                         warn!("entretien Partition Pousser les cles locales vers le CA : {:?}", e);
    //                         prochaine_confirmation_ca = maintenant + intervalle_entretien;  // Reessayer dans 5 minutes
    //                     }
    //                 }
    //             }
    //
    //         },
    //         TypeGestionnaire::SQLite(g) => {
    //             if prochain_sync < maintenant {
    //                 debug!("entretien Effectuer sync des cles du CA non disponibles localement");
    //                 match g.synchroniser_cles(middleware.as_ref()).await {
    //                     Ok(()) => {
    //                         prochain_sync = maintenant + intervalle_sync;
    //                     },
    //                     Err(e) => {
    //                         prochain_sync = maintenant + intervalle_entretien;
    //                         warn!("entretien SQLite Erreur synchronization cles avec CA : {:?}", e)
    //                     }
    //                 }
    //             }
    //
    //             if prochaine_confirmation_ca < maintenant {
    //                 // Emettre certificat local (pas vraiment a la bonne place)
    //                 match g.emettre_certificat_maitredescles(middleware.as_ref(), None).await {
    //                     Ok(_) => (),
    //                     Err(e) => error!("entretien SQLite Erreur emission certificat de maitre des cles : {:?}", e)
    //                 }
    //
    //                 match emettre_cles_symmetriques(middleware.as_ref(), &g.handler_rechiffrage).await {
    //                     Ok(()) => (),
    //                     Err(e) => error!("entretien Partition Erreur emission evenement cles rechiffrage : {:?}", e)
    //                 }
    //
    //                 debug!("entretien Pousser les cles locales vers le CA");
    //                 match g.confirmer_cles_ca(middleware.clone(), Some(reset_flag_confirmation_ca)).await {
    //                     Ok(()) => {
    //                         reset_flag_confirmation_ca = false;
    //                         prochaine_confirmation_ca = maintenant + intervalle_entretien;
    //                     },
    //                     Err(e) => {
    //                         warn!("entretien SQLITE Pousser les cles locales vers le CA : {:?}", e);
    //                         prochaine_confirmation_ca = maintenant + intervalle_entretien;
    //                     }
    //                 }
    //             }
    //         },
    //         _ => ()
    //     }
    //
    //     sleep(duration).await;
    // }
    //
    // // panic!("Forcer fermeture");
    // info!("domaines_maitredescles.entretien : Fin thread");
}
