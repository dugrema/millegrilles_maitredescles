//! Module MaitreDesCles de millegrilles installe sur un noeud 3.protege.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use log::{debug, error, info, warn};
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chrono as chrono;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::{EmetteurCertificat};
use millegrilles_common_rust::middleware_db::preparer_middleware_db;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::{Callback, EventMq, QueueType};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::tokio::{sync::{mpsc, mpsc::{Receiver, Sender}}, time::{Duration as DurationTokio, timeout}};
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::resoumettre_transactions;

use crate::maitredescles_ca::{GESTIONNAIRE_MAITREDESCLES_CA, GestionnaireMaitreDesClesCa};
use crate::maitredescles_partition::{GestionnaireMaitreDesClesPartition};

const DUREE_ATTENTE: u64 = 20000;

// Creer espace static pour conserver les gestionnaires
static mut GESTIONNAIRES: [TypeGestionnaire; 2] = [TypeGestionnaire::None, TypeGestionnaire::None];

/// Enum pour distinger les types de gestionnaires.
#[derive(Clone, Debug)]
enum TypeGestionnaire {
    CA(Arc<GestionnaireMaitreDesClesCa>),
    Partition(Arc<GestionnaireMaitreDesClesPartition>),
    None
}

pub async fn run() {

    // Inserer les gestionnaires dans la variable static - permet d'obtenir lifetime 'static
    let gestionnaires = unsafe {
        GESTIONNAIRES[0] = TypeGestionnaire::CA(Arc::new(GestionnaireMaitreDesClesCa{}));
        GESTIONNAIRES[1] = TypeGestionnaire::Partition(Arc::new(GestionnaireMaitreDesClesPartition::new("DUMMY")));

        let mut vec_gestionnaires = Vec::new();
        vec_gestionnaires.extend(&GESTIONNAIRES);
        vec_gestionnaires
    };

    build_run(gestionnaires).await
}

async fn build_run(gestionnaires: Vec<&'static TypeGestionnaire>) {

    // let gestionnaires = unsafe {
    //     let mut vec_gestionnaires = Vec::new();
    //     vec_gestionnaires.extend(&GESTIONNAIRES);
    //     vec_gestionnaires
    // };

    // Recuperer configuration des Q de tous les domaines
    let queues = {
        let mut queues: Vec<QueueType> = Vec::new();
        for g in gestionnaires.clone() {
            match g {
                TypeGestionnaire::CA(g) => {
                    queues.extend(g.preparer_queues());
                },
                TypeGestionnaire::Partition(g) => {
                    queues.extend(g.preparer_queues());
                },
                TypeGestionnaire::None => ()
            }
        }
        queues
    };

    // Listeners de connexion MQ
    let (tx_entretien, rx_entretien) = mpsc::channel(1);
    let listeners = {
        let mut callbacks: Callback<EventMq> = Callback::new();
        callbacks.register(Box::new(move |event| {
            debug!("Callback sur connexion a MQ, event : {:?}", event);
            let tx_ref = tx_entretien.clone();
            let _ = spawn(async move{
                match tx_ref.send(event).await {
                    Ok(_) => (),
                    Err(e) => error!("Erreur queuing via callback : {:?}", e)
                }
            });
        }));

        Some(Mutex::new(callbacks))
    };

    // Preparer middleware avec acces direct aux tables Pki (le domaine est local)
    let (
        middleware,
        rx_messages_verifies,
        rx_triggers,
        future_recevoir_messages
    ) = preparer_middleware_db(queues, listeners);

    // Preparer les green threads de tous les domaines/processus
    let mut futures = FuturesUnordered::new();
    {
        let mut map_senders: HashMap<String, Sender<TypeMessage>> = HashMap::new();

        // ** Wiring global **

        // Creer consommateurs MQ globaux pour rediriger messages recus vers Q internes appropriees
        futures.push(spawn(
            consommer( middleware.clone(), rx_messages_verifies, map_senders.clone())
        ));
        futures.push(spawn(
            consommer( middleware.clone(), rx_triggers, map_senders.clone())
        ));

        // ** Thread d'entretien **
        futures.push(spawn(entretien(middleware.clone(), rx_entretien, gestionnaires.clone())));

        // ** Domaines **
        {
            for g in gestionnaires {
                let (
                    routing_g,
                    futures_g
                ) = match g {
                    TypeGestionnaire::CA(g) => {
                        g.preparer_threads(middleware.clone()).await.expect("gestionnaire")
                    },
                    TypeGestionnaire::Partition(g) => {
                        g.preparer_threads(middleware.clone()).await.expect("gestionnaire")
                    },
                    TypeGestionnaire::None => (HashMap::new(), FuturesUnordered::new()),
                };
                futures.extend(futures_g);        // Deplacer vers futures globaux
                map_senders.extend(routing_g);    // Deplacer vers mapping global
            }
        }

        // Thread ecoute et validation des messages
        for f in future_recevoir_messages {
            futures.push(f);
        }

    }

    info!("domaines_maitredescles: Demarrage traitement, top level threads {}", futures.len());
    let arret = futures.next().await;
    info!("domaines_maitredescles: Fermeture du contexte, task daemon terminee : {:?}", arret);
}

/// Thread d'entretien
async fn entretien<M>(middleware: Arc<M>, mut rx: Receiver<EventMq>, gestionnaires: Vec<&'static TypeGestionnaire>)
where
    M: GenerateurMessages + ValidateurX509 + EmetteurCertificat + MongoDao,
{
    let mut certificat_emis = false;

    // Liste de collections de transactions pour tous les domaines geres par Core
    let collections_transaction = {
        let mut coll_docs_strings = Vec::new();
        for g in gestionnaires {
            match g {
                TypeGestionnaire::CA(g) => {
                    coll_docs_strings.push(String::from(g.get_collection_transactions()));
                },
                TypeGestionnaire::Partition(g) => {
                    coll_docs_strings.push(String::from(g.get_collection_transactions()));
                },
                TypeGestionnaire::None => ()
            }
        }
        coll_docs_strings
    };

    let mut prochain_entretien_transactions = chrono::Utc::now();
    let intervalle_entretien_transactions = chrono::Duration::minutes(5);

    loop {
        let maintenant = chrono::Utc::now();
        debug!("entretien  Execution task d'entretien Core {:?}", maintenant);

        middleware.entretien().await;

        if prochain_entretien_transactions < maintenant {
            let resultat = resoumettre_transactions(
                middleware.as_ref(),
                &collections_transaction
            ).await;

            match resultat {
                Ok(_) => {
                    prochain_entretien_transactions = maintenant + intervalle_entretien_transactions;
                },
                Err(e) => {
                    warn!("entretien Erreur resoumission transactions (entretien) : {:?}", e);
                }
            }
        }

        // Sleep jusqu'au prochain entretien
        debug!("Task entretien core fin cycle, sleep {} secondes", DUREE_ATTENTE / 1000);
        let duration = DurationTokio::from_millis(DUREE_ATTENTE);
        let result = timeout(duration, rx.recv()).await;

        match result {
            Ok(inner) => {
                debug!("Recu event MQ : {:?}", inner);
                match inner {
                    Some(e) => {
                        match e {
                            EventMq::Connecte => {
                            },
                            EventMq::Deconnecte => {
                                // Reset flag certificat
                                certificat_emis = false;
                            }
                        }
                    },
                    None => {
                        warn!("domaines_maitredescles.entretien MQ n'est pas disponible, on ferme");
                        break
                    },
                }

            },
            Err(_) => {
                debug!("entretien Timeout, entretien est du");
            }
        }

        if certificat_emis == false {
            debug!("Emettre certificat");
            match middleware.emettre_certificat(middleware.as_ref()).await {
                Ok(()) => certificat_emis = true,
                Err(e) => error!("Erreur emission certificat local : {:?}", e),
            }
            debug!("Fin emission traitement certificat local, resultat : {}", certificat_emis);
        }
    }

    // panic!("Forcer fermeture");

}

async fn consommer(
    _middleware: Arc<impl ValidateurX509 + GenerateurMessages + MongoDao>,
    mut rx: Receiver<TypeMessage>,
    map_senders: HashMap<String, Sender<TypeMessage>>
) {
    info!("consommer: Mapping senders core : {:?}", map_senders.keys());

    while let Some(message) = rx.recv().await {
        match &message {
            TypeMessage::Valide(m) => {
                warn!("domaines_maitredescles.consommer: Message valide sans routing key/action : {:?}", m.message);
            },
            TypeMessage::ValideAction(m) => {
                let contenu = &m.message;
                let rk = m.routing_key.as_str();
                let action = m.action.as_str();
                let domaine = m.domaine.as_str();
                let nom_q = m.q.as_str();
                info!("domaines_maitredescles.consommer: Traiter message valide (action: {}, rk: {}, q: {}): {:?}", action, rk, nom_q, contenu);

                // Tenter de mapper avec le nom de la Q (ne fonctionnera pas pour la Q de reponse)
                let sender = match map_senders.get(nom_q) {
                    Some(sender) => sender,
                    None => {
                        match map_senders.get(domaine) {
                            Some(sender) => sender,
                            None => {
                                error!("domaines_maitredescles.consommer Message de queue ({}) et domaine ({}) inconnu, on le drop", nom_q, domaine);
                                continue  // On skip
                            },
                        }
                    }
                };

                match sender.send(message).await {
                    Ok(()) => (),
                    Err(e) => {
                        error!("domaines_maitredescles.consommer Erreur consommer message {:?}", e)
                    }
                }
            },
            TypeMessage::Certificat(_) => (),  // Rien a faire
            TypeMessage::Regeneration => (),   // Rien a faire
        }
    }
}