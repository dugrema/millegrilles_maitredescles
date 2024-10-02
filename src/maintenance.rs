use log::{debug, error, info, warn};
use millegrilles_common_rust::chrono;
use millegrilles_common_rust::middleware::Middleware;
use millegrilles_common_rust::tokio::time::{sleep, Duration as DurationTokio};
use crate::builder::{MaitreDesClesManager, MaitreDesClesSymmetricManager};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::mongo_dao::MongoDao;
use crate::maitredescles_commun::{emettre_certificat_maitredescles, emettre_cles_symmetriques};
use crate::maitredescles_mongodb::{confirmer_cles_ca, synchroniser_cles};

const DUREE_ATTENTE: u64 = 20000;


struct IntervalTrigger {
    interval: chrono::Duration,
    next_trigger: chrono::DateTime<chrono::Utc>
}

impl IntervalTrigger {
    fn new(interval: chrono::Duration) -> IntervalTrigger {
        IntervalTrigger { interval, next_trigger: chrono::Utc::now() }
    }

    fn check_trigger(&mut self) -> bool {
        let now = chrono::Utc::now();
        if self.next_trigger < now {
            self.next_trigger = now + self.interval;
            true
        } else {
            false
        }
    }

    fn set_next_trigger(&mut self, interval: chrono::Duration) {
        self.next_trigger = chrono::Utc::now() + interval;
    }
}

pub async fn thread_entretien<M>(manager: &MaitreDesClesManager, middleware: &M)
where M: Middleware
{
    let intervalle_entretien = chrono::Duration::minutes(5);

    // Intervalle sync certificats avec CA et autres maitre des cles
    let mut trigger_certificat = IntervalTrigger::new(intervalle_entretien);
    let mut trigger_confirmation_ca = IntervalTrigger::new(intervalle_entretien);
    let mut trigger_emettre_cles_symmetrique = IntervalTrigger::new(intervalle_entretien);
    let mut trigger_sync = IntervalTrigger::new(chrono::Duration::hours(6));

    let mut reset_flag_confirmation_ca = true;

    info!("thread_entretien : Debut thread dans 5 secondes");

    // Donner 5 secondes pour que les Q soient pretes (e.g. Q reponse)
    sleep(DurationTokio::new(5, 0)).await;

    let handler_rechiffrage = match &manager.symmetric {
        MaitreDesClesSymmetricManager::MongoDb(inner) => Some(&inner.handler_rechiffrage),
        MaitreDesClesSymmetricManager::SQLite(inner) => Some(&inner.handler_rechiffrage),
        MaitreDesClesSymmetricManager::None => None
    };

    loop {
        let maintenant = chrono::Utc::now();
        debug!("thread_entretien  Execution task d'entretien Core {:?}", maintenant);

        // Sleep jusqu'au prochain entretien ou evenement MQ (e.g. connexion)
        debug!("thread_entretien.entretien Fin cycle, sleep {} secondes", DUREE_ATTENTE / 1000);
        let duration = DurationTokio::from_millis(DUREE_ATTENTE);

        if trigger_certificat.check_trigger() {
            match emettre_certificat_maitredescles(middleware, None).await {
                Ok(()) => (),
                Err(e) => error!("thread_entretien Partition Erreur emission certificat de maitre des cles : {:?}", e)
            }
        }

        if let Some(handler_rechiffrage) = handler_rechiffrage {
            if trigger_sync.check_trigger() {
                debug!("thread_entretien Effectuer sync des cles du CA non disponibles localement");
                match synchroniser_cles(middleware, handler_rechiffrage).await {
                    Ok(()) => {},
                    Err(e) => {
                        trigger_sync.set_next_trigger(intervalle_entretien); // Reessayer dans 5 minutes
                        warn!("thread_entretien Partition Erreur syncrhonization cles avec CA : {:?}", e)
                    }
                }
            }

            if trigger_emettre_cles_symmetrique.check_trigger() {
                match emettre_cles_symmetriques(middleware, handler_rechiffrage).await {
                    Ok(()) => (),
                    Err(e) => error!("thread_entretien Partition Erreur emission evenement cles rechiffrage : {:?}", e)
                }
            }
        }

        debug!("thread_entretien Pousser les cles locales vers le CA");
        if trigger_confirmation_ca.check_trigger() {
            match confirmer_cles_ca(middleware, Some(reset_flag_confirmation_ca)).await {
                Ok(()) => {
                    reset_flag_confirmation_ca = false;
                },
                Err(e) => {
                    warn!("thread_entretien Partition Pousser les cles locales vers le CA : {:?}", e);
                }
            }
        }

        sleep(duration).await;
    }

    info!("thread_entretien : Fin thread");
}
