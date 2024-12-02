use log::{debug, error, info, warn};
use millegrilles_common_rust::chrono;
use millegrilles_common_rust::chrono::Timelike;
use millegrilles_common_rust::middleware::{Middleware, MiddlewareMessages};
use millegrilles_common_rust::tokio::time::{sleep, Duration as DurationTokio};
use crate::builder::{MaitreDesClesManager, MaitreDesClesSymmetricManager};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::mongo_dao::MongoDao;
use crate::maitredescles_commun::{emettre_certificat_maitredescles, emettre_cles_symmetriques};
use crate::maitredescles_mongodb::{confirmer_cles_ca, marquer_cles_ca_timeout, synchroniser_cles};
use crate::maitredescles_rechiffrage::HandlerCleRechiffrage;

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
    let mut trigger_emettre_cles_symmetrique = IntervalTrigger::new(intervalle_entretien);

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
            if trigger_emettre_cles_symmetrique.check_trigger() {
                match emettre_cles_symmetriques(middleware, handler_rechiffrage).await {
                    Ok(()) => (),
                    Err(e) => error!("thread_entretien Partition Erreur emission evenement cles rechiffrage : {:?}", e)
                }
            }
        }

        sleep(duration).await;
    }

    info!("thread_entretien : Fin thread");
}

pub async fn maintenance_ca<M>(middleware: &M, trigger: &MessageCedule) -> Result<(), Error>
where
    M: MiddlewareMessages + MongoDao
{
    let hour = trigger.get_date().hour();
    let minute = trigger.get_date().minute();

    if hour % 6 == 3 && minute == 25 {
        if let Err(e) = marquer_cles_ca_timeout(middleware).await {
            warn!("maintenance_ca Erreur marquer cles timeout : {:?}", e);
        }
    }

    Ok(())
}

pub async fn maintenance_mongodb<M>(middleware: &M, trigger: &MessageCedule, handler_rechiffrage: &HandlerCleRechiffrage) -> Result<(), Error>
where
    M: MiddlewareMessages + MongoDao
{

    let minute = trigger.get_date().minute();
    let hour = trigger.get_date().hour();

    if handler_rechiffrage.is_ready() {
        // Pousser l'information des cles locales (dechiffrables) vers le CA
        // La sync de base emet uniquement les cles qui ne sont pas encore confirmees par le CA
        // La sync complet re-emet toutes les cles dechiffrables localement.
        let reset_flag_confirmation_ca = hour % 6 == 3 && minute == 18;  // Sync complete
        // let reset_flag_confirmation_ca = true;
        if reset_flag_confirmation_ca || minute % 15 == 3
        {
            debug!("maintenance_mongodb Pousser les cles locales vers le CA");
            if let Err(e) = confirmer_cles_ca(middleware, Some(reset_flag_confirmation_ca)).await {
                warn!("maintenance_mongodb Partition Pousser les cles locales vers le CA : {:?}", e);
            }
        }
    }

    if hour % 6 == 4 && minute == 47
    {
        debug!("thread_entretien Effectuer sync des cles du CA non disponibles localement");
        if let Err(e) = synchroniser_cles(middleware, handler_rechiffrage).await {
            warn!("thread_entretien Partition Erreur syncrhonization cles avec CA : {:?}", e)
        }
    }

    Ok(())
}
