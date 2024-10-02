// mod domaines_maitredescles;
// mod maitredescles_partition;
// mod maitredescles_ca;
//mod maitredescles_redis;  // Obsolete
// mod maitredescles_sqlite;
mod maitredescles_commun;
mod maitredescles_rechiffrage;
mod messages;
mod chiffrage_cles;
mod constants;
mod maitredescles_mongodb;
mod builder;
mod ca_manager;
mod mongodb_manager;
mod sqlite_manager;
mod requests;
mod commands;
mod events;
mod transactions;

use log::{info};
use millegrilles_common_rust::tokio as tokio;
// use crate::domaines_maitredescles::run;
use crate::builder::run;

fn main() {
    env_logger::init();
    info!("Demarrer le contexte");
    executer()
}

#[tokio::main(flavor = "current_thread")]
// #[tokio::main(flavor = "multi_thread", worker_threads = 5)]
async fn executer() {
    run().await
}

#[cfg(test)]
pub mod test_setup {
    use log::{debug};

    pub fn setup(nom: &str) {
        let _ = env_logger::builder().is_test(true).try_init();
        debug!("Running {}", nom);
    }
}
