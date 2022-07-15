mod domaines_maitredescles;
mod maitredescles_partition;
mod maitredescles_ca;
mod maitredescles_commun;
mod maitredescles_redis;
mod maitredescles_sqlite;

use log::{info};
use millegrilles_common_rust::tokio as tokio;
use crate::domaines_maitredescles::run;

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
