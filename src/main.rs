mod maitredescles_commun;
mod maitredescles_rechiffrage;
mod messages;
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
mod maintenance;
pub mod state;
pub mod external;
pub mod flow;
pub mod models;

use millegrilles_common_rust::tracing::{info};
use millegrilles_common_rust::{tracing_subscriber, tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt}};
use millegrilles_common_rust::tokio as tokio;
// use crate::domaines_maitredescles::run;
use crate::builder::run;

fn main() {
    init_logging();
    info!("Starting MaitreDesCles");
    executer()
}

fn init_logging() {
    let rust_log_var = std::env::var("RUST_LOG").unwrap_or("error,millegrilles_maitredescles=warn,millegrilles_common_rust=warn".to_string());
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(rust_log_var))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

 #[tokio::main(flavor = "current_thread")]
// #[tokio::main(flavor = "multi_thread", worker_threads = 5)]
async fn executer() {
    run().await
}

#[cfg(test)]
pub mod test_setup {
    use millegrilles_common_rust::tracing::{debug};
    use millegrilles_common_rust::{tracing_subscriber, tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt}};

    pub fn setup(nom: &str) {
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new("warn,millegrilles_maitredescles=debug"))
            .with(tracing_subscriber::fmt::layer())
            .init();
        debug!("Running {}", nom);
    }
}
