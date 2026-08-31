mod maitredescles_commun;
mod models;
mod constants;
mod maitredescles_mongodb;
mod builder;
mod ca_manager;
mod mongodb_manager;
mod requests;
mod commands;
mod maintenance;
pub mod state;
pub mod external;
pub mod flow;

use crate::flow::symmetric::symmetric_init_tasks;
use crate::state::AppContext;
use external::crypto::SymmetricEncryptionHandler;
use millegrilles_common_rust::tracing::{info, warn};
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::{rustls, tokio as tokio};
use millegrilles_common_rust::{tracing_subscriber, tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt}};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    init_resources();
    info!("Starting MaitreDesCles");

    // Start the application by creating the context. This starts all threads and connections.
    let mut context = AppContext::new().await.expect("AppContext::new");
    let shutdown_token = context.shutdown_token.clone();

    let shutdown_signal = async {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to install sigint handler");
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to install sigterm handler");

        tokio::select! {
            _ = sigint.recv() => info!("Received SIGINT (Ctrl+C)"),
            _ = sigterm.recv() => info!("Received SIGTERM (Docker/K8s)"),
        }
    };

    init_tasks(context.outbound.as_ref(), context.decryption.as_ref()).await;

    tokio::select! {
        _ = shutdown_signal => {
            info!("Shutdown signal received. Triggering cancellation...");
            shutdown_token.cancel();
        }
    }

    info!("Waiting for workers to finish (15s limit)...");
    match tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while context.join_set.join_next().await.is_some() {}
    }).await {
        Ok(_) => info!("Shutdown complete."),
        Err(_) => warn!("Grace period expired! Forcing exit."),
    }
}


fn init_resources() {
    let rust_log_var = std::env::var("RUST_LOG").unwrap_or("error,millegrilles_maitredescles=warn,millegrilles_common_rust=warn".to_string());
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(rust_log_var))
        .with(tracing_subscriber::fmt::layer())
        .init();

    rustls::crypto::ring::default_provider().install_default()
        .expect("Failed to install rustls crypto provider");
}

/// This runs once on startup after all the wiring is done and threads are started
async fn init_tasks(outbound: &MessageOutboundFacade, decryption: &SymmetricEncryptionHandler) {
    // Initial tasks to run once for the symmetric keymaster
    symmetric_init_tasks(outbound, decryption).await;
}

#[cfg(test)]
pub mod test_setup {
    use millegrilles_common_rust::tracing::debug;
    use millegrilles_common_rust::{tracing_subscriber, tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt}};

    pub fn setup(nom: &str) {
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new("warn,millegrilles_maitredescles=debug"))
            .with(tracing_subscriber::fmt::layer())
            .init();
        debug!("Running {}", nom);
    }
}
