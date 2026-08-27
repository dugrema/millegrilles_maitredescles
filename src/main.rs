mod maitredescles_commun;
mod maitredescles_rechiffrage;
mod models;
mod constants;
mod maitredescles_mongodb;
mod builder;
mod ca_manager;
mod mongodb_manager;
mod sqlite_manager;
mod requests;
mod commands;
mod transactions;
mod maintenance;
pub mod state;
pub mod external;
pub mod flow;

use crate::state::AppContext;
use millegrilles_common_rust::tokio as tokio;
use millegrilles_common_rust::tracing::info;
use millegrilles_common_rust::{tracing_subscriber, tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt}};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    init_logging();
    info!("Starting MaitreDesCles");

    // Start the application by creating the context. This starts all threads and connections.
    let context = AppContext::new().await.expect("AppContext::new");
    let shutdown_token = context.shutdown_token.clone();

    let shutdown_signal = async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to install sigint handler");
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to install sigterm handler");

        tokio::select! {
            _ = sigint.recv() => info!("Received SIGINT (Ctrl+C)"),
            _ = sigterm.recv() => info!("Received SIGTERM (Docker/K8s)"),
        }
    };

    tokio::select! {
        _ = shutdown_signal => {
            info!("Shutdown signal received. Triggering cancellation...");
            shutdown_token.cancel();
        }
    }

    info!("Waiting for background tasks to clean up...");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    info!("Shutdown complete.");
}


fn init_logging() {
    let rust_log_var = std::env::var("RUST_LOG").unwrap_or("error,millegrilles_maitredescles=warn,millegrilles_common_rust=warn".to_string());
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(rust_log_var))
        .with(tracing_subscriber::fmt::layer())
        .init();
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
