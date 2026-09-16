mod models;
mod constants;
mod state;
mod external;
mod flow;
mod errors;
pub mod restore;
pub mod legacy;

use std::path::Path;
use clap::Parser;
use clap_derive::Parser;
use crate::flow::symmetric::symmetric_init_tasks;
use crate::state::AppContext;
use external::crypto::SymmetricEncryptionHandler;
use millegrilles_common_rust::mongo_dao::MongoDaoImpl;
use millegrilles_common_rust::tracing::{debug, info, warn};
use millegrilles_common_rust::v3::{ConfigService, PresenceService};
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::{rustls, tokio as tokio};
use millegrilles_common_rust::{tracing_subscriber, tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt}};
use millegrilles_common_rust::millegrilles_cryptographie::x509::parse_encrypted_private_key;
use millegrilles_common_rust::openssl::pkey::{PKey, Private};
use crate::constants::DOMAINE_NOM;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    init_resources();

    let cli = Cli::parse();
    let master_key = parse_ca_password(&cli);

    info!("Starting MaitreDesCles");

    // Start the application by creating the context. This starts all threads and connections.
    let mut context = AppContext::new(&cli, master_key).await.expect("AppContext::new");
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

    init_tasks(
        context.config.as_ref(),
        context.mongo.as_ref(),
        context.outbound.as_ref(),
        context.decryption.as_ref(),
    ).await;

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
async fn init_tasks(config: &dyn ConfigService, mongo: &MongoDaoImpl, outbound: &MessageOutboundFacade, decryption: &SymmetricEncryptionHandler) {
    // Initial tasks to run once for the symmetric keymaster
    symmetric_init_tasks(config, mongo, outbound, decryption).await;

    // Wait for queues to emit initial domain presence
    match outbound.wait_ready(Some(5_000)).await {
        Ok(()) => {
            if let Err(e) = outbound.emit_domain_presence(DOMAINE_NOM, None).await {
                warn!("Error emitting initial domain presence: {}", e);
            }
        },
        Err(e) => {
            warn!("Error waiting for queues to be ready, not emitting inital domain presence: {:?}", e);
        }
    }

}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Enable restoration mode
    #[arg(long)]
    restore: bool,

    /// Path to the master key file
    #[arg(short, long)]
    capath: Option<String>,
}

/// Handle the master key and password prompt
fn parse_ca_password (cli: &Cli) -> Option<PKey<Private>> {
    if ! cli.restore {
        // No need to look at key path if not restoring
        return None
    }

    // We return an Option containing the path and the password
    if let Some(path) = cli.capath.as_ref() {
        debug!("Master key path provided: {}", path);

        // rpassword::prompt_password will hide the input as the user types
        let password = match rpassword::prompt_password("Enter master key password: ") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to read password: {}", e);
                std::process::exit(1);
            }
        };

        let private_key = match parse_encrypted_private_key(Path::new(&path), &password) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error loading private key: {}", e);
                std::process::exit(1);
            }
        };

        Some(private_key)
    } else {
        eprintln!("Restoring keymaster requires the CA key (param --capath)");
        std::process::exit(1);
    }
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
