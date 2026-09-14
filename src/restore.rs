use std::sync::Arc;
use millegrilles_common_rust::openssl::pkey::{PKey, Private};
use millegrilles_common_rust::tokio_util::sync::CancellationToken;
use crate::flow::ca::MaitreDesClesCAServiceImpl;
use millegrilles_common_rust::tokio::time::sleep;

pub async fn restore_from_backup(ca_service: Arc<MaitreDesClesCAServiceImpl>, master_key: PKey<Private>, shutdown_token: CancellationToken) {
    eprintln!("Beginning database restoration");
    let result = match ca_service.restore(Some(master_key), false, None).await {
        Ok(inner) => inner,
        Err(e) => {
            eprintln!("Error during restoration: {:?}", e);
            std::process::exit(2);
        }
    };

    // Produce final restoration report
    eprintln!("Restored {} transactions", result.transaction_count);

    eprintln!("Restoration process complete - shutting down");
    // Stop all processes - restoration complete
    shutdown_token.cancel();

    sleep(std::time::Duration::from_secs(2)).await;
    std::process::exit(0);
}
