use crate::Cli;
use crate::constants::NOM_COLLECTION_CA_CLES;
use crate::external::crypto::SymmetricEncryptionHandler;
use crate::flow::ca::MaitreDesClesCAServiceImpl;
use crate::flow::symmetric::MaitreDesClesSymmetricServiceImpl;
use crate::flow::transactions::KeyMasterTransactionService;
use crate::restore::restore_from_backup;
use millegrilles_common_rust::certificats::build_store_path_v2;
use millegrilles_common_rust::chiffrage_cle::CleChiffrageHandlerImpl;
use millegrilles_common_rust::configuration::{ConfigDb, ConfigMessages, charger_configuration, charger_configuration_mongo};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::{MongoDaoImpl, initialiser};
use millegrilles_common_rust::openssl::pkey::{PKey, Private};
use millegrilles_common_rust::tokio::task::JoinSet;
use millegrilles_common_rust::tokio_util::sync::CancellationToken;
use millegrilles_common_rust::tracing::{debug, info};
use millegrilles_common_rust::v3::facades::message_inbound::MessageInboundValidator;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::backup_service::DomainBackupServiceImpl;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::format_service::FormatServiceImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::impls::security_service::SecurityServiceImpl;
use millegrilles_common_rust::v3::{ChiffrageService, ConfigService};
use std::sync::Arc;
use millegrilles_common_rust::v3::impls::filehost_service::FilehostServiceImpl;

/// Composition object with services from common library
pub struct AppContext {
    pub join_set: JoinSet<()>,
    pub config: Arc<dyn ConfigService>,
    // pub config_db: Arc<dyn ConfigDb>,
    // pub pki: Arc<dyn PkiService>,
    // pub messaging: Arc<dyn MessagingService>,
    // pub format: Arc<dyn FormatService>,
    pub mongo: Arc<MongoDaoImpl>,
    pub outbound: Arc<MessageOutboundFacade>,
    // pub inbound: Arc<MessageInboundValidator>,
    // pub ca_service: Arc<dyn MaitreDesClesCAService>,
    // pub symmetric_service: Arc<dyn MaitreDesClesSymmetricService>,
    pub decryption: Arc<SymmetricEncryptionHandler>,
    // pub transaction: Arc<KeyMasterTransactionService>,
    pub shutdown_token: CancellationToken,
}

impl AppContext {
    pub async fn new(cli: &Cli, master_key: Option<PKey<Private>>) -> Result<Self, CommonError> {
        // Shutdown/cancel semantics
        let shutdown_token = CancellationToken::new();
        let mut join_set = JoinSet::new();

        // Basic services
        let config = Arc::new(init_config().await?);
        let security = Arc::new(init_security(config.as_ref()).await?);
        let messaging = Arc::new(MessagingServiceImpl::new(config.clone(), security.clone()));
        let format = Arc::new(FormatServiceImpl::new(config.clone()));
        let decryption = Arc::new(SymmetricEncryptionHandler::with_certificate(
            config.get_configuration_pki().get_enveloppe_privee()
        ));

        let mongo = Arc::new(
            initialiser(config.get_configuration_pki(), config.get_configuraiton_mongo())?
        );

        // Facades
        let outbound = Arc::new(
            MessageOutboundFacade::new(config.clone(), messaging.clone(), format.clone(), security.clone()));
        let inbound = Arc::new(
            MessageInboundValidator::new(config.clone(), messaging.clone(), security.clone(), shutdown_token.clone())
        );

        let transaction = Arc::new(KeyMasterTransactionService::new(
            config.clone(),
            format.clone(),
            mongo.clone(),
            cli.restore,
        ));

        let filehost = Arc::new(FilehostServiceImpl::new(config.clone(), format.clone(), outbound.clone()));

        // List data tables (exclusing redolog and tracking). They get truncated on restore (when not resuming).
        let data_tables = vec![
            NOM_COLLECTION_CA_CLES.to_string(),
            // NOM_COLLECTION_SYMMETRIQUE_CLES.to_string(),
            // NOM_COLLECTION_CONFIGURATION.to_string(),
        ];
        let backup = Arc::new(DomainBackupServiceImpl::new(
            config.clone(),
            security.clone(),
            outbound.clone(),
            security.clone(),
            mongo.clone(),
            transaction.ca.clone(), // Transaction is a wrapper for the CA service
            filehost.clone(),
            data_tables
        ));

        // Flow services (business logic)
        let ca_service = Arc::new(
            MaitreDesClesCAServiceImpl::new(
                outbound.clone(),
                transaction.clone(),
                mongo.clone(),
                backup.clone(),
            )
        );
        let symmetric_service = Arc::new(
            MaitreDesClesSymmetricServiceImpl::new(
                config.clone(),
                outbound.clone(),
                security.clone(),
                security.clone(),
                mongo.clone(),
                decryption.clone()
            )
        );

        info!("Configure middleware resources : queues, index, tables, ...");
        ca_service.configure(messaging.as_ref(), config.as_ref()).await?;
        symmetric_service.configure(messaging.as_ref(), config.as_ref()).await?;

        info!("Connect services, start maintenance threads");
        start_threads(
            &mut join_set,
            security.clone(),
            messaging.as_ref(),
            inbound.clone(),
            filehost.clone(),
            ca_service.clone(),
            symmetric_service.clone(),
            shutdown_token.clone(),
            cli.restore,
            master_key,
        ).await?;

        Ok(AppContext {
            join_set,
            config: config.clone(),
            mongo,
            outbound,
            decryption,
            shutdown_token,
        })
    }
}

async fn init_config() -> Result<ConfigServiceDbImpl, CommonError> {
    let config = charger_configuration()?;
    let mongo = charger_configuration_mongo(config.get_configuration_pki())?;
    Ok(ConfigServiceDbImpl::new(Arc::new(config), Arc::new(mongo)))
}

async fn init_security(config: &dyn ConfigService) -> Result<SecurityServiceImpl, CommonError> {
    let validator = build_store_path_v2(&config.get_configuration_pki().ca_certfile).map_err(|e| e.to_string())?;
    let private_key = config.get_configuration_pki().get_enveloppe_privee();
    let encryption_key = private_key.enveloppe_pub.clone();

    let security_impl = SecurityServiceImpl::new(
        private_key,
        Arc::new(validator),
        Arc::new(CleChiffrageHandlerImpl::new()),
    );

    // Trick for KeyMaster - use own key for encryption. DO NOT DO THIS WITH OTHER DOMAINS.
    security_impl.add_encryption_publickey(encryption_key)?;

    Ok(security_impl)
}

async fn start_threads(
    join_set: &mut JoinSet<()>,
    security: Arc<SecurityServiceImpl>,
    messaging: &MessagingServiceImpl,
    inbound: Arc<MessageInboundValidator>,
    filehost: Arc<FilehostServiceImpl>,
    ca_service: Arc<MaitreDesClesCAServiceImpl>,
    symmetric_service: Arc<MaitreDesClesSymmetricServiceImpl>,
    shutdown_token: CancellationToken,
    is_restoring: bool,
    master_key: Option<PKey<Private>>,
) -> Result<(), CommonError> {

    // Connect to RabbitMQ (throws error on failure).
    // This also spawns all other required threads.
    messaging.start(join_set, shutdown_token.clone()).await?;
    debug!("Started messaging service, connection OK");

    // Spawn other service maintenance threads
    let shutdown_token_clone = shutdown_token.clone();
    join_set.spawn(async move { security.run(shutdown_token_clone).await });
    let shutdown_token_clone = shutdown_token.clone();
    join_set.spawn(async move { filehost.run(shutdown_token_clone).await });

    if ! is_restoring {
        // Spawn consumer threads
        ca_service.start(join_set, inbound.clone())?;
        symmetric_service.start(join_set, inbound.clone())?;
    } else {
        let master_key = match master_key {
            Some(key) => key,
            None => panic!("Master key not provided for restoring, aborting")
        };
        info!("Not starting consumer threads - restoring from backup");
        let shutdown_token_clone = shutdown_token.clone();
        join_set.spawn(async move {
            restore_from_backup(ca_service, symmetric_service, &master_key, shutdown_token_clone).await
        });
    }

    Ok(())
}
