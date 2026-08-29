use crate::flow::ca::{MaitreDesClesCAService, MaitreDesClesCAServiceImpl};
use crate::flow::symmetric::{MaitreDesClesSymmetricService, MaitreDesClesSymmetricServiceImpl};
use millegrilles_common_rust::certificats::build_store_path_v2;
use millegrilles_common_rust::chiffrage_cle::CleChiffrageHandlerImpl;
use millegrilles_common_rust::configuration::{ConfigDb, ConfigMessages, charger_configuration, charger_configuration_mongo};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::{MongoDaoImpl, initialiser};
use millegrilles_common_rust::tokio::task::JoinSet;
use millegrilles_common_rust::tokio_util::sync::CancellationToken;
use millegrilles_common_rust::tracing::{debug, error, info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::MessageInboundValidator;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::format_service::FormatServiceImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::impls::security_service::SecurityServiceImpl;
use millegrilles_common_rust::v3::{ConfigService, FormatService, MessagingService, PkiService};
use std::sync::Arc;
use crate::external::mongo::load_symmetric_key;
use crate::maitredescles_rechiffrage::HandlerCleRechiffrage;

/// Composition object with services from common library
pub struct AppContext {
    pub join_set: JoinSet<()>,
    pub config: Arc<dyn ConfigService>,
    pub config_db: Arc<dyn ConfigDb>,
    // pub redis: Arc<RedisService>,
    pub pki: Arc<dyn PkiService>,
    pub messaging: Arc<dyn MessagingService>,
    pub format: Arc<dyn FormatService>,
    pub mongo: Arc<MongoDaoImpl>,
    pub outbound: Arc<MessageOutboundFacade>,
    pub inbound: Arc<MessageInboundValidator>,
    pub ca_service: Arc<dyn MaitreDesClesCAService>,
    pub symmetric_service: Arc<dyn MaitreDesClesSymmetricService>,
    pub decryption: Arc<HandlerCleRechiffrage>,
    pub shutdown_token: CancellationToken,
}

impl AppContext {
    pub async fn new() -> Result<Self, CommonError> {
        // Shutdown/cancel semantics
        let shutdown_token = CancellationToken::new();
        let mut join_set = JoinSet::new();

        // Basic services
        let config = Arc::new(init_config().await?);
        // let redis = Arc::new(init_redis(config.as_ref()).await?);
        let security = Arc::new(init_security(config.as_ref()).await?);
        let messaging = Arc::new(MessagingServiceImpl::new(config.clone(), security.clone()));
        let format = Arc::new(FormatServiceImpl::new(config.clone()));
        let decryption = Arc::new(HandlerCleRechiffrage::with_certificat(
            config.get_configuration_pki().get_enveloppe_privee()
        ));

        let mongo = Arc::new(
            initialiser(config.get_configuration_pki(), config.get_configuraiton_mongo())?
        );

        // Facades
        let outbound = Arc::new(
            MessageOutboundFacade::new(messaging.clone(), format.clone()),);
        let inbound = Arc::new(
            MessageInboundValidator::new(config.clone(), messaging.clone(), security.clone(), shutdown_token.clone())
        );

        // Flow services (business logic)
        let ca_service = Arc::new(
            MaitreDesClesCAServiceImpl::new(config.clone(), outbound.clone(), mongo.clone())
        );
        let symmetric_service = Arc::new(
            MaitreDesClesSymmetricServiceImpl::new(config.clone(), outbound.clone(), security.clone(), mongo.clone(), decryption.clone())
        );

        info!("Configure middleware resources : queues, index, tables, ...");
        ca_service.configure(messaging.as_ref(), config.as_ref()).await?;
        symmetric_service.configure(messaging.as_ref(), config.as_ref()).await?;

        info!("Connect services, start maintenance threads");
        start_threads(
            &mut join_set,
            security.clone(),
            messaging.as_ref(),
            // redis.clone(),
            inbound.clone(),
            ca_service.clone(),
            symmetric_service.clone(),
            shutdown_token.clone(),
        ).await?;

        // Try to load decryption key from mongo
        if let Err(e) = load_symmetric_key(
            mongo.as_ref(),
            config.get_configuration_pki().get_enveloppe_privee().as_ref(),
            decryption.as_ref()
        ).await {
            warn!("Error loading symmetric key : {}", e);
        }

        Ok(AppContext {
            join_set,
            config: config.clone(),
            config_db: config,
            // redis,
            pki: security,
            messaging,
            format,
            mongo,
            outbound,
            inbound,
            ca_service,
            symmetric_service,
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

// async fn init_redis(config: &dyn ConfigService) -> Result<RedisService, CommonError> {
//     let redis = RedisDao::new(config.get_configuration_instance().clone()).expect("connexion redis");
//     let redis_service = RedisService::new(redis).await?;
//
//     // Test the connection
//     let mut connection = redis_service.get_connection()?;
//     connection.ping().await.map_err(|e| e.to_string())?;
//
//     Ok(redis_service)
// }

async fn init_security(config: &dyn ConfigService) -> Result<SecurityServiceImpl, CommonError> {
    let validator = build_store_path_v2(&config.get_configuration_pki().ca_certfile).map_err(|e| e.to_string())?;
    let security_impl = SecurityServiceImpl::new(
        Arc::new(validator),
        CleChiffrageHandlerImpl::new(),
    );
    Ok(security_impl)
}

async fn start_threads(
    join_set: &mut JoinSet<()>,
    security: Arc<SecurityServiceImpl>,
    messaging: &MessagingServiceImpl,
    // redis: Arc<RedisService>,
    incoming: Arc<MessageInboundValidator>,
    ca_service: Arc<MaitreDesClesCAServiceImpl>,
    symmetric_service: Arc<MaitreDesClesSymmetricServiceImpl>,
    shutdown_token: CancellationToken,
) -> Result<(), CommonError> {

    // Connect to RabbitMQ (throws error on failure).
    // This also spawns all other required threads.
    messaging.start(join_set, shutdown_token.clone()).await?;
    debug!("Started messaging service, connection OK");

    // Spawn other service maintenance threads
    let shutdown_token_clone = shutdown_token.clone();
    join_set.spawn(async move { security.run(shutdown_token_clone).await });
    // tokio::task::spawn(async move { redis.run().await });

    // Spawn consumer threads
    ca_service.start(join_set, incoming.clone())?;
    symmetric_service.start(join_set, incoming.clone())?;

    Ok(())
}
