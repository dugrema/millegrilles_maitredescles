use millegrilles_common_rust::certificats::build_store_path_v2;
use millegrilles_common_rust::chiffrage_cle::CleChiffrageHandlerImpl;
use millegrilles_common_rust::configuration::{ConfigDb, ConfigMessages, charger_configuration, charger_configuration_mongo};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::{MongoDaoImpl, initialiser};
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::tracing::{debug, info};
use millegrilles_common_rust::v3::facades::message_inbound::MessageInboundValidator;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::format_service::FormatServiceImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::impls::security_service::SecurityServiceImpl;
use millegrilles_common_rust::v3::{ConfigService, FormatService, MessagingService, PkiService};
use std::sync::Arc;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::rabbitmq_dao::ConfigQueue;
use millegrilles_common_rust::tokio::spawn;
use crate::builder::{MaitreDesClesManager, MaitreDesClesSymmetricManager};
use crate::ca_manager::preparer_index_mongodb_ca;
use crate::flow::ca::MaitreDesClesCAServiceImpl;
use crate::flow::symmetric::MaitreDesClesSymmetricServiceImpl;
use crate::mongodb_manager::{preparer_index_mongodb, thread_entretien_manager_mongodb};

/// Composition object with services from common library
pub struct AppContext {
    pub config: Arc<dyn ConfigService>,
    pub config_db: Arc<dyn ConfigDb>,
    // pub redis: Arc<RedisService>,
    pub pki: Arc<dyn PkiService>,
    pub messaging: Arc<dyn MessagingService>,
    pub format: Arc<dyn FormatService>,
    pub mongo: Arc<MongoDaoImpl>,
    pub outgoing: Arc<MessageOutboundFacade>,
    pub incoming: Arc<MessageInboundValidator>,
}

impl AppContext {
    pub async fn new() -> Result<Self, CommonError> {
        // Basic services
        let config = Arc::new(init_config().await?);
        // let redis = Arc::new(init_redis(config.as_ref()).await?);
        let security = Arc::new(init_security(config.as_ref()).await?);
        let messaging = Arc::new(MessagingServiceImpl::new(config.clone()));
        let format = Arc::new(FormatServiceImpl::new(config.clone()));

        let mongo = Arc::new(
            initialiser(config.get_configuration_pki(), config.get_configuraiton_mongo())?
        );

        // Facades
        let outgoing = Arc::new(
            MessageOutboundFacade::new(messaging.clone(), format.clone()),);
        let incoming = Arc::new(
            MessageInboundValidator::new(config.clone(), messaging.clone(), security.clone()));

        // Flow services (business logic)
        let ca_service = Arc::new(
            MaitreDesClesCAServiceImpl::new(
                messaging.as_ref(),
                incoming.as_ref(),
            )?
        );
        let symmetric_service = Arc::new(
            MaitreDesClesSymmetricServiceImpl::new(
                messaging.as_ref(),
                incoming.as_ref(),
            )?
        );

        info!("Connect services, start maintenance threads");
        start_threads(
            security.clone(),
            messaging.as_ref(),
            // redis.clone(),
        ).await?;

        Ok(AppContext {
            config: config.clone(),
            config_db: config,
            // redis,
            pki: security,
            messaging,
            format,
            mongo,
            outgoing,
            incoming
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
    security: Arc<SecurityServiceImpl>,
    messaging: &MessagingServiceImpl,
    // redis: Arc<RedisService>,
) -> Result<(), CommonError> {

    // Connect to RabbitMQ (throws error on failure).
    // This also spawns all other required threads.
    messaging.start().await?;
    debug!("Started messaging service");

    // Spawn other service maintenance threads
    tokio::task::spawn(async move { security.run().await });
    // tokio::task::spawn(async move { redis.run().await });

    Ok(())
}
