use crate::constants::*;
use crate::external::mongo::{create_index_mongodb_custom, create_index_mongodb_partition};
use crate::external::mq::init_symmetric_queues;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::chrono::Timelike;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::futures::StreamExt;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::mongo_dao::{MongoDaoImpl, MongoDaoTyped};
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::tokio::task::JoinSet;
use millegrilles_common_rust::tracing::{debug, error, warn};
use millegrilles_common_rust::v3::ConfigService;
use millegrilles_common_rust::v3::facades::message_inbound::{MessageInboundValidator, MessageValidated};
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use std::sync::Arc;
use millegrilles_common_rust::certificats::VerificateurPermissions;

#[async_trait]
pub trait MaitreDesClesSymmetricService {}

pub struct MaitreDesClesSymmetricServiceImpl {
    _config: Arc<dyn ConfigService>,
    _outgoing: Arc<MessageOutboundFacade>,
    mongo: Arc<MongoDaoImpl>,
}

impl MaitreDesClesSymmetricServiceImpl {
    pub fn new(config: Arc<dyn ConfigService>, outgoing: Arc<MessageOutboundFacade>, mongo: Arc<MongoDaoImpl>) -> Self {
        Self { _config: config, _outgoing: outgoing, mongo }
    }

    pub async fn configure(&self, mq: &MessagingServiceImpl, config: &ConfigServiceDbImpl) -> Result<(), CommonError> {
        init_symmetric_queues(mq)?;
        create_index_mongodb_custom(self.mongo.as_ref(), config.config.as_ref(), NOM_COLLECTION_SYMMETRIQUE_CLES).await?;
        create_index_mongodb_partition(self.mongo.as_ref(), config.config.as_ref()).await?;
        Ok(())
    }

    pub fn start(self: Arc<Self>, join_set: &mut JoinSet<()>, incoming: Arc<MessageInboundValidator>) -> Result<(), CommonError> {

        // Ticker jobs
        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_ticker_thread(incoming_clone).await});

        // Symmetric queues

        // todo!()
        Ok(())
    }

    async fn process_ticker_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/symmetric/job_ticker", DOMAINE_NOM).as_str()
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    let mongo = self.mongo.as_ref();
                    if let Err(e) = ticker_job_symmetric(mongo, message).await {
                        error!("Ticker job ca failed: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Error processing ticker message: {}", e);
                }
            }
        }
    }
}

impl MaitreDesClesSymmetricService for MaitreDesClesSymmetricServiceImpl {
}

async fn ticker_job_symmetric<M>(mongo: &M, trigger: MessageValidated) -> Result<(), CommonError>
where M: MongoDaoTyped
{
    // Ensure this is an authorized module
    if let Ok(true) = trigger.certificate.verifier_roles_string(vec![ROLE_TICKER.to_string()]) {
        // Ok
    } else {
        debug!("Ticker message without ticker (ceduleur) role, ignoring");
        return Ok(());
    }

    let trigger_value: MessageCedule = trigger.message.deserialize()?;

    let hour = trigger_value.get_date().hour();
    let minute = trigger_value.get_date().minute();

    debug!("ticker_job_symmetric for h:{} m:{}",hour,minute);

    Ok(())
}
