use crate::constants::*;
use crate::external::mongo::{create_index_mongodb_custom, marquer_cles_ca_timeout, process_ca_key_sync};
use crate::external::mq::init_ca_queues;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::chrono::Timelike;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::futures::StreamExt;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::mongo_dao::{MongoDaoImpl, MongoDaoTyped};
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::tracing::{error, warn};
use millegrilles_common_rust::v3::facades::message_inbound::{MessageInboundValidator, MessageValidated};
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::ConfigService;
use std::sync::Arc;

#[async_trait]
pub trait MaitreDesClesCAService {}

pub struct MaitreDesClesCAServiceImpl {
    _config: Arc<dyn ConfigService>,
    _outgoing: Arc<MessageOutboundFacade>,
    mongo: Arc<MongoDaoImpl>,
}

impl MaitreDesClesCAServiceImpl {
    pub fn new(config: Arc<dyn ConfigService>, outgoing: Arc<MessageOutboundFacade>, mongo: Arc<MongoDaoImpl>) -> Self {
        Self { _config: config, _outgoing: outgoing, mongo }
    }

    pub async fn configure(&self, mq: &MessagingServiceImpl, config: &ConfigServiceDbImpl) -> Result<(), CommonError> {
        init_ca_queues(mq)?;
        create_index_mongodb_custom(self.mongo.as_ref(), config.config.as_ref(), NOM_COLLECTION_CA_CLES).await?;
        Ok(())
    }

    /// Call to spawn the consumer threads
    pub fn start(self: Arc<Self>, incoming: Arc<MessageInboundValidator>) -> Result<(), CommonError> {

        // Spawn queue consuming tasks

        // Ticker jobs
        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        tokio::spawn(async move {self_clone.process_ticker_thread(incoming_clone).await});

        // Backup queue
        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        tokio::spawn(async move {self_clone.process_backup_thread(incoming_clone).await});

        // CA queue

        //todo!()
        Ok(())
    }

    async fn process_ticker_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/ca_job_ticker", DOMAINE_NOM).as_str()
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            let message: MessageValidated = result.expect("Message streaming failed");
            let mongo = self.mongo.as_ref();
            if let Err(e) = ticker_job_ca(mongo, message).await {
                error!("Ticker job ca failed: {}", e);
            }
        }
    }

    async fn process_backup_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/backup", DOMAINE_NOM).as_str()
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            let message: MessageValidated = result.expect("Message streaming failed");
            todo!()
        }
    }
}

impl MaitreDesClesCAService for MaitreDesClesCAServiceImpl {
}

pub async fn ticker_job_ca<M>(mongo: &M, trigger: MessageValidated) -> Result<(), CommonError>
    where M: MongoDaoTyped
{
    let trigger_value: MessageCedule = trigger.message.deserialize()?;

    let hour = trigger_value.get_date().hour();
    let minute = trigger_value.get_date().minute();

    // The sync content is produced every hour at minute 42.
    // Try to process twice per hour in case the first pass is missed
    if minute % 30 == 25
    {
        if let Err(e) = process_ca_key_sync(mongo).await {
            warn!("ticker_job_ca Error processing CA key sync : {:?}", e);
        }
    }

    if hour % 6 == 3 && minute == 25 {
        if let Err(e) = marquer_cles_ca_timeout(mongo).await {
            warn!("ticker_job_ca Failed to mark CA key timeout : {:?}", e);
        }
    }

    Ok(())
}
