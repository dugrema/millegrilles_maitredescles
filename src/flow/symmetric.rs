use crate::constants::*;
use crate::external::mongo::{create_index_mongodb_custom, create_index_mongodb_partition};
use crate::external::mq::init_symmetric_queues;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::futures::StreamExt;
use millegrilles_common_rust::mongo_dao::MongoDaoImpl;
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::v3::facades::message_inbound::{MessageInboundValidator, MessageValidated};
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::ConfigService;
use std::sync::Arc;
use millegrilles_common_rust::tokio::task::JoinSet;

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

        // Spawn queue consuming tasks

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
            format!("{}/symmetric_job_ticker", DOMAINE_NOM).as_str()
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            let message: MessageValidated = result.expect("Message streaming failed");
            todo!()
        }
    }
}

impl MaitreDesClesSymmetricService for MaitreDesClesSymmetricServiceImpl {
}
