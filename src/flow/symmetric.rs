use crate::constants::DOMAINE_NOM;
use crate::external::mq::init_symmetric_queues;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::futures::StreamExt;
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::v3::facades::message_inbound::{MessageInboundValidator, MessageValidated};
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use std::sync::Arc;

#[async_trait]
pub trait MaitreDesClesSymmetricService {}

pub struct MaitreDesClesSymmetricServiceImpl {}

impl MaitreDesClesSymmetricServiceImpl {
    pub fn new(mq: &MessagingServiceImpl) -> Result<Self, CommonError> {
        let mut service = Self {};
        init_symmetric_queues(mq)?;
        Ok(service)
    }

    pub fn start(self: Arc<Self>, incoming: Arc<MessageInboundValidator>) -> Result<(), CommonError> {

        // Spawn queue consuming tasks

        // Ticker jobs
        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        tokio::spawn(async move {self_clone.process_ticker_thread(incoming_clone).await});

        // CA queue

        todo!()
    }

    async fn process_ticker_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let mut streamer = incoming.consume_named_queue(
            format!("{}/ca_job_ticker", DOMAINE_NOM).as_str()
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
