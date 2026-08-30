use crate::constants::*;
use crate::external::mongo::{create_index_mongodb_custom, marquer_cles_ca_timeout, process_ca_key_sync, save_new_ca_key};
use crate::external::mq::{init_ca_queues, QUEUE_CA_BACKUP, QUEUE_CA_NEWKEYS, QUEUE_CA_TICKER};
use crate::flow::maintenance::validate_ticker;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::chrono::Timelike;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::futures::StreamExt;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::mongo_dao::{MongoDaoImpl, MongoDaoTyped};
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::tokio::task::JoinSet;
use millegrilles_common_rust::tracing::{debug, error, warn};
use millegrilles_common_rust::v3::{ConfigService, FormatService};
use millegrilles_common_rust::v3::facades::message_inbound::{MessageInboundValidator, MessageValidated};
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use std::sync::Arc;
use millegrilles_common_rust::chiffrage_cle::CommandeAjouterCleDomaine;
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use crate::models::ErrorMessage;

#[async_trait]
pub trait MaitreDesClesCAService {}

pub struct MaitreDesClesCAServiceImpl {
    config: Arc<dyn ConfigService>,
    outbound: Arc<MessageOutboundFacade>,
    mongo: Arc<MongoDaoImpl>,
    format: Arc<dyn FormatService>,
}

impl MaitreDesClesCAServiceImpl {
    pub fn new(config: Arc<dyn ConfigService>, outgoing: Arc<MessageOutboundFacade>, mongo: Arc<MongoDaoImpl>, format: Arc<dyn FormatService>) -> Self {
        Self { config: config, outbound: outgoing, mongo, format, }
    }

    pub async fn configure(&self, mq: &MessagingServiceImpl, config: &ConfigServiceDbImpl) -> Result<(), CommonError> {
        init_ca_queues(mq)?;
        create_index_mongodb_custom(self.mongo.as_ref(), config.config.as_ref(), NOM_COLLECTION_CA_CLES).await?;
        Ok(())
    }

    /// Call to spawn the consumer threads
    pub fn start(self: Arc<Self>, join_set: &mut JoinSet<()>, incoming: Arc<MessageInboundValidator>) -> Result<(), CommonError> {

        // Spawn queue consuming tasks

        // Ticker jobs
        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_ticker_thread(incoming_clone).await});

        // Backup queue
        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_backup_thread(incoming_clone).await});

        // Key processing for CA
        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_newkeys_thread(incoming_clone).await});

        //todo!()
        Ok(())
    }

    async fn process_ticker_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_CA_TICKER).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = ticker_job_ca(self.mongo.as_ref(), message).await {
                        error!("Ticker job ca failed: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error processing ticker message: {}", e);
                }
            }
        }
        debug!("process_ticker_thread Closed");
    }

    async fn process_backup_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_CA_BACKUP).as_str()
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    error!("TODO - process backup message");
                }
                Err(e) => {
                    error!("Backup job ca message parsing failed: {}", e);
                }
            }
        }
        debug!("process_backup_thread Closed");
    }

    async fn process_newkeys_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_CA_NEWKEYS).as_str()
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    let delivery_info = message.delivery_info.clone();  // Clone for error response
                    if let Err(e) = process_newkeys(
                        self.outbound.as_ref(),
                        self.mongo.as_ref(),
                        self.format.as_ref(),
                        self.config.as_ref(),
                        message
                    ).await {
                        error!("process_newkeys_thread Saving key failed: {}", e);
                        // Attempt to reply with an error message
                        self.outbound.respond(
                            delivery_info,
                            ErrorMessage {
                                ok: false,
                                code: Some(1),
                                err: Some("Error saving key".to_string()),
                            }
                        ).await.ok();
                    }
                }
                Err(e) => {
                    error!("Backup job ca message parsing failed: {}", e);
                }
            }
        }
        debug!("process_backup_thread Closed");
    }
}

impl MaitreDesClesCAService for MaitreDesClesCAServiceImpl {
}

async fn ticker_job_ca<M>(mongo: &M, trigger: MessageValidated) -> Result<(), CommonError>
    where M: MongoDaoTyped
{
    // Ensure this is an authorized module
    if let Err(e) = validate_ticker(&trigger).await {
        error!("Invalid ticker message, rejecting: {}", e);
        return Ok(());
    }

    let trigger_value: MessageCedule = trigger.message.deserialize()?;

    let hour = trigger_value.get_date().hour();
    let minute = trigger_value.get_date().minute();

    debug!("ticker_job_ca for h:{} m:{}",hour,minute);

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

async fn process_newkeys<M>(
    outbound: &MessageOutboundFacade,
    mongo: &M,
    formatter: &dyn FormatService,
    config: &dyn ConfigService,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let delivery_info = wrapper.delivery_info.clone();
    save_new_ca_key(mongo, formatter, config, wrapper).await?;
    outbound.respond(delivery_info, ErrorMessage::ok()).await
}
