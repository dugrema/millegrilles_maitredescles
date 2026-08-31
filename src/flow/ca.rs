use crate::constants::*;
use crate::external::mongo::{check_key_exists, create_index_mongodb_custom, marquer_cles_ca_timeout, process_ca_key_sync};
use crate::external::mq::{QUEUE_CA_BACKUP, QUEUE_CA_NEWKEYS, QUEUE_CA_TICKER, init_ca_queues};
use crate::flow::maintenance::validate_ticker;
use crate::flow::transactions::KeyMasterTransactionService;
use crate::models::ErrorMessage;
use crate::models::TransactionCleV2;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::chiffrage_cle::CommandeAjouterCleDomaine;
use millegrilles_common_rust::chrono::Timelike;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::futures::StreamExt;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::mongo_dao::{MongoDaoImpl, MongoDaoTyped};
use millegrilles_common_rust::tokio::task::JoinSet;
use millegrilles_common_rust::tracing::{debug, error, warn};
use millegrilles_common_rust::v3::facades::message_inbound::{MessageInboundValidator, MessageValidated};
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::{ConfigService, FormatService};
use millegrilles_common_rust::{serde_json, tokio};
use std::sync::Arc;

#[async_trait]
pub trait MaitreDesClesCAService {}

pub struct MaitreDesClesCAServiceImpl {
    config: Arc<dyn ConfigService>,
    outbound: Arc<MessageOutboundFacade>,
    transaction: Arc<KeyMasterTransactionService>,
    mongo: Arc<MongoDaoImpl>,
    format: Arc<dyn FormatService>,
}

impl MaitreDesClesCAServiceImpl {
    pub fn new(
        config: Arc<dyn ConfigService>,
        outbound: Arc<MessageOutboundFacade>,
        transaction: Arc<KeyMasterTransactionService>,
        mongo: Arc<MongoDaoImpl>,
        format: Arc<dyn FormatService>
    ) -> Self {
        Self { config, outbound, transaction, mongo, format, }
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
                        self.transaction.as_ref(),
                        self.mongo.as_ref(),
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
    transaction: &KeyMasterTransactionService,
    mongo: &M,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let delivery_info = wrapper.delivery_info.clone();

    // Parse to validate and check for duplicates
    let command: CommandeAjouterCleDomaine = wrapper.message.deserialize()?;
    let signature = command.signature;

    // Check if the key already exists.
    let key_id = signature.get_cle_ref()?.to_string();

    if ! check_key_exists(mongo, key_id.as_str()).await? {
        debug!("save_new_ca_key Saving new key with id {}", key_id);

        // Generate a new transaction document
        let value = serde_json::to_value(TransactionCleV2 { signature })?;
        transaction.process_value(DOMAINE_NOM, TRANSACTION_CLE_V2, value).await?;
    }

    outbound.respond(delivery_info, ErrorMessage::ok()).await
}
