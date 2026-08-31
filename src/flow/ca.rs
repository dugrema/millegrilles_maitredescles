use crate::constants::*;
use crate::external::mongo::{check_key_exists, count_ca_undecipherable_keys, create_index_mongodb_ca, create_index_mongodb_symmetric, marquer_cles_ca_timeout, process_ca_key_sync};
use crate::external::mq::{init_ca_queues, QUEUE_CA_BACKUP, QUEUE_CA_NEWKEYS, QUEUE_CA_REQUESTS, QUEUE_CA_TICKER};
use crate::flow::maintenance::validate_ticker;
use crate::flow::transactions::KeyMasterTransactionService;
use crate::models::{ErrorMessage, RecupererCleCa, ReponseClesNonDechiffrables, RequeteClesNonDechiffrable, RowCleCaRef, UndecipherableKeyCountResponse};
use crate::models::TransactionCleV2;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::chiffrage_cle::CommandeAjouterCleDomaine;
use millegrilles_common_rust::chrono::Timelike;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::futures::StreamExt;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoImpl, MongoDaoTyped};
use millegrilles_common_rust::tokio::task::JoinSet;
use millegrilles_common_rust::tracing::{debug, error, warn};
use millegrilles_common_rust::v3::facades::message_inbound::{MessageInboundValidator, MessageValidated};
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::{ConfigService, FormatService};
use millegrilles_common_rust::{serde_json, tokio};
use std::sync::Arc;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::mongodb::options::Hint;
use crate::external::crypto::SymmetricEncryptionHandler;

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
        create_index_mongodb_ca(self.mongo.as_ref(), config.config.as_ref() ).await?;
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

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_requests_thread(incoming_clone).await});

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

    async fn process_requests_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAINE_NOM, QUEUE_CA_REQUESTS).as_str()
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    let delivery_info = message.delivery_info.clone();  // Clone for error response
                    if let Err(e) = process_requests(
                        self.config.as_ref(),
                        self.outbound.as_ref(),
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
                                err: Some("Error processing request".to_string()),
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
    // if minute % 30 == 25
    // {
    //     if let Err(e) = process_ca_key_sync(mongo).await {
    //         warn!("ticker_job_ca Error processing CA key sync : {:?}", e);
    //     }
    // }

    // if hour % 6 == 3 && minute == 25 {
    //     if let Err(e) = marquer_cles_ca_timeout(mongo).await {
    //         warn!("ticker_job_ca Failed to mark CA key timeout : {:?}", e);
    //     }
    // }

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


async fn process_requests(
    config: &dyn ConfigService,
    outbound: &MessageOutboundFacade,
    mongo: &MongoDaoImpl,
    wrapper: MessageValidated
) -> Result<(), CommonError> {
    let action = match wrapper.message.routage.as_ref() {
        Some(routage) => match routage.action.as_ref() {
            Some(action) => action.clone(),
            None => {
                // Bad message, no action
                return Err(CommonError::Str("Bad message, no action was found"))
            }
        },
        None => {
            // Bad message, no routing
            return Err(CommonError::Str("Bad message, no routing information was found"))
        }
    };

    match action.as_str() {
        //                 REQUETE_COMPTER_CLES_NON_DECHIFFRABLES => requete_compter_cles_non_dechiffrables_ca(middleware, message).await,
        //                 REQUETE_SYNCHRONISER_CLES => requete_synchronizer_cles(middleware, message, &mut session).await,
        //                 REQUETE_CLES_NON_DECHIFFRABLES_V2 => requete_cles_non_dechiffrables_v2(middleware, message, &mut session).await,
        REQUETE_COMPTER_CLES_NON_DECHIFFRABLES => request_count_undecipherable_keys(outbound, mongo, wrapper).await,
        REQUETE_SYNCHRONISER_CLES => todo!(),
        REQUETE_CLES_NON_DECHIFFRABLES_V2 => request_fetch_key_batch(outbound, mongo, wrapper).await,
        _ => {
            warn!("process_requests (CA) Unsupported action type: {}", action);
            Err(CommonError::Str("Bad message, unsupported action type"))
        }
    }
}

async fn request_count_undecipherable_keys(
    outbound: &MessageOutboundFacade,
    mongo: &dyn MongoDao,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    let value = count_ca_undecipherable_keys(mongo).await?;
    let response = UndecipherableKeyCountResponse { compte: value };
    outbound.respond(wrapper.delivery_info, serde_json::to_value(&response)?).await
}

async fn request_fetch_key_batch(
    outbound: &MessageOutboundFacade,
    mongo: &MongoDaoImpl,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    let request: RequeteClesNonDechiffrable = wrapper.message.deserialize()?;

    let mut idx = request.skip.unwrap_or_else(||0);
    let mut cursor = {
        let collection = mongo.get_collection_typed::<RowCleCaRef>(NOM_COLLECTION_CA_CLES)?;
        // Using the hint on MongoDB _id_ to iterate in order through the whole collection.
        // If we skip any undecipherable keys, we can double-back at the end (we'll see the count)
        collection
            .find(doc!{})
            .hint(Hint::Name("_id_".to_string()))
            .skip(idx)
            .await?
    };

    let limite_docs = request.limite.unwrap_or_else(|| 100) as usize;
    let mut undecipherable_keys: Vec<RecupererCleCa> = Vec::new();
    let mut date_creation = None;

    while cursor.advance().await? {
        idx += 1;  // Compter toutes les cles pour permettre d'aller chercher la suite dans la prochaine requete.
        let current_key = cursor.deserialize_current()?;

        // Cumulate undecipherable keys only (we iterate through the whole DB)
        if Some(true) == current_key.non_dechiffrable {
            date_creation = Some(current_key.date_creation.clone());
            undecipherable_keys.push(current_key.try_into()?);
            // Check if batch is complete
            if undecipherable_keys.len() >= limite_docs {
                break
            }
        }
    }

    let response = ReponseClesNonDechiffrables {
        cles: undecipherable_keys,
        date_creation_max: date_creation,
        idx,
    };

    outbound.respond(wrapper.delivery_info, serde_json::to_value(response)?).await
}