use crate::constants::{NOM_COLLECTION_CA_CLES, NOM_COLLECTION_TRACKING_CA, NOM_COLLECTION_TRANSACTIONS_CA, TRANSACTION_CLE, TRANSACTION_CLE_V2};
use crate::models::RowCleCaRef;
use crate::models::TransactionCleV2;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson;
use millegrilles_common_rust::error::{Error as CommonError, Error};
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::v3::impls::transaction_service::TransactionServiceImpl;
use millegrilles_common_rust::v3::models::{BatchInsertions, TransactionOperationAggregator, TransactionWrapper};
use millegrilles_common_rust::v3::{ConfigService, FormatService, TransactionRouter, TransactionService};
use std::sync::Arc;

pub struct KeyMasterTransactionService {
    ca: Box<dyn TransactionService>,
}

impl KeyMasterTransactionService {
    pub fn new(
        config: Arc<dyn ConfigService>,
        format: Arc<dyn FormatService>,
        mongo: Arc<dyn MongoDao>
    ) -> Self {
        let ca_router = CaTransactionRouter {};
        let ca_service =  TransactionServiceImpl::new(
            config,
            format,
            mongo,
            NOM_COLLECTION_TRANSACTIONS_CA.to_string(),
            NOM_COLLECTION_TRACKING_CA.to_string(),
            Box::new(ca_router)
        );

        Self {
            ca: Box::new(ca_service),
        }
    }

    pub async fn process_transaction(&self, wrapper: TransactionWrapper) -> Result<(), CommonError> {
        self.ca.process_transaction(wrapper).await
    }

    pub async fn process_value(&self, domain: &str, action: &str, value: Value) -> Result<(), Error> {
        self.ca.process_value(domain, action, value).await
    }
}

struct CaTransactionRouter {}

#[async_trait]
impl TransactionRouter for CaTransactionRouter {
    async fn route(
        &self,
        action: String,
        wrapper: TransactionWrapper
    ) -> Result<TransactionOperationAggregator, CommonError> {
        match action.as_str() {
            TRANSACTION_CLE => todo!(),  // transaction_cle(middleware, transaction, session).await,
            TRANSACTION_CLE_V2 => save_new_key(wrapper).await,
            _ => Err(CommonError::Str("Unknown transaction action"))
        }
    }
}

async fn save_new_key(
    wrapper: TransactionWrapper
) -> Result<TransactionOperationAggregator, CommonError> {
    let mut aggregator = TransactionOperationAggregator::new();
    let transaction: TransactionCleV2 = wrapper.message.deserialize()?;

    let signature = transaction.signature;
    let cle_id = signature.get_cle_ref()?.to_string();

    let insert_doc = RowCleCaRef {
        cle_id: cle_id.as_str(),
        signature: (&signature).into(),
        non_dechiffrable: Some(true),
        date_creation: wrapper.message.estampille,
        // Deprecated fields
        format: None,
        iv: None,
        tag: None,
        header: None,
    };

    let batch_insertions = BatchInsertions::new(
        NOM_COLLECTION_CA_CLES,
        vec![bson::serialize_to_document(&insert_doc)?],
    );
    aggregator.batch_insertion(batch_insertions)?;

    Ok(aggregator)
}
