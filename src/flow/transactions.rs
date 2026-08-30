use crate::constants::{NOM_COLLECTION_TRANSACTIONS_CA, TRANSACTION_CLE, TRANSACTION_CLE_V2};
use crate::maitredescles_commun::{RowCleCaRef, TransactionCleV2};
use crate::models::TransactionWrapper;
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::Document;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::mongodb::options::WriteModel;

pub async fn process_ca_transaction<F, Fut>(
    mongo: &dyn MongoDao,
    router: F,
    wrapper: TransactionWrapper,
) -> Result<(), CommonError>
where F: Fn(String, TransactionWrapper) -> Fut,
      Fut: Future<Output = Result<TransactionOperationAggregator, CommonError>>
{
    // Start a session
    let mut session = mongo.get_session().await?;

    match process_atomic_transaction(mongo, &mut session, router, wrapper).await {
        Ok(()) => {
            session.commit_transaction().await?;
            Ok(())
        },
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)
        },
    }
}

async fn process_atomic_transaction<F, Fut>(
    mongo: &dyn MongoDao,
    session: &mut ClientSession,
    router: F,
    wrapper: TransactionWrapper
) -> Result<(), CommonError>
where F: Fn(String, TransactionWrapper) -> Fut,
    Fut: Future<Output = Result<TransactionOperationAggregator, CommonError>>
{
    let action = match wrapper.message.routage.as_ref() {
        Some(r) => match r.action.as_ref() {
            Some(a) => a.to_string(),
            None => return Err(CommonError::Str("Transaction with no routing action"))
        },
        None => return Err(CommonError::Str("Transaction with no routing information"))
    };

    // Save the transaction detail in the redo log (transaction table) for the domain
    persist_transaction(&wrapper).await?;

    // Run the domain router to generate MongoDB write operations
    // let operations = ca_transaction_router(action.as_str(), wrapper).await?;
    let operations = router(action, wrapper).await?;

    // Run the operations within a database session - will rollback everything on error
    run_transaction_aggregator(mongo, session, operations).await?;

    Ok(())
}

#[derive(Debug, Clone)]
pub struct BatchInsertions {
    collection_name: String,
    insertions: Vec<Document>
}

impl BatchInsertions {
    pub fn new(collection_name: &str, insertions: Vec<Document>) -> Self {
        Self {
            collection_name: collection_name.to_string(),
            insertions,
        }
    }
}

#[derive(Debug, Clone)]
/// Used to aggregate transaction operations.
/// Simplifies batching on rebuilds (redo).
pub struct TransactionOperationAggregator {
    /// Insertions run first as a batch, they must not have any dependency (e.g. deletion to avoid duplicate)
    batch_insertions: Option<Vec<BatchInsertions>>,
    /// Operations that can run concurrently (e.g. updating/deleting entries from different collections)
    /// These operations can depend on batch_insertions because insertions always run first.
    unordered: Option<Vec<WriteModel>>,
    /// Operations that must be run in order, e.g. "update val=val+1" then "delete where val>10".
    /// They will always be run after the batch_insertions and unordered operations.
    ordered: Option<Vec<WriteModel>>,
}

impl TransactionOperationAggregator {
    pub fn new() -> Self {
        Self {
            batch_insertions: None,
            unordered: None,
            ordered: None
        }
    }

    pub fn batch_insertion(&mut self, operation: BatchInsertions) -> Result<&mut Self, CommonError> {
        if self.ordered.is_some() {
            Err(CommonError::Str("Cannot use batch insertion once ordered list is used"))?
        }
        self.batch_insertions.get_or_insert(vec![]).push(operation);
        Ok(self)
    }

    pub fn add_unordered(&mut self, operation: WriteModel) -> Result<&mut Self, CommonError> {
        if self.ordered.is_some() {
            Err(CommonError::Str("Cannot use unordered operations once ordered list is used"))?
        }
        self.unordered.get_or_insert(vec![]).push(operation);
        Ok(self)
    }

    pub fn add_ordered(&mut self, operation: WriteModel) -> &mut Self {
        self.ordered.get_or_insert(vec![]).push(operation);
        self
    }

}

pub async fn ca_transaction_router(
    action: String,
    wrapper: TransactionWrapper
) -> Result<TransactionOperationAggregator, CommonError> {
    match action.as_str() {
        TRANSACTION_CLE => todo!(),  // transaction_cle(middleware, transaction, session).await,
        TRANSACTION_CLE_V2 => save_new_key(wrapper).await,
        _ => Err(CommonError::Str("Unknown transaction action"))
    }
}

async fn persist_transaction(wrapper: &TransactionWrapper) -> Result<(), CommonError> {
    todo!();
    Ok(())
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
        date_creation: Utc::now(),
        // Deprecated fields
        format: None,
        iv: None,
        tag: None,
        header: None,
    };

    let batch_insertions = BatchInsertions::new(
        NOM_COLLECTION_TRANSACTIONS_CA,
        vec![bson::serialize_to_document(&insert_doc)?],
    );
    aggregator.batch_insertion(batch_insertions)?;

    Ok(aggregator)
}

async fn run_transaction_aggregator(
    mongo: &dyn MongoDao,
    session: &mut ClientSession,
    ops_aggregator: TransactionOperationAggregator
) -> Result<(), CommonError> {
    // Run batch inserts first
    if let Some(batch_insertions) = ops_aggregator.batch_insertions {
        for batch_insertion in batch_insertions {
            let collection = mongo.get_collection(batch_insertion.collection_name.as_str())?;
            collection.insert_many(batch_insertion.insertions).await?;
        }
    }

    // Run unordered operations
    if let Some(unordered) = ops_aggregator.unordered {
        mongo.bulk_write(unordered, Some(session), false).await?;
    }

    // Ordered operations last
    if let Some(ordered) = ops_aggregator.ordered {
        mongo.bulk_write(ordered, Some(session), true).await?;
    }

    Ok(())
}
