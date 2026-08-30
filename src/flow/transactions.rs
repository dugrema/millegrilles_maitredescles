use crate::models::TransactionWrapper;
use millegrilles_common_rust::bson::Document;
use millegrilles_common_rust::constantes::COMMANDE_AJOUTER_CLE_DOMAINES;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::mongodb::options::WriteModel;

pub async fn process_ca_transaction(mongo: &dyn MongoDao, wrapper: TransactionWrapper) -> Result<(), CommonError>{

    let action = match wrapper.message.routage.as_ref() {
        Some(r) => match r.action.as_ref() {
            Some(a) => a.to_string(),
            None => return Err(CommonError::Str("Transaction with no routing action"))
        },
        None => return Err(CommonError::Str("Transaction with no routing information"))
    };

    // Start a session
    let mut session = mongo.get_session().await?;

    match process_atomic_transaction(mongo, &mut session, action.as_str(), wrapper).await {
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

async fn process_atomic_transaction(
    mongo: &dyn MongoDao,
    session: &mut ClientSession,
    action: &str,
    wrapper: TransactionWrapper
) -> Result<(), CommonError> {
    // Save the transaction in the transaction table for the domain
    persist_transaction(&wrapper).await?;

    let operations = ca_transaction_router(mongo, session, action, wrapper).await?;

    // Run the operations within a database session - will rollback everything on error
    run_transaction_aggregator(mongo, session, operations).await?;

    Ok(())
}

struct BatchInsertions {
    collection_name: String,
    insertions: Vec<Document>
}

/// Used to aggregate transaction operations.
/// Simplifies batching on rebuilds (redo).
struct TransactionOperationAggregator {
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

async fn ca_transaction_router(
    mongo: &dyn MongoDao,
    session: &mut ClientSession,
    action: &str,
    wrapper: TransactionWrapper
) -> Result<TransactionOperationAggregator, CommonError> {
    match action {
        COMMANDE_AJOUTER_CLE_DOMAINES => save_new_key(mongo, session, wrapper).await,
        _ => Err(CommonError::Str("Unknown transaction action"))
    }
}

async fn persist_transaction(wrapper: &TransactionWrapper) -> Result<(), CommonError> {
    Ok(())
}

async fn save_new_key(
    mongo: &dyn MongoDao,
    session: &mut ClientSession,
    wrapper: TransactionWrapper
) -> Result<TransactionOperationAggregator, CommonError> {
    let mut aggregator = TransactionOperationAggregator::new();

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
