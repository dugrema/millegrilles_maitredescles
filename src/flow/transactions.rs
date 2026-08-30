use crate::models::TransactionWrapper;
use millegrilles_common_rust::constantes::COMMANDE_AJOUTER_CLE_DOMAINES;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::ClientSession;

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

    match ca_transaction_router(mongo, &mut session, action.as_str(), wrapper).await {
        Ok(()) => session.commit_transaction().await?,
        Err(e) => {
            session.abort_transaction().await?;
            return Err(e)
        },
    }

    todo!()
}

async fn ca_transaction_router(mongo: &dyn MongoDao, session: &mut ClientSession, action: &str, wrapper: TransactionWrapper) -> Result<(), CommonError> {
    match action {
        COMMANDE_AJOUTER_CLE_DOMAINES => save_new_key(mongo, session, wrapper).await,
        _ => Err(CommonError::Str("Unknown transaction action"))
    }
}

async fn save_new_key(mongo: &dyn MongoDao, session: &mut ClientSession, wrapper: TransactionWrapper) -> Result<(), CommonError> {
    todo!()
}
