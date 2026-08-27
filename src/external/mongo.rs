use crate::constants::*;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{CHAMP_CREATION, CHAMP_MODIFICATION};
use millegrilles_common_rust::error::{Error as CommonError, Error};
use millegrilles_common_rust::jwt_simple::prelude::Deserialize;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao, MongoDaoTyped, start_transaction_regular};
use millegrilles_common_rust::mongodb::options::{AggregateOptions, Hint};
use millegrilles_common_rust::tracing::{debug, info};

pub async fn create_index_mongodb_custom(db: &dyn MongoDao, config: &dyn ConfigMessages, key_collection_name: &str) -> Result<(), Error> {
    // Index cle_id
    let options_cle_id = IndexOptions {
        nom_index: Some(String::from(INDEX_CLE_ID)),
        unique: true,
    };
    let champs_index_cle_id = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_CLE_ID), direction: 1},
    );
    db.create_index(
        config,
        key_collection_name,
        champs_index_cle_id,
        Some(options_cle_id)
    ).await?;

    // Index cles non dechiffrable
    let options_non_dechiffrables = IndexOptions {
        nom_index: Some(String::from(INDEX_NON_DECHIFFRABLES)),
        unique: false,
    };
    let champs_index_non_dechiffrables = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_NON_DECHIFFRABLE), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_CREATION), direction: 1},
    );
    db.create_index(
        config,
        key_collection_name,
        champs_index_non_dechiffrables,
        Some(options_non_dechiffrables)
    ).await?;

    Ok(())
}

pub async fn create_index_mongodb_partition(db: &dyn MongoDao, config: &dyn ConfigMessages) -> Result<(), CommonError> {
    let collection_cles = NOM_COLLECTION_SYMMETRIQUE_CLES;

    // Index confirmation ca (table cles)
    let options_confirmation_ca = IndexOptions {
        nom_index: Some(String::from(INDEX_CONFIRMATION_CA)),
        unique: false
    };
    let champs_index_confirmation_ca = vec!(
        ChampIndex { nom_champ: String::from(CHAMP_CONFIRMATION_CA), direction: 1 },
    );
    db.create_index(
        config,
        collection_cles,
        champs_index_confirmation_ca,
        Some(options_confirmation_ca)
    ).await?;

    // Index confirmation ca (table cles)
    let options_configuration = IndexOptions {
        nom_index: Some(String::from("pk")),
        unique: true
    };
    let champs_index_configuration = vec!(
        ChampIndex { nom_champ: String::from("type"), direction: 1 },
        ChampIndex { nom_champ: String::from("instance_id"), direction: 1 },
        ChampIndex { nom_champ: String::from("fingerprint"), direction: 1 },
    );
    db.create_index(
        config,
        NOM_COLLECTION_CONFIGURATION,
        champs_index_configuration,
        Some(options_configuration)
    ).await?;

    Ok(())
}

#[derive(Deserialize)]
struct MissingKeyRow {
    cle_id: String,
}

/// Processes the temp_keysync_done table filled by the active keymasters.
pub async fn process_ca_key_sync<M>(mongo: &M) -> Result<(), Error>
    where M: MongoDaoTyped
{
    info!("process_ca_key_sync Starting");
    let collection = mongo.get_collection(NOM_COLLECTION_CA_TEMP_KEYSYNC_DONE)?;
    let db_name = collection.namespace().db;

    // Flag all keys that have been received but are missing from the main table
    let pipeline = vec![
        doc!("$sort": {CHAMP_CLE_ID: 1}),           // Use the index
        doc!("$group": {"_id": format!("${}", CHAMP_CLE_ID)}),      // Group by indexed field to de-duplicate
        doc!{"$replaceWith": {CHAMP_CLE_ID: "$_id"}},   // Recover the cle_id field name
        doc!{"$lookup": {
            "from": NOM_COLLECTION_CA_CLES,
            "localField": CHAMP_CLE_ID,
            "foreignField": CHAMP_CLE_ID,
            "as": "caKeys"
        }},
        doc!{"$match": {"caKeys.0": {"$exists": false}}},
        doc!{"$out": {"db": db_name, "coll": NOM_COLLECTION_CA_MISSING}},
    ];
    // Go through all keys using the index - makes the keys sorted for de-duplication
    let options = AggregateOptions::builder().hint(Hint::Name(String::from(INDEX_CLE_ID))).build();
    collection.aggregate(pipeline, options).await?;
    // Drop the sync collection - output saved in the CA MISSING table.
    collection.drop(None).await?;

    // Request all missing keys
    let collection_ca_missing = mongo.get_collection_typed::<MissingKeyRow>(NOM_COLLECTION_CA_MISSING)?;
    let mut cursor = collection_ca_missing.find(None, None).await?;
    const BATCH_SIZE: usize = 50;
    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut total_keys_missing = 0;
    let mut keys_received = 0;
    let mut session = mongo.get_session().await?;
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        batch.push(row.cle_id);

        start_transaction_regular(&mut session).await?;
        if batch.len() >= BATCH_SIZE {
            total_keys_missing += batch.len();
            debug!("Requesting {} missing keys for CA", batch.len());
            todo!()
            // let new_keys = crate::maitredescles_mongodb::get_missing_ca_keys(middleware, batch, gestionnaire, &mut session).await?;
            // keys_received += new_keys;
            // batch = Vec::with_capacity(BATCH_SIZE);
        }
        session.commit_transaction().await?;
    }

    if batch.len() > 0 {
        total_keys_missing += batch.len();
        debug!("Requesting {} missing keys for CA", batch.len());
        start_transaction_regular(&mut session).await?;
        todo!()
        // let new_keys = crate::maitredescles_mongodb::get_missing_ca_keys(middleware, batch, gestionnaire, &mut session).await?;
        // session.commit_transaction().await?;
        // keys_received += new_keys;
    }

    if total_keys_missing == keys_received {
        // All missing keys received, cleanup temp collection
        collection_ca_missing.drop(None).await?;
    }

    info!("process_ca_key_sync Done, requested {} missing keys, received {} keys", total_keys_missing, keys_received);
    Ok(())
}

pub async fn marquer_cles_ca_timeout(mongo: &dyn MongoDao) -> Result<(), Error> {
    let expired = Utc::now() - Duration::hours(12);
    let filtre = doc!{CHAMP_DERNIERE_PRESENCE: {"$lte": expired}};
    let ops = doc!{
        "$set": {CHAMP_NON_DECHIFFRABLE: true},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let collection = mongo.get_collection(NOM_COLLECTION_CA_CLES)?;
    let mut session = mongo.get_session().await?;
    start_transaction_regular(&mut session).await?;
    match collection.update_many_with_session(filtre, ops, None, &mut session).await {
        Ok(_) => {
            session.commit_transaction().await?;
            Ok(())
        }
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)?
        }
    }
}
