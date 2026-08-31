use crate::constants::*;
use crate::external::crypto::SymmetricEncryptionHandler;
use crate::flow::transactions::KeyMasterTransactionService;
use crate::models::DocumentCleRechiffrage;
use crate::models::{CleInterneChiffree, RowClePartition, TransactionCleV2};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chiffrage_cle::CommandeAjouterCleDomaine;
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::common_messages::ResponseRequestDechiffrageV2Cle;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{CHAMP_CREATION, CHAMP_MODIFICATION, Securite};
use millegrilles_common_rust::error::{Error as CommonError, Error};
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::jwt_simple::prelude::Deserialize;
use millegrilles_common_rust::millegrilles_cryptographie::heapless;
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::{SignatureDomaines, SignatureDomainesRef};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageKind;
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppePrivee;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao, MongoDaoTyped, start_transaction_regular};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::mongodb::options::Hint;
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::tracing::{debug, error, info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::models::TransactionWrapper;
use millegrilles_common_rust::v3::{ConfigService, FormatService};
use millegrilles_common_rust::{bson, serde_json};
// DB / Index creation

const KEY_CA: &str = "CA";
const KEY_LOCAL: &str = "local";

pub async fn create_index_mongodb_custom(db: &dyn MongoDao, config: &dyn ConfigMessages, key_collection_name: &str) -> Result<(), CommonError> {
    // Index cle_id
    let options_cle_id = IndexOptions {
        nom_index: Some(String::from(INDEX_CLE_ID)),
        unique: true,
    };
    let champs_index_cle_id = vec!(
        ChampIndex { nom_champ: String::from(CHAMP_CLE_ID), direction: 1 },
    );
    db.create_index(
        config,
        key_collection_name,
        champs_index_cle_id,
        Some(options_cle_id),
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

// CA key handling

/// Processes the temp_keysync_done table filled by the active keymasters.
pub async fn process_ca_key_sync<M>(mongo: &M) -> Result<(), CommonError>
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
    // let options = AggregateOptions::builder().hint(Hint::Name(String::from(INDEX_CLE_ID))).build();
    collection
        .aggregate(pipeline)
        .hint(Hint::Name(String::from(INDEX_CLE_ID)))
        .await?;
    // Drop the sync collection - output saved in the CA MISSING table.
    collection.drop().await?;

    // Request all missing keys
    let collection_ca_missing = mongo.get_collection_typed::<MissingKeyRow>(NOM_COLLECTION_CA_MISSING)?;
    let mut cursor = collection_ca_missing.find(doc!{}).await?;
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
        collection_ca_missing.drop().await?;
    }

    info!("process_ca_key_sync Done, requested {} missing keys, received {} keys", total_keys_missing, keys_received);
    Ok(())
}

pub async fn marquer_cles_ca_timeout(mongo: &dyn MongoDao) -> Result<(), CommonError> {
    let expired = Utc::now() - Duration::hours(12);
    let filtre = doc!{CHAMP_DERNIERE_PRESENCE: {"$lte": expired}};
    let ops = doc!{
        "$set": {CHAMP_NON_DECHIFFRABLE: true},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let collection = mongo.get_collection(NOM_COLLECTION_CA_CLES)?;
    let mut session = mongo.get_session().await?;
    start_transaction_regular(&mut session).await?;
    match collection
        .update_many(filtre, ops)
        .session(&mut session)
        .await
    {
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

/// Checks if a given key already exists
pub async fn check_key_exists(mongo: &dyn MongoDao, key_id: &str) ->Result<bool, Error> {
    let filtre = doc! { CHAMP_CLE_ID: &key_id };
    let collection = mongo.get_collection(NOM_COLLECTION_CA_CLES)?;
    let resultat = collection
        .find_one(filtre)
        .hint(Hint::Name("index_cle_id".to_string()))
        .projection(doc!{CHAMP_CLE_ID: 1})
        .await?;
    Ok(resultat.is_some())
}

// Symmetric key handling

pub async fn get_symmetric_keys<M>(
    mongo: &M,
    decryption: &SymmetricEncryptionHandler,
    cle_ids: &Vec<String>,
    domain: &str,
    include_signature: bool,
) -> Result<Vec<ResponseRequestDechiffrageV2Cle>, CommonError> where M: MongoDaoTyped {
    let mut cles: Vec<ResponseRequestDechiffrageV2Cle> = Vec::new();

    let nom_collection = NOM_COLLECTION_SYMMETRIQUE_CLES;

    let filtre = doc! {CHAMP_CLE_ID: {"$in": cle_ids}};
    let collection = mongo.get_collection_typed::<RowClePartition>(nom_collection)?;
    let mut curseur = collection.find(filtre).await?;
    let domain: heapless::String<40> = domain.try_into()
        .map_err(|_| CommonError::Str("Erreur map domain dans heapless::String<40>"))?;

    // Compter les cles trouvees separement de la liste. On rejete des cles qui ont un mismatch de domaine
    // mais elles comptent sur le total trouve.
    //let mut cles_trouvees = 0;

    while let Some(row) = curseur.next().await {
        match row {
            Ok(inner) => {
                //cles_trouvees += 1;
                if inner.signature.domaines.contains(&domain) {
                    let signature = inner.signature.clone();
                    match inner.to_cle_secrete_serialisee(decryption) {
                        Ok(inner) => {
                            let mut cle: ResponseRequestDechiffrageV2Cle = inner.into();
                            if include_signature { cle.signature = Some(signature); }
                            cles.push(cle);
                        },
                        Err(e) => {
                            warn!("Erreur mapping / dechiffrage cle - SKIP : {:?}", e);
                            continue
                        }
                    }
                } else {
                    warn!("requete_dechiffrage_v2 Requete de cle rejetee, domaines {:?} ne match pas la cle {}", inner.signature.domaines, inner.cle_id);
                }
            },
            Err(e) => {
                warn!("requete_dechiffrage_v2 Erreur mapping cle, SKIP : {:?}", e);
                continue
            }
        }
    }

    Ok(cles)
}

pub async fn get_symmetric_ca_key<M>(
    mongo: &M
) -> Result<Option<DocumentCleRechiffrage>, CommonError> where M: MongoDaoTyped {
    let filtre = doc!{"type": KEY_CA};
    let collection =
        mongo.get_collection_typed::<DocumentCleRechiffrage>(NOM_COLLECTION_CONFIGURATION)?;
    Ok(collection.find_one(filtre).await?)
}

/// This loads a symmetric key from the database. If the key is not found, will generate a
/// new symmetric key batch (CA and local) only when a CA key does not exist.
/// Raises error when a CA key exists and no matching local key is found.
pub async fn prepare_symmetric_key<M>(
    mongo: &M,
    private_key: &EnveloppePrivee,
    decryption: &SymmetricEncryptionHandler
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let instance_id = private_key.enveloppe_pub.get_common_name()?;

    let collection =
        mongo.get_collection_typed::<DocumentCleRechiffrage>(NOM_COLLECTION_CONFIGURATION)?;

    let fingerprint = private_key.fingerprint()?;
    let filtre = doc!{
        "type": KEY_LOCAL,
        "instance_id": instance_id.as_str(),
        "fingerprint": &fingerprint,
    };

    match collection.find_one(filtre).await? {
        Some(cle_locale) => {
            decryption.set_cle_symmetrique(cle_locale.cle)?;
            info!("prepare_symmetric_key Local symmetric key is loaded, fingerprint: {}", fingerprint);
            Ok(())
        },
        None => {
            // Check if a "CA" encrypted key is available for this instance
            if get_symmetric_ca_key(mongo).await?.is_some() {
                // CA key exists
                return Err(CommonError::Str("prepare_symmetric_key Waiting for symmetric key"));
            }

            info!("No CA decryption key found, this is a new system. Initializing new KeyMaster symmetric key.");
            decryption.generer_cle_symmetrique()?;

            // Encrypt the new key for CA and local
            let encrytped_ca_key = decryption.get_cle_symmetrique_chiffree(
                &private_key.enveloppe_ca.certificat.public_key()?
            )?;
            let encrypted_local_key = decryption.get_cle_symmetrique_chiffree(
                &private_key.enveloppe_pub.certificat.public_key()?
            )?;

            debug!("Encrypted key\nCA : {}\ninstance_id {} : {}",
                instance_id, encrytped_ca_key, encrypted_local_key
            );

            // Save the keys
            let mut keys = Vec::new();
            keys.push(DocumentCleRechiffrage {
                type_: KEY_CA.to_string(),
                instance_id: KEY_CA.to_string(),
                fingerprint: None,
                cle: encrytped_ca_key,
            });
            keys.push(DocumentCleRechiffrage {
                type_: KEY_LOCAL.to_string(),
                instance_id: instance_id.to_string(),
                fingerprint: Some(fingerprint.clone()),
                cle: encrypted_local_key,
            });

            // Save keys using a session
            let mut session = mongo.get_session().await?;
            session.start_transaction().await?;
            match save_symmetric_keys(mongo, &mut session, keys).await {
                Ok(()) => session.commit_transaction().await?,
                Err(e) => {
                    error!("prepare_symmetric_key Error saving keys: {:?}", e);
                    session.abort_transaction().await?;
                }
            }

            Ok(())
        }
    }
}

/// Save a new symmetric key
pub async fn save_symmetric_keys(
    mongo: &dyn MongoDao,
    session: &mut ClientSession,
    keys: Vec<DocumentCleRechiffrage>,
) -> Result<(), CommonError> {
    let collection = mongo.get_collection(NOM_COLLECTION_CONFIGURATION)?;
    for key in keys {
        collection.insert_one(bson::serialize_to_document(&key)?).session(&mut *session).await?;
    }
    Ok(())
}

pub async fn save_symmetric_key(
    mongo: &dyn MongoDao,
    signature: SignatureDomaines,
    key: CleInterneChiffree
) -> Result<(), CommonError> {

    let key_id = signature.get_cle_ref()?;
    let new_key_row = RowClePartition {
        cle_id: key_id.to_string(),
        signature,
        cle_symmetrique: Some(key.cle),
        nonce_symmetrique: Some(key.nonce),
        // Deprecated, not used for new keys
        format: None,
        iv: None,
        tag: None,
        header: None,

        // Other flags
        confirmation_ca: Some(false),
    };

    let collection = mongo.get_collection(NOM_COLLECTION_SYMMETRIQUE_CLES)?;
    collection.insert_one(bson::serialize_to_document(&new_key_row)?).await?;

    Ok(())
}
