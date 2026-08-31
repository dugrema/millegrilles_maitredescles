use crate::constants::*;
use crate::external::crypto::SymmetricEncryptionHandler;
use crate::models::{CleInterneChiffree, RowClePartition};
use crate::models::{DocumentCleRechiffrage, RecupererCleCa, ReponseClesNonDechiffrables, RequeteClesNonDechiffrable, RowCleCaRef};
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::{Document, doc};
use millegrilles_common_rust::common_messages::ResponseRequestDechiffrageV2Cle;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{CHAMP_CREATION, FIELD_BID, FIELD_DATE_PROCESSED, INDEX_BID, INDEX_DATE_PROCESSED, TRANSACTION_CHAMP_ID};
use millegrilles_common_rust::error::{Error as CommonError, Error};
use millegrilles_common_rust::millegrilles_cryptographie::heapless;
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::SignatureDomaines;
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppePrivee;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao, MongoDaoImpl, MongoDaoTyped};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::mongodb::options::{Hint, UpdateOneModel, WriteModel};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::tracing::{debug, error, info, warn};
// DB / Index creation

const KEY_CA: &str = "CA";
pub const KEY_LOCAL: &str = "local";


pub async fn create_index_mongodb_ca(db: &dyn MongoDao, config: &dyn ConfigMessages) -> Result<(), CommonError> {
    db.create_index(
        config,
        NOM_COLLECTION_TRANSACTIONS_CA,
        vec!(
            ChampIndex { nom_champ: String::from(TRANSACTION_CHAMP_ID), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_REDO_LOG_ID)),
            unique: true,
        }),
    ).await?;

    db.create_index(
        config,
        NOM_COLLECTION_TRACKING_CA,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_BID), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_BID)),
            unique: true,
        })
    ).await?;

    db.create_index(
        config,
        NOM_COLLECTION_TRACKING_CA,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_DATE_PROCESSED), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_DATE_PROCESSED)),
            unique: false,
        })
    ).await?;

    db.create_index(
        config,
        NOM_COLLECTION_CA_CLES,
        vec!(
            ChampIndex { nom_champ: String::from(CHAMP_CLE_ID), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_CLE_ID)),
            unique: true,
        })
    ).await?;

    db.create_index(
        config,
        NOM_COLLECTION_CA_CLES,
        vec!(
            ChampIndex {nom_champ: String::from(CHAMP_NON_DECHIFFRABLE), direction: 1},
            ChampIndex {nom_champ: String::from(CHAMP_CREATION), direction: 1},
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_NON_DECHIFFRABLES)),
            unique: false,
        })
    ).await?;
    Ok(())
}

pub async fn create_index_mongodb_symmetric(db: &dyn MongoDao, config: &dyn ConfigMessages) -> Result<(), CommonError> {
    db.create_index(config, NOM_COLLECTION_SYMMETRIQUE_CLES,
        vec!(
            ChampIndex { nom_champ: String::from(CHAMP_CLE_ID), direction: 1 },
        ),
        Some(IndexOptions { nom_index: Some(String::from(INDEX_CLE_ID)), unique: true })
    ).await?;

    db.create_index(config, NOM_COLLECTION_SYMMETRIQUE_CLES,
        vec!(
            ChampIndex {nom_champ: String::from(CHAMP_NON_DECHIFFRABLE), direction: 1},
            ChampIndex {nom_champ: String::from(CHAMP_CREATION), direction: 1},
        ),
        Some(IndexOptions { nom_index: Some(String::from(INDEX_NON_DECHIFFRABLES)), unique: false })
    ).await?;

    db.create_index(config, NOM_COLLECTION_CONFIGURATION,
        vec!(
            ChampIndex { nom_champ: String::from("type"), direction: 1 },
            ChampIndex { nom_champ: String::from("instance_id"), direction: 1 },
            ChampIndex { nom_champ: String::from("fingerprint"), direction: 1 },
        ),
        Some(IndexOptions { nom_index: Some(String::from("pk")), unique: true })
    ).await?;

    Ok(())
}

// CA key handling
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
            decryption.set_key(cle_locale.cle)?;
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
            decryption.generate_new_key()?;

            // Encrypt the new key for CA and local
            let encrytped_ca_key = decryption.get_encrypted_key(
                &private_key.enveloppe_ca.certificat.public_key()?
            )?;
            let encrypted_local_key = decryption.get_encrypted_key(
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
            match save_symmetric_keys(mongo, Some(&mut session), keys).await {
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
    mut session: Option<&mut ClientSession>,
    keys: Vec<DocumentCleRechiffrage>,
) -> Result<(), CommonError> {
    let collection = mongo.get_collection(NOM_COLLECTION_CONFIGURATION)?;
    for key in keys {
        let mut op = collection.insert_one(bson::serialize_to_document(&key)?);
        if let Some(session) = session.as_mut() {
            op = op.session(&mut **session);
        }
        op.await?;
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
        // confirmation_ca: Some(false),
    };

    let collection = mongo.get_collection(NOM_COLLECTION_SYMMETRIQUE_CLES)?;
    collection.insert_one(bson::serialize_to_document(&new_key_row)?).await?;

    // Set the CA key flags to decipherable.
    // May misfire if symmetric key processed before CA. This will be handled by the cleanup process.
    set_ca_batch_decipherable(mongo, vec![key_id.to_string()]).await?;

    Ok(())
}

pub async fn count_ca_undecipherable_keys(mongo: &dyn MongoDao) -> Result<usize, CommonError> {
    let filtre = doc! { CHAMP_NON_DECHIFFRABLE: true };
    let collection = mongo.get_collection(NOM_COLLECTION_CA_CLES)?;
    let compte = collection
        .count_documents(filtre)
        .hint(Hint::Name(INDEX_NON_DECHIFFRABLES.into()))
        .await?;
    Ok(compte as usize)
}

pub async fn save_symmetric_batch(mongo: &dyn MongoDao, keys: Vec<RowClePartition>) -> Result<(), CommonError> {

    let collection = mongo.get_collection(NOM_COLLECTION_SYMMETRIQUE_CLES)?;

    let key_docs: Vec<Document> = keys
        .into_iter()
        .map(|k| bson::serialize_to_document(&k).unwrap())
        .collect();

    // Try to insert all values in a single batch
    let mut session = mongo.get_session().await?;
    session.start_transaction().await?;
    match collection.insert_many(&key_docs).session(&mut session).ordered(false).await {
        Ok(_) => {
            session.commit_transaction().await?;
            Ok(())
        },
        Err(e) => {
            warn!("Error saving batch of keys using insert: {:?}", e);
            session.abort_transaction().await?;

            let mut write_actions = Vec::with_capacity(key_docs.len());
            for key in key_docs {
                let model = WriteModel::UpdateOne(UpdateOneModel::builder()
                    .namespace(collection.namespace())
                    .filter(doc! {
                        "cle_id": key.get("cle_id").expect("cle_id"),
                    })
                    .update(doc! {
                        "$setOnInsert": key,
                    })
                    .upsert(true)
                    .build()
                );
                write_actions.push(model);
            }

            // Run the bulk upsert
            session.start_transaction().await?;
            match mongo.bulk_write(write_actions, Some(&mut session), false).await {
                Ok(_) => {
                    session.commit_transaction().await?;
                    Ok(())
                }
                Err(e) => {
                    session.abort_transaction().await?;
                    Err(e)
                }
            }
        }
    }
}

// Sample from collection: MaitreDesCles/CA/cles
// {
//     _id: ObjectId('6a95b504374480125b09196b'),
//     cle_id: 'zCkb2AhftK6ywCpoBszQp8Hb3Za6Pg7DBP5fmzuHhR2PW',
//     signature: {
//         domaines: [
//             'GrosFichiers'
//         ],
//         version: 1,
//         ca: 'TSAVnynEb4nQz5Va/ZdlgJbAQz1x+NDd6BVeHdojAj0',
//         signature: 'pryt5xjbi+qRl2bWlIittUqZTxTJjjo5so4j9/YGuU8YINqR1nyiSSzx5SUNOt1kp0sReM2eXLNajR1enQBTDA'
//     },
//     non_dechiffrable: true,
//     date_creation: ISODate('2026-08-31T17:08:20.751Z')
// }

// Matching sample from collection: MaitreDesCles/cles
// {
//     _id: ObjectId('6a95c9d8ff2af87849bc6864'),
//     cle_id: 'zCkb2AhftK6ywCpoBszQp8Hb3Za6Pg7DBP5fmzuHhR2PW',
//     signature: {
//         ca: 'TSAVnynEb4nQz5Va/ZdlgJbAQz1x+NDd6BVeHdojAj0',
//         domaines: [
//             'GrosFichiers'
//         ],
//         signature: 'pryt5xjbi+qRl2bWlIittUqZTxTJjjo5so4j9/YGuU8YINqR1nyiSSzx5SUNOt1kp0sReM2eXLNajR1enQBTDA',
//         version: 1
//     },
//     cle_symmetrique: 'm/El5qmxCObpOrWlMYW3y2rzPuWX7RU4Pbco8qpgPl2EK6IezPx3w22nzuSAQvpat',
//     nonce_symmetrique: 'mwOlCoOD1RYoahlgncUgh5UheGobIlbpr',
//     confirmation_ca: true
// }

/// Checks the symmetric table to set the "non_dechiffrable" flag to true when applicable.
pub async fn check_ca_keys_undecipherable_flag(mongo: &dyn MongoDao) -> Result<(), CommonError> {
    let pipeline = vec![
        // 1. Only process records that are currently marked as undecipherable
        doc! { "$match": { "non_dechiffrable": true } },

        // 2. Join with the symmetric 'cles' collection
        doc! {
            "$lookup": {
                "from": NOM_COLLECTION_SYMMETRIQUE_CLES,
                "localField": "cle_id",
                "foreignField": "cle_id",
                "as": "matches"
            }
        },

        // 3. Filter to keep only those that found at least one matching record in 'cles'
        doc! { "$match": { "matches.0": { "$exists": true } } },

        // 4. Set the flag to false
        doc! { "$set": { "non_dechiffrable": false } },

        // 5. Remove the temporary 'matches' field used for joining
        doc! { "$project": { "matches": 0 } },

        // 6. Merge the updated documents back into the CA/cles collection
        doc! {
            "$merge": {
                "into": NOM_COLLECTION_CA_CLES,
                "on": "_id",
                "whenMatched": "replace"
            }
        },
    ];

    let collection_ca = mongo.get_collection(NOM_COLLECTION_CA_CLES)?;
    collection_ca.aggregate(pipeline).await?;

    debug!("check_ca_keys_undecipherable_flag Check Done");

    Ok(())
}

/// Sets the flag "non_dechiffrable" to false in the CA table.
pub async fn set_ca_batch_decipherable(mongo: &dyn MongoDao, keys: Vec<String>) -> Result<(), CommonError> {
    let collection_ca = mongo.get_collection(NOM_COLLECTION_CA_CLES)?;
    let filter = doc!{"cle_id": {"$in": keys}};
    let ops = doc!{"$set": {CHAMP_NON_DECHIFFRABLE: false}};
    collection_ca.update_many(filter, ops).await?;
    Ok(())
}

pub async fn fetch_key_batch_db(mongo: &MongoDaoImpl, request: RequeteClesNonDechiffrable) -> Result<ReponseClesNonDechiffrables, Error> {
    let mut idx = request.skip.unwrap_or_else(|| 0);

    let mut cursor = {
        let collection = mongo.get_collection_typed::<RowCleCaRef>(NOM_COLLECTION_CA_CLES)?;
        // Using the hint on MongoDB _id_ to iterate in order through the whole collection.
        // If we skip any undecipherable keys, we can double-back at the end (we'll see the count)
        collection
            .find(doc! {})
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
    Ok(response)
}
