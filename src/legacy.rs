use crate::constants::NOM_COLLECTION_CA_CLES;
use crate::models::RowCleCaRef;
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::{FormatChiffrage, optionformatchiffragestr};
use millegrilles_common_rust::millegrilles_cryptographie::heapless;
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::{SignatureDomaines, SignatureDomainesVersion};
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::serde::Deserialize;
use millegrilles_common_rust::v3::models::{TransactionOperationAggregator, TransactionWrapper};
use std::collections::HashMap;
use millegrilles_common_rust::mongodb::options::{UpdateOneModel, WriteModel};

/// New Key transaction version 1
/// Legacy Transaction - ** OBSOLETE ** - Use to restore from backups only
#[derive(Clone, Debug, Deserialize)]
pub struct TransactionCle {
    // Identite
    pub hachage_bytes: String,
    pub domaine: String,
    pub identificateurs_document: HashMap<String, String>,
    // pub signature_identite: String,

    // Cle chiffree
    pub cle: String,

    // Dechiffrage contenu
    #[serde(with = "optionformatchiffragestr")]
    pub format: Option<FormatChiffrage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
}

pub async fn legacy_transaction_cle(mongo: &dyn MongoDao, wrapper: TransactionWrapper) -> Result<TransactionOperationAggregator, CommonError> {
    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.legacy = true;  // Toggles legacy mode for processing this batch
    let transaction_cle: TransactionCle = wrapper.message.deserialize()?;

    let hachage_bytes = transaction_cle.hachage_bytes.as_str();
    let mut domaines = heapless::Vec::new();
    domaines.push(
        transaction_cle.domaine.as_str().try_into()
            .map_err(|_|CommonError::Str("transaction_cle Erreur mapping domaine to heapless::String"))?
    ).map_err(|_|CommonError::Str("transaction_cle Erreur ajout domaine to heapless::Vec"))?;

    // Convertir la cle dans le nouveau format de SignatureDomaine
    // Retirer le marqueur 'm' multibase pour obtenir base64 no pad.
    let cle_str = &transaction_cle.cle.as_str()[1..];
    let cle_heapless = cle_str.try_into().map_err(|_|CommonError::Str("transaction_cle Erreur mapping cle to heapless::String"))?;

    let signature = SignatureDomaines {
        domaines,
        version: SignatureDomainesVersion::NonSigne,
        ca: Some(cle_heapless),
        signature: hachage_bytes.try_into().map_err(|_|CommonError::Str("transaction_cle Erreur mapping hachage_bytes to heapless::String"))?,
    };

    let key_id = signature.get_cle_ref()?.to_string();
    let insert_doc = RowCleCaRef {
        cle_id: key_id.as_str(),
        signature: (&signature).into(),
        non_dechiffrable: Some(true),
        date_creation: wrapper.message.estampille,
        format: transaction_cle.format,
        iv: match transaction_cle.iv.as_ref() { Some(value) => Some(value.as_str()), None => None },
        tag: match transaction_cle.tag.as_ref() { Some(value) => Some(value.as_str()), None => None },
        header: match transaction_cle.header.as_ref() { Some(value) => Some(value.as_str()), None => None },
    };

    // let batch_insertions = BatchInsertions::new(
    //     NOM_COLLECTION_CA_CLES,
    //     vec![bson::serialize_to_document(&insert_doc)?],
    // );
    // aggregator.batch_insertion(batch_insertions)?;

    let collection = mongo.get_collection(NOM_COLLECTION_CA_CLES)?;
    let ops = doc! {
        "$setOnInsert": bson::serialize_to_document(&insert_doc)?,
    };
    let update_model = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .upsert(true)
            .namespace(collection.namespace())
            .filter(doc! {"cle_id": &key_id})
            .update(ops)
            .build()
    );
    aggregator.unordered = Some(vec![update_model]);

    Ok(aggregator)
}
