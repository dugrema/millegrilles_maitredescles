use std::error::Error;
use std::sync::Arc;

use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::middleware::Middleware;
use millegrilles_common_rust::mongo_dao::{ChampIndex, convertir_bson_deserializable, convertir_bson_value, convertir_to_bson, filtrer_doc_id, IndexOptions, MongoDao};
use millegrilles_common_rust::mongodb as mongodb;
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, FindOneOptions, Hint};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::tokio::time::{Duration, sleep};

pub const DOMAINE_NOM: &str = "MaitreDesCles";

pub const INDEX_CLES_HACHAGE_BYTES: &str = "index_hachage_bytes";
pub const INDEX_NON_DECHIFFRABLES: &str = "index_non_dechiffrables";

pub const NOM_Q_DECHIFFRAGE: &str = "MaitreDesCles/dechiffrage";

pub const COMMANDE_SAUVEGARDER_CLE: &str = "sauvegarderCle";

pub const TRANSACTION_CLE: &str = "cle";

pub const CHAMP_HACHAGE_BYTES: &str = "hachage_bytes";
pub const CHAMP_LISTE_FINGERPRINTS: &str = "liste_fingerprints";
pub const CHAMP_NON_DECHIFFRABLE: &str = "non_dechiffrable";

/// Creer index MongoDB
pub async fn preparer_index_mongodb_custom<M>(middleware: &M, nom_collection_cles: &str) -> Result<(), String>
    where M: MongoDao
{
    // Index hachage_bytes
    let options_unique_cles_hachage_bytes = IndexOptions {
        nom_index: Some(String::from(INDEX_CLES_HACHAGE_BYTES)),
        unique: true
    };
    let champs_index_cles_hachage_bytes = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_HACHAGE_BYTES), direction: 1},
    );
    middleware.create_index(
        nom_collection_cles,
        champs_index_cles_hachage_bytes,
        Some(options_unique_cles_hachage_bytes)
    ).await?;

    // Index cles non dechiffrable
    let options_non_dechiffrables = IndexOptions {
        nom_index: Some(String::from(INDEX_NON_DECHIFFRABLES)),
        unique: false,
    };
    let champs_index_non_dechiffrables = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_LISTE_FINGERPRINTS), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_NON_DECHIFFRABLE), direction: 1},
        ChampIndex {nom_champ: String::from(CHAMP_CREATION), direction: 1},
    );
    middleware.create_index(
        nom_collection_cles,
        champs_index_non_dechiffrables,
        Some(options_non_dechiffrables)
    ).await?;

    Ok(())
}

pub async fn entretien<M>(_middleware: Arc<M>)
    where M: Middleware + 'static
{
    let mut catalogues_charges = false;

    loop {
        sleep(Duration::new(30, 0)).await;
        debug!("Cycle entretien {}", DOMAINE_NOM);
    }
}

pub async fn traiter_cedule<M>(_middleware: &M, _trigger: MessageValideAction) -> Result<(), Box<dyn Error>>
where M: Middleware + 'static {
    // let message = trigger.message;

    debug!("Traiter cedule {}", DOMAINE_NOM);

    Ok(())
}
