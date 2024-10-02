use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::constantes::{CHAMP_CREATION, CHAMP_MODIFICATION};
use crate::constants::*;
use crate::maitredescles_partition::GestionnaireMaitreDesClesPartition;

/// Creer index MongoDB
pub async fn preparer_index_mongodb_custom<M>(middleware: &M, nom_collection_cles: &str, ca: bool) -> Result<(), Error>
where M: MongoDao + ConfigMessages
{
    // Index cle_id
    let options_cle_id = IndexOptions {
        nom_index: Some(String::from(INDEX_CLE_ID)),
        unique: true,
    };
    let champs_index_cle_id = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_CLE_ID), direction: 1},
    );
    middleware.create_index(
        middleware,
        nom_collection_cles,
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
    middleware.create_index(
        middleware,
        nom_collection_cles,
        champs_index_non_dechiffrables,
        Some(options_non_dechiffrables)
    ).await?;

    Ok(())
}

pub async fn preparer_index_mongodb_partition<M>(middleware: &M, gestionnaire: &GestionnaireMaitreDesClesPartition) -> Result<(), Error>
where M: MongoDao + ConfigMessages
{
    if let Some(collection_cles) = gestionnaire.get_collection_cles()? {

        // Index confirmation ca (table cles)
        let options_confirmation_ca = IndexOptions {
            nom_index: Some(String::from(INDEX_CONFIRMATION_CA)),
            unique: false
        };
        let champs_index_confirmation_ca = vec!(
            ChampIndex { nom_champ: String::from(CHAMP_CONFIRMATION_CA), direction: 1 },
        );
        middleware.create_index(
            middleware,
            collection_cles.as_str(),
            champs_index_confirmation_ca,
            Some(options_confirmation_ca)
        ).await?;

    }

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
    middleware.create_index(
        middleware,
        NOM_COLLECTION_CONFIGURATION,
        champs_index_configuration,
        Some(options_configuration)
    ).await?;

    Ok(())
}
