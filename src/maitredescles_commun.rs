use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use log::debug;
use millegrilles_common_rust::certificats::EnveloppeCertificat;
use millegrilles_common_rust::chiffrage::{CommandeSauvegarderCle, FormatChiffrage};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::middleware::Middleware;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio::time::{Duration, sleep};

pub const DOMAINE_NOM: &str = "MaitreDesCles";

pub const INDEX_CLES_HACHAGE_BYTES: &str = "index_hachage_bytes";
pub const INDEX_NON_DECHIFFRABLES: &str = "index_non_dechiffrables";

pub const NOM_Q_DECHIFFRAGE: &str = "MaitreDesCles/dechiffrage";

pub const REQUETE_SYNCHRONISER_CLES: &str = "synchroniserCles";

pub const COMMANDE_SAUVEGARDER_CLE: &str = "sauvegarderCle";
pub const COMMANDE_CONFIRMER_CLES_SUR_CA: &str = "confirmerClesSurCa";

pub const TRANSACTION_CLE: &str = "cle";

// pub const EVENEMENT_RESET_CLES_NON_DECHIFFRABLES: &str = "resetClesNonDechiffrables";
pub const EVENEMENT_CLES_MANQUANTES_PARTITION: &str = "clesManquantesPartition";

pub const CHAMP_HACHAGE_BYTES: &str = "hachage_bytes";
pub const CHAMP_LISTE_HACHAGE_BYTES: &str = "liste_hachage_bytes";
// pub const CHAMP_LISTE_FINGERPRINTS: &str = "liste_fingerprints";
pub const CHAMP_NON_DECHIFFRABLE: &str = "non_dechiffrable";
// pub const CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";

// pub const CHAMP_ACCES: &str = "acces";
pub const CHAMP_ACCES_REFUSE: &str = "0.refuse";
pub const CHAMP_ACCES_PERMIS: &str = "1.permis";
// pub const CHAMP_ACCES_ERREUR: &str = "2.erreur";
// pub const CHAMP_ACCES_CLE_INDECHIFFRABLE: &str = "3.indechiffrable";
pub const CHAMP_ACCES_CLE_INCONNUE: &str = "4.inconnue";

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionCle {
    pub cle: String,
    pub domaine: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
    pub format: FormatChiffrage,
    pub hachage_bytes: String,
    pub identificateurs_document: HashMap<String, String>,
    pub iv: String,
    pub tag: String,
}

impl TransactionCle {
    pub fn new_from_commande(commande: &CommandeSauvegarderCle, fingerprint: &str)
        -> Result<Self, Box<dyn Error>>
    {
        let cle = match commande.cles.get(fingerprint) {
            Some(c) => c,
            None => {
                Err(format!("TransactionCle.new_from_commande Cle non trouvee pour fingerprint {}", fingerprint))?
            }
        };

        Ok(TransactionCle {
            cle: cle.to_owned(),
            domaine: commande.domaine.clone(),
            partition: commande.partition.clone(),
            format: commande.format.clone(),
            hachage_bytes: commande.hachage_bytes.to_owned(),
            identificateurs_document: commande.identificateurs_document.clone(),
            iv: commande.iv.clone(),
            tag: commande.tag.clone(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionDechiffrage {
    pub liste_hachage_bytes: Vec<String>,
    pub domaines_permis: Option<Vec<String>>,
    pub user_id: Option<String>,
    pub duree: u32,
}

/// Permission deja validee avec un certificat
#[derive(Clone, Debug)]
pub struct EnveloppePermission {
    pub enveloppe: Arc<EnveloppeCertificat>,
    pub permission: PermissionDechiffrage,
}

/// Requete utilisee pour parcourir toutes les cles du CA a partir d'une partition
/// Permet a la partition de trouver des cles qu'elle ne connait pas et/ou confirmer au CA
/// qu'elle est capable de dechiffrer toutes les cles.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteSynchroniserCles {
    /// Page a utiliser pour continuer la sync
    pub page: u32,
    /// Nombre d'elements par page
    pub limite: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseSynchroniserCles {
    pub liste_hachage_bytes: Vec<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseConfirmerClesSurCa {
    pub cles_manquantes: Vec<String>
}
