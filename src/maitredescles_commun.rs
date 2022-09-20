use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::{Arc, Mutex};

use log::{debug, error, info};
use millegrilles_common_rust::certificats::{EnveloppeCertificat, EnveloppePrivee, ValidateurX509};
use millegrilles_common_rust::chiffrage::{CleSecrete, FormatChiffrage};
use millegrilles_common_rust::chiffrage_cle::{CommandeSauvegarderCle, IdentiteCle};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::Middleware;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio::{sync::mpsc::Sender, time::{Duration, sleep}};
use millegrilles_common_rust::certificats::ordered_map;
use millegrilles_common_rust::common_messages::ReponseSignatureCertificat;
use crate::domaines_maitredescles::TypeGestionnaire;
use crate::maitredescles_volatil::HandlerCleRechiffrage;

pub const DOMAINE_NOM: &str = "MaitreDesCles";

pub const INDEX_CLES_HACHAGE_BYTES: &str = "index_hachage_bytes";
pub const INDEX_CLES_HACHAGE_BYTES_DOMAINES: &str = "index_hachage_bytes_domaines";
pub const INDEX_NON_DECHIFFRABLES: &str = "index_non_dechiffrables";

pub const NOM_Q_DECHIFFRAGE: &str = "MaitreDesCles/dechiffrage";

pub const REQUETE_SYNCHRONISER_CLES: &str = "synchroniserCles";
pub const REQUETE_DECHIFFRAGE: &str = "dechiffrage";
pub const REQUETE_VERIFIER_PREUVE: &str = "verifierPreuve";

// pub const COMMANDE_SAUVEGARDER_CLE: &str = "sauvegarderCle";
pub const COMMANDE_CONFIRMER_CLES_SUR_CA: &str = "confirmerClesSurCa";

pub const TRANSACTION_CLE: &str = "cle";

// pub const EVENEMENT_RESET_CLES_NON_DECHIFFRABLES: &str = "resetClesNonDechiffrables";
pub const EVENEMENT_CLES_MANQUANTES_PARTITION: &str = "clesManquantesPartition";
pub const EVENEMENT_CLE_RECUE_PARTITION: &str = "cleRecuePartition";

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

    // Index hachage_bytes
    let options_unique_cles_hachage_bytes_domaines = IndexOptions {
        nom_index: Some(String::from(INDEX_CLES_HACHAGE_BYTES_DOMAINES)),
        unique: true
    };
    let champs_index_cles_hachage_bytes_domaines = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_HACHAGE_BYTES), direction: 1},
        ChampIndex {nom_champ: String::from(TRANSACTION_CHAMP_DOMAINE), direction: 1},
    );
    middleware.create_index(
        nom_collection_cles,
        champs_index_cles_hachage_bytes_domaines,
        Some(options_unique_cles_hachage_bytes_domaines)
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

// pub async fn entretien_rechiffreur<M>(middleware: Arc<M>, handler_rechiffrage: Arc<HandlerCleRechiffrage>)
//     where M: Middleware + 'static
// {
//     loop {
//         debug!("Cycle entretien rechiffreur {}", DOMAINE_NOM);
//
//         match handler_rechiffrage.fingerprint() {
//             Some(f) => {
//                 // Rechiffreur pret et actif
//                 debug!("entretien_rechiffreur Handler rechiffrage fingerprint {:?}", f);
//             },
//             None => {
//                 info!("entretien_rechiffreur Aucun certificat configure, on demande de generer un certificat volatil");
//                 match generer_certificat_volatil(middleware.as_ref(), handler_rechiffrage.as_ref()).await {
//                     Ok(()) => (),
//                     Err(e) => error!("entretien_rechiffreur Erreur generation certificat volatil : {:?}", e)
//                 }
//             }
//         };
//
//         sleep(Duration::new(30, 0)).await;
//     }
// }

pub async fn generer_certificat_volatil<M>(middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + ValidateurX509
{
    let idmg = middleware.get_enveloppe_privee().idmg()?;
    let csr_volatil = handler_rechiffrage.generer_csr(idmg)?;
    debug!("generer_certificat_volatil Demande de generer un certificat volatil, CSR : {:?}", csr_volatil);

    let routage = RoutageMessageAction::builder(DOMAINE_PKI, "signerCsr")
        .exchanges(vec![Securite::L3Protege])
        // .timeout_blocking(20000)
        .build();

    let reponse: ReponseSignatureCertificat = match middleware.transmettre_commande(routage, &csr_volatil, true).await? {
        Some(m) => match m {
            TypeMessage::Valide(m) => m.message.parsed.map_contenu(None)?,
            _ => Err(format!("maitredescles_commun.generer_certificat_volatil Mauvais type de reponse"))?
        },
        None => Err(format!("maitredescles_commun.generer_certificat_volatil Aucune reponse recue"))?
    };

    debug!("generer_certificat_volatil Reponse {:?}", reponse);
    if Some(true) == reponse.ok {
        match reponse.certificat {
            Some(vec_certificat_pem) => {
                let enveloppe = middleware.charger_enveloppe(&vec_certificat_pem, None, None).await?;
                handler_rechiffrage.set_certificat(enveloppe)?;

                // Certificat pret
                Ok(())
            },
            None => Err(format!("maitredescles_commun.generer_certificat_volatil Erreur creation certificat volatil cote serveur, aucun certificat recu"))?
        }
    } else {
        Err(format!("maitredescles_commun.generer_certificat_volatil Erreur creation certificat volatil cote serveur (certissuer ok == false)"))?
    }
}

pub async fn traiter_cedule<M>(_middleware: &M, _trigger: &MessageCedule) -> Result<(), Box<dyn Error>>
where M: Middleware + 'static {
    // let message = trigger.message;

    debug!("Traiter cedule {}", DOMAINE_NOM);

    Ok(())
}

/// Emettre evenement de cles inconnues suite a une requete. Permet de faire la difference entre
/// les cles de la requete et les cles connues.
pub async fn emettre_cles_inconnues<M>(middleware: &M, requete: RequeteDechiffrage, cles_connues: Vec<String>)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
{
    // Faire une demande interne de sync pour voir si les cles inconnues existent (async)
    let routage_evenement_manquant = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION)
        .exchanges(vec![Securite::L4Secure])
        .build();

    let mut set_cles = HashSet::new();
    set_cles.extend(requete.liste_hachage_bytes.iter());
    let mut set_cles_trouvees = HashSet::new();
    set_cles_trouvees.extend(&cles_connues);
    let set_diff = set_cles.difference(&set_cles_trouvees);
    let liste_cles: Vec<String> = set_diff.into_iter().map(|m| m.to_string()).collect();
    debug!("emettre_cles_inconnues Requete de cles inconnues : {:?}", liste_cles);

    let evenement_cles_manquantes = ReponseSynchroniserCles { liste_hachage_bytes: liste_cles };

    Ok(middleware.emettre_evenement(routage_evenement_manquant.clone(), &evenement_cles_manquantes).await?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionDechiffrage {
    pub permission_hachage_bytes: Vec<String>,
    pub domaines_permis: Option<Vec<String>>,
    pub permission_duree: u32,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeRechiffrerBatch {
    pub cles: Vec<DocumentClePartition>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteDechiffrage {
    pub liste_hachage_bytes: Vec<String>,
    // pub permission: Option<MessageMilleGrille>,
    pub certificat_rechiffrage: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionCle {
    // Identite
    pub hachage_bytes: String,
    pub domaine: String,
    pub identificateurs_document: HashMap<String, String>,
    pub signature_identite: String,

    // Cle chiffree
    pub cle: String,

    // Dechiffrage contenu
    pub format: FormatChiffrage,
    pub iv: Option<String>,
    pub tag: Option<String>,
    pub header: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
}

impl Into<IdentiteCle> for TransactionCle {
    fn into(self) -> IdentiteCle {
        IdentiteCle {
            hachage_bytes: self.hachage_bytes,
            domaine: self.domaine,
            identificateurs_document: self.identificateurs_document,
            signature_identite: self.signature_identite
        }
    }
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
            hachage_bytes: commande.hachage_bytes.to_owned(),
            domaine: commande.domaine.clone(),
            identificateurs_document: commande.identificateurs_document.clone(),
            signature_identite: commande.signature_identite.clone(),
            cle: cle.to_owned(),
            format: commande.format.clone(),
            iv: commande.iv.clone(),
            tag: commande.tag.clone(),
            header: commande.header.clone(),
            partition: commande.partition.clone(),
        })
    }

    pub fn into_commande<S>(self, fingerprint: S) -> CommandeSauvegarderCle
        where S: Into<String>
    {
        let fingerprint_ = fingerprint.into();
        let mut cles: HashMap<String, String> = HashMap::new();
        cles.insert(fingerprint_, self.cle);
        CommandeSauvegarderCle {
            hachage_bytes: self.hachage_bytes,
            domaine: self.domaine,
            identificateurs_document: self.identificateurs_document,
            signature_identite: self.signature_identite,
            cles,
            format: self.format,
            iv: self.iv,
            tag: self.tag,
            header: self.header,
            partition: self.partition,
            fingerprint_partitions: None
        }
    }

    pub fn verifier_identite(&self, cle_secrete: &CleSecrete) -> Result<bool, String> {
        let identite: IdentiteCle = self.clone().into();
        Ok(identite.verifier(cle_secrete)?)
    }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentClePartition {
    // Identite
    pub hachage_bytes: String,
    pub domaine: String,
    pub identificateurs_document: HashMap<String, String>,
    pub signature_identite: String,

    // Cle chiffree
    pub cle: String,

    // Dechiffrage contenu
    pub format: FormatChiffrage,
    pub iv: Option<String>,
    pub tag: Option<String>,
    pub header: Option<String>,
}

impl From<CommandeSauvegarderCle> for DocumentClePartition {
    fn from(value: CommandeSauvegarderCle) -> Self {

        Self {
            hachage_bytes: value.hachage_bytes,
            domaine: value.domaine,
            identificateurs_document: value.identificateurs_document,
            signature_identite: value.signature_identite,
            cle: "".to_string(),
            format: value.format,
            iv: value.iv,
            tag: value.tag,
            header: value.header
        }
    }
}

impl DocumentClePartition {

    pub fn into_commande<S>(self, fingerprint: S) -> CommandeSauvegarderCle
        where S: Into<String>
    {
        let fingerprint_ = fingerprint.into();
        let mut cles: HashMap<String, String> = HashMap::new();
        cles.insert(fingerprint_.clone(), self.cle);
        CommandeSauvegarderCle {
            hachage_bytes: self.hachage_bytes,
            domaine: self.domaine,
            identificateurs_document: self.identificateurs_document,
            signature_identite: self.signature_identite,
            cles,
            format: self.format,
            iv: self.iv,
            tag: self.tag,
            header: self.header,
            partition: Some(fingerprint_),
            fingerprint_partitions: None
        }
    }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeCleTransfert {
    // Identite de la cle
    pub hachage_bytes: String,
    pub domaine: String,
    #[serde(serialize_with = "ordered_map")]
    pub identificateurs_document: HashMap<String, String>,
    pub signature_identite: String,

    // Cles chiffrees
    #[serde(serialize_with = "ordered_map")]
    pub cles: HashMap<String, String>,

    // Information de dechiffrage
    pub format: FormatChiffrage,
    pub iv: Option<String>,
    pub tag: Option<String>,
    pub header: Option<String>,
}

impl From<DocumentClePartition> for CommandeCleTransfert {
    fn from(value: DocumentClePartition) -> Self {
        Self {
            hachage_bytes: value.hachage_bytes,
            domaine: value.domaine,
            identificateurs_document: value.identificateurs_document,
            signature_identite: value.signature_identite,
            cles: HashMap::new(),
            format: value.format,
            iv: value.iv,
            tag: value.tag,
            header: value.header
        }
    }
}

pub struct GestionnaireRessources {
    pub tx_messages: Option<Sender<TypeMessage>>,
    pub tx_triggers: Option<Sender<TypeMessage>>,
    pub routing: Mutex<HashMap<String, Sender<TypeMessage>>>,
}
