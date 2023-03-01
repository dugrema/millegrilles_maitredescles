use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::{Arc, Mutex};

use log::{debug, error, info};
use millegrilles_common_rust::certificats::{EnveloppeCertificat, EnveloppePrivee, ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage::{CleSecrete, FormatChiffrage, rechiffrer_asymetrique_multibase};
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
use millegrilles_common_rust::{multibase, multibase::Base};
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::hachages::hacher_bytes;
use millegrilles_common_rust::multibase::Base::Base58Btc;
use millegrilles_common_rust::multihash::Code;
use crate::domaines_maitredescles::TypeGestionnaire;
use crate::maitredescles_volatil::HandlerCleRechiffrage;

pub const DOMAINE_NOM: &str = "MaitreDesCles";

pub const INDEX_CLES_HACHAGE_BYTES: &str = "index_hachage_bytes";
pub const INDEX_CLE_REF: &str = "index_cle_ref";
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
pub const CHAMP_LISTE_CLE_REF: &str = "liste_cle_ref";
pub const CHAMP_NON_DECHIFFRABLE: &str = "non_dechiffrable";
// pub const CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";
pub const CHAMP_CLE_REF: &str = "cle_ref";
pub const CHAMP_LISTE_CLES: &str = "cles";

// pub const CHAMP_ACCES: &str = "acces";
pub const CHAMP_ACCES_REFUSE: &str = "0.refuse";
pub const CHAMP_ACCES_PERMIS: &str = "1.permis";
// pub const CHAMP_ACCES_ERREUR: &str = "2.erreur";
// pub const CHAMP_ACCES_CLE_INDECHIFFRABLE: &str = "3.indechiffrable";
pub const CHAMP_ACCES_CLE_INCONNUE: &str = "4.inconnue";

/// Creer index MongoDB
pub async fn preparer_index_mongodb_custom<M>(middleware: &M, nom_collection_cles: &str, ca: bool) -> Result<(), String>
    where M: MongoDao + ConfigMessages
{
    // // Index hachage_bytes
    // let options_unique_cles_hachage_bytes = IndexOptions {
    //     nom_index: Some(String::from(INDEX_CLES_HACHAGE_BYTES)),
    //     unique: true
    // };
    // let champs_index_cles_hachage_bytes = vec!(
    //     ChampIndex {nom_champ: String::from(CHAMP_HACHAGE_BYTES), direction: 1},
    // );
    // middleware.create_index(
    //     nom_collection_cles,
    //     champs_index_cles_hachage_bytes,
    //     Some(options_unique_cles_hachage_bytes)
    // ).await?;

    // Index cle_ref (unique)
    if ca == false {
        let options_unique_cle_ref = IndexOptions {
            nom_index: Some(String::from(INDEX_CLE_REF)),
            unique: true
        };
        let champs_index_unique_cle_ref = vec!(
            ChampIndex { nom_champ: String::from(CHAMP_CLE_REF), direction: 1 },
        );
        middleware.create_index(
            middleware,
            nom_collection_cles,
            champs_index_unique_cle_ref,
            Some(options_unique_cle_ref)
        ).await?;
    }

    // Index hachage_bytes/domaine
    let options_unique_cles_hachage_bytes_domaines = IndexOptions {
        nom_index: Some(String::from(INDEX_CLES_HACHAGE_BYTES_DOMAINES)),
        unique: false
    };
    let champs_index_cles_hachage_bytes_domaines = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_HACHAGE_BYTES), direction: 1},
        ChampIndex {nom_champ: String::from(TRANSACTION_CHAMP_DOMAINE), direction: 1},
    );
    middleware.create_index(
        middleware,
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
        middleware,
        nom_collection_cles,
        champs_index_non_dechiffrables,
        Some(options_non_dechiffrables)
    ).await?;

    Ok(())
}

pub async fn entretien<M>(middleware: Arc<M>)
    where M: Middleware + 'static
{
    loop {
        sleep(Duration::new(30, 0)).await;
        debug!("Cycle entretien {}", DOMAINE_NOM);
        middleware.entretien_validateur().await;
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
    let idmg = middleware.get_enveloppe_signature().idmg()?;
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
                let enveloppe_ca = middleware.get_enveloppe_signature().enveloppe_ca.clone();
                let ca_pem = enveloppe_ca.get_pem_vec().get(0).expect("CA").pem.clone();
                let enveloppe = middleware.charger_enveloppe(&vec_certificat_pem, None, Some(ca_pem.as_str())).await?;
                handler_rechiffrage.set_certificat(enveloppe, enveloppe_ca)?;

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
pub async fn emettre_cles_inconnues<M>(middleware: &M, requete: &RequeteDechiffrage, cles_connues: Vec<String>)
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

/// Emettre evenement de cles inconnues suite a une requete. Permet de faire la difference entre
/// les cles de la requete et les cles connues.
pub async fn requete_cles_inconnues<M>(middleware: &M, requete: &RequeteDechiffrage, cles_connues: Vec<String>)
    -> Result<ReponseCleManquantes, Box<dyn Error>>
    where M: GenerateurMessages
{
    // Faire une demande interne de sync pour voir si les cles inconnues existent (async)
    let routage_evenement_manquant = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION)
        .exchanges(vec![Securite::L4Secure])
        .timeout_blocking(3000)
        .build();

    let mut set_cles = HashSet::new();
    set_cles.extend(requete.liste_hachage_bytes.iter());
    let mut set_cles_trouvees = HashSet::new();
    set_cles_trouvees.extend(&cles_connues);
    let set_diff = set_cles.difference(&set_cles_trouvees);
    let liste_cles: Vec<String> = set_diff.into_iter().map(|m| m.to_string()).collect();
    debug!("emettre_cles_inconnues Requete de cles inconnues : {:?}", liste_cles);

    let evenement_cles_manquantes = ReponseSynchroniserCles { liste_hachage_bytes: liste_cles };

    let reponse = match middleware.transmettre_requete(routage_evenement_manquant.clone(), &evenement_cles_manquantes).await? {
        TypeMessage::Valide(m) => {
            debug!("requete_cles_inconnues Reponse recue {:?}", m);
            m.message.parsed.map_contenu::<ReponseCleManquantes>(None)?
        },
        _ => Err(format!("Erreur reponse pour requete cle manquante, mauvais type de reponse"))?
    };

    Ok(reponse)
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
    pub cles: Vec<CommandeSauvegarderCle>
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
    pub cle_ref: String,
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
            cle_ref: "".to_string(),
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

    pub fn try_into_document_cle_partition<S,T>(value: &CommandeCleTransfert, fingerprint: S, cle_ref: T) -> Result<DocumentClePartition, String>
        where S: Into<String>,
              T: Into<String>
    {
        let fingerprint = fingerprint.into();
        let cle_ref = cle_ref.into();

        let cle = match value.cles.get(&fingerprint) {
            Some(c) => c.as_str(),
            None => Err(format!("DocumentClePartition.try_into_document_cle_partition Erreur cle introuvable {}", fingerprint))?
        };

        Ok(DocumentClePartition {
            cle_ref,
            hachage_bytes: value.hachage_bytes.clone(),
            domaine: value.domaine.clone(),
            identificateurs_document: value.identificateurs_document.clone(),
            signature_identite: value.signature_identite.clone(),
            cle: cle.to_string(),
            format: value.format.clone(),
            iv: value.iv.clone(),
            tag: value.tag.clone(),
            header: value.header.clone()
        })
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseCleManquantes {
    pub ok: Option<bool>,
    pub cles: Option<Vec<CommandeCleTransfert>>,
}

impl Into<CommandeSauvegarderCle> for CommandeCleTransfert {
    fn into(self) -> CommandeSauvegarderCle {
        CommandeSauvegarderCle {
            hachage_bytes: self.hachage_bytes.clone(),
            domaine: self.domaine.clone(),
            identificateurs_document: self.identificateurs_document.clone(),
            signature_identite: self.signature_identite.clone(),
            cles: self.cles.clone(),
            format: self.format.clone(),
            iv: self.iv.clone(),
            tag: self.tag.clone(),
            header: self.header.clone(),
            partition: None,
            fingerprint_partitions: None
        }
    }
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

/// Calcule la cle_ref a partir du hachage et cle_secret d'une cle recue (commande/transaction)
pub fn calculer_cle_ref(commande: &CommandeSauvegarderCle, cle_secrete: &CleSecrete) -> Result<String, String>
{
    let hachage_bytes_str = commande.hachage_bytes.as_str();
    let mut hachage_src_bytes: Vec<u8> = match multibase::decode(hachage_bytes_str) {
        Ok(b) => b.1,
        Err(e) => Err(format!("calculer_cle_ref Erreur decodage multibase hachage_bytes : {:?}", e))?
    };

    // Ajouter iv, tag, header si presents
    if let Some(iv) = commande.iv.as_ref() {
        let mut iv_bytes: Vec<u8> = match multibase::decode(iv) {
            Ok(b) => b.1,
            Err(e) => Err(format!("calculer_cle_ref Erreur decodage multibase iv : {:?}", e))?
        };
        hachage_src_bytes.extend(&iv_bytes[..]);
    }

    if let Some(tag) = commande.tag.as_ref() {
        let mut tag_bytes: Vec<u8> = match multibase::decode(tag) {
            Ok(b) => b.1,
            Err(e) => Err(format!("calculer_cle_ref Erreur decodage multibase tag : {:?}", e))?
        };
        hachage_src_bytes.extend(&tag_bytes[..]);
    }

    if let Some(header) = commande.header.as_ref() {
        let mut header_bytes: Vec<u8> = match multibase::decode(header) {
            Ok(b) => b.1,
            Err(e) => Err(format!("calculer_cle_ref Erreur decodage multibase header : {:?}", e))?
        };
        hachage_src_bytes.extend(&header_bytes[..]);
    }

    // Ajouter cle secrete
    hachage_src_bytes.extend(cle_secrete.0);

    // Ajouter domaine
    let domaine = commande.domaine.as_str();
    hachage_src_bytes.extend(domaine.as_bytes());

    // Hacher
    let cle_ref = hacher_bytes(&hachage_src_bytes[..], Some(Code::Blake2s256), Some(Base58Btc));

    Ok(cle_ref)
}

/// Rechiffre une cle secrete
pub fn rechiffrer_cle(cle: &mut DocumentClePartition, privee: &EnveloppePrivee, certificat_destination: &EnveloppeCertificat)
    -> Result<(), Box<dyn Error>>
{
    if certificat_destination.verifier_exchanges(vec![Securite::L4Secure, Securite::L3Protege, Securite::L2Prive, Securite::L1Public]) {
        // Ok, certificat de composant avec acces MQ
    } else if certificat_destination.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok, acces global,
    } else if certificat_destination.verifier_roles(vec![RolesCertificats::ComptePrive]) {
        // ComptePrive : certificats sont verifies par le domaine (relai de permission)
    } else {
        Err(format!("maitredescles_partition.rechiffrer_cle Certificat sans user_id ni L4Secure, acces refuse"))?
    }

    let cle_originale = cle.cle.as_str();
    let cle_privee = privee.cle_privee();
    let cle_publique = certificat_destination.certificat().public_key()?;

    let cle_rechiffree = rechiffrer_asymetrique_multibase(cle_privee, &cle_publique, cle_originale)?;

    // Remplacer cle dans message reponse
    cle.cle = cle_rechiffree;

    Ok(())
}
