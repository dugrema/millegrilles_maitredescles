use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use log::{debug, error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use millegrilles_common_rust::base64::{engine::general_purpose::STANDARD_NO_PAD as base64_nopad, Engine as _};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage_cle::{CommandeAjouterCleDomaine, CommandeSauvegarderCle};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::Middleware;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio::{sync::mpsc::Sender, time::{sleep, Duration}};
use millegrilles_common_rust::certificats::ordered_map;
use millegrilles_common_rust::common_messages::{ReponseSignatureCertificat, RequeteDechiffrage};
use millegrilles_common_rust::{multibase, multibase::Base, serde_json};
use millegrilles_common_rust::bson::{bson, doc, serde_helpers::chrono_datetime_as_bson_datetime, Bson, Document};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::hachages::hacher_bytes;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::{optionformatchiffragestr, CleSecrete, FormatChiffrage};
use millegrilles_common_rust::millegrilles_cryptographie::x25519::{chiffrer_asymmetrique_ed25519, CleSecreteX25519};
use millegrilles_common_rust::millegrilles_cryptographie::x509::{EnveloppeCertificat, EnveloppePrivee};
use millegrilles_common_rust::multibase::Base::Base58Btc;
use millegrilles_common_rust::multihash::Code;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::{CleChiffrageHandler, CleSecreteSerialisee};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::epochseconds;
use millegrilles_common_rust::bson;
use millegrilles_common_rust::millegrilles_cryptographie::heapless;
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::{SignatureDomaines, SignatureDomainesRef, SignatureDomainesVersion};

use crate::chiffrage_cles::chiffrer_asymetrique_multibase;
use crate::constants::{CHAMP_CLE_ID, CHAMP_NON_DECHIFFRABLE, DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION, EVENEMENT_DEMANDE_CLE_SYMMETRIQUE, INDEX_CLE_ID, INDEX_NON_DECHIFFRABLES};
use crate::domaines_maitredescles::TypeGestionnaire;
use crate::maitredescles_partition::GestionnaireMaitreDesClesPartition;
use crate::maitredescles_rechiffrage::{CleInterneChiffree, HandlerCleRechiffrage};
use crate::maitredescles_sqlite::GestionnaireMaitreDesClesSQLite;
use crate::messages::MessageReponseChiffree;

pub async fn entretien<M>(middleware: Arc<M>)
    where M: Middleware + 'static
{
    loop {
        sleep(Duration::new(30, 0)).await;
        if middleware.get_mode_regeneration() == true {
            debug!("entretien Regeneration en cours, skip entretien");
            continue;
        }
        debug!("Cycle entretien {}", DOMAINE_NOM);
        middleware.entretien_validateur().await;
    }
}

/// Emet le certificat de maitre des cles
/// Le message n'a aucun contenu, c'est l'enveloppe qui permet de livrer le certificat
/// Si message est None, emet sur evenement.MaitreDesCles.certMaitreDesCles
pub async fn emettre_certificat_maitredescles<M>(middleware: &M, m: Option<MessageValide>)
    -> Result<(), Error>
    where M: GenerateurMessages
{
    debug!("emettre_certificat_maitredescles");

    let reponse = json!({});

    match m {
        Some(demande) => {
            let reply_to = match demande.type_message {
                TypeMessageOut::Requete(r) |
                TypeMessageOut::Commande(r) => match r.reply_to {
                    Some(inner) => inner,
                    None => Err(Error::Str("emettre_certificat_maitredescles Message sans reply_to"))?
                },
                _ => Err(Error::Str("emettre_certificat_maitredescles Mauvais type de message, doit etre requete/commande"))?
            };

            // On utilise une correlation fixe pour permettre au demandeur de recevoir les
            // reponses de plusieurs partitions de maitre des cles en meme temps.
            let routage = RoutageMessageReponse::new(
                reply_to, COMMANDE_CERT_MAITREDESCLES);
            middleware.repondre(routage, &reponse).await?;
        },
        None => {
            let routage = RoutageMessageAction::builder(
                DOMAINE_NOM, COMMANDE_CERT_MAITREDESCLES,
                vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]
            )
                .correlation_id(COMMANDE_CERT_MAITREDESCLES)
                .build();
            middleware.emettre_evenement(routage, &reponse).await?;
        }
    }

    Ok(())
}

/// Emettre les cles de l'instance locale pour s'assurer que tous les maitre des cles en ont une copie
pub async fn emettre_cles_symmetriques<M>(middleware: &M, rechiffreur: &HandlerCleRechiffrage)
    -> Result<(), Error>
    where M: GenerateurMessages + CleChiffrageHandler
{
    debug!("emettre_cles_symmetriques");

    let enveloppe_privee = middleware.get_enveloppe_signature();
    let enveloppes_publiques = middleware.get_publickeys_chiffrage();

    // Recuperer cles symmetriques chiffrees pour CA et tous les maitre des cles connus
    let cle_secrete_chiffree_ca = rechiffreur.get_cle_symmetrique_chiffree(
        &enveloppe_privee.enveloppe_ca.certificat.public_key()?)?;
    let mut cles = HashMap::new();
    for cle in enveloppes_publiques.into_iter() {
        let cle_rechiffree = rechiffreur.get_cle_symmetrique_chiffree(&cle.certificat.public_key()?)?;
        cles.insert(cle.fingerprint()?, cle_rechiffree);
    }

    let evenement = EvenementClesRechiffrage {
        cle_ca: cle_secrete_chiffree_ca,
        cles_dechiffrage: cles,
    };
    // let evenement = json!({
    //     "cle_ca": cle_secrete_chiffree_ca,
    //     "cles_dechiffrage": cles,
    // });

    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM, EVENEMENT_CLES_RECHIFFRAGE, vec![Securite::L4Secure])
        .build();

    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(())
}

pub async fn preparer_rechiffreur<M>(middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage)
    -> Result<(), Error>
    where M: GenerateurMessages + ValidateurX509
{
    info!("preparer_rechiffreur Generer nouvelle cle symmetrique de rechiffrage");
    handler_rechiffrage.generer_cle_symmetrique()
}

pub async fn traiter_cedule<M>(_middleware: &M, _trigger: &MessageCedule) -> Result<(), Error>
where M: Middleware + 'static {
    // let message = trigger.message;

    debug!("Traiter cedule {}", DOMAINE_NOM);

    Ok(())
}

/// Emettre evenement de cles inconnues suite a une requete. Permet de faire la difference entre
/// les cles de la requete et les cles connues.
pub async fn requete_cles_inconnues<M>(middleware: &M, requete: &RequeteDechiffrage, cles_connues: Vec<String>)
    -> Result<MessageListeCles, Error>
    where M: GenerateurMessages + CleChiffrageHandler
{
    let domaine = requete.domaine.clone();

    // Faire une demande interne de sync pour voir si les cles inconnues existent (async)
    let routage_evenement_manquant = RoutageMessageAction::builder(
        DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION, vec![Securite::L4Secure]
    )
        .timeout_blocking(3000)
        .build();

    let mut set_cles = HashSet::new();
    set_cles.extend(requete.liste_hachage_bytes.iter());
    let mut set_cles_trouvees = HashSet::new();
    set_cles_trouvees.extend(&cles_connues);
    todo!("fix me")
    // let set_diff = set_cles.difference(&set_cles_trouvees);
    // let liste_cles: Vec<CleSynchronisation> = set_diff.into_iter().map(|m| {
    //     CleSynchronisation { hachage_bytes: m.to_string(), domaine: domaine.clone() }
    // }).collect();
    // debug!("maitredescles_commun.requete_cles_inconnues Requete de cles inconnues : {:?}", liste_cles);
    //
    // let evenement_cles_manquantes = ReponseSynchroniserCles { liste_cles };
    //
    // let reponse = match middleware.transmettre_requete(routage_evenement_manquant.clone(), &evenement_cles_manquantes).await? {
    //     Some(inner) => match inner {
    //         TypeMessage::Valide(m) => {
    //             debug!("maitredescles_commun.requete_cles_inconnues Reponse recue {:?}", m.type_message);
    //             let message_ref = m.message.parse()?;
    //             match MessageReponseChiffree::try_from(message_ref) {
    //                 Ok(inner) => {
    //                     let message_dechiffre = inner.dechiffrer(middleware)?;
    //                     let reponse: MessageListeCles = serde_json::from_slice(&message_dechiffre.data_dechiffre[..])?;
    //                     reponse
    //                 },
    //                 Err(e) => {
    //                     Err(format!("maitredescles_commun.requete_cles_inconnues synchroniser_cles Erreur dechiffrage reponse : {:?}", e))?
    //                 }
    //             }
    //         },
    //         _ => Err(format!("maitredescles_commun.requete_cles_inconnues Erreur reponse pour requete cle manquante, mauvais type de reponse"))?
    //     },
    //     None => Err(format!("maitredescles_commun.requete_cles_inconnues Aucune reponse pour requete cle manquante"))?
    // };
    //
    // Ok(reponse)
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

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct CleSynchronisation {
    // pub domaine: String,
    // pub hachage_bytes: String,
    pub cle_id: String,
}

impl Into<Bson> for CleSynchronisation {
    fn into(self) -> Bson {
        bson!({
            // "domaine": self.domaine,
            // "hachage_bytes": self.hachage_bytes,
            "cle_id": self.cle_id,
        })
    }
}

impl AsRef<Self> for CleSynchronisation {
    fn as_ref(&self) -> &Self {
        &self
    }
}

impl CleSynchronisation {
    pub fn get_bson_filter<S>(cles: &Vec<S>) -> Result<Vec<Document>, Error>
        where S: AsRef<Self>
    {
        // Extraire refs
        let cles: Vec<&Self> = cles.iter().map(|c| c.as_ref()).collect();

        let mut cles_mappees = Vec::new();
        for cle in cles {
            cles_mappees.push(cle.cle_id.as_str());
        }

        let filtre = doc!{"cle_id": {"$in": cles_mappees}};
        Ok(vec![filtre])

        // let mut map_domaines: HashMap<&String, Vec<&str>> = HashMap::new();
        // for item in cles {
        //     match map_domaines.get_mut(&item.domaine) {
        //         Some(liste) => liste.push(item.hachage_bytes.as_str()),
        //         None => {
        //             let mut liste = Vec::new();
        //             liste.push(item.hachage_bytes.as_str());
        //             map_domaines.insert(&item.domaine, liste);
        //         }
        //     }
        // }
        //
        // // Fabriquer un Vec de { domaine: mon_domaine, hachage_bytes: {"$in": [...]} }
        // // Permet de creer un filtre avec { "$or": ...vec... }
        // let mut liste_domaines = Vec::new();
        // for (domaine, liste) in map_domaines.into_iter() {
        //     liste_domaines.push(doc!{ CHAMP_DOMAINE: domaine, CHAMP_HACHAGE_BYTES: {"$in": liste}});
        // }
        //
        // Ok(liste_domaines)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseSynchroniserCles {
    pub liste_cle_id: Vec<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseConfirmerClesSurCa {
    pub cles_manquantes: Vec<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CleSecreteRechiffrage {
    pub signature: SignatureDomaines,
    pub cle_secrete: String,
    // pub hachage_bytes: String,
    // pub domaine: String,
    pub format: Option<String>,
    pub header: Option<String>,
    // pub identificateurs_document: HashMap<String, String>,
}

// impl Into<IdentiteCle> for CleSecreteRechiffrage {
//     fn into(self) -> IdentiteCle {
//         IdentiteCle {
//             hachage_bytes: self.hachage_bytes.clone(),
//             domaine: self.domaine.clone(),
//             identificateurs_document: self.identificateurs_document.clone(),
//             signature_identite: self.signature_identite.clone(),
//         }
//     }
// }

impl TryInto<RowClePartition> for CleSecreteRechiffrage {
    type Error = String;

    fn try_into(self) -> Result<RowClePartition, Self::Error> {
        todo!("fix me")
        // Ok(RowClePartition {
        //     cle_ref: self.hachage_bytes.clone(),
        //     hachage_bytes: self.hachage_bytes,
        //     domaine: self.domaine,
        //     identificateurs_document: self.identificateurs_document,
        //     // signature_identite: self.signature_identite,
        //     cle: "".to_string(),
        //     cle_symmetrique: None,
        //     nonce_symmetrique: None,
        //     format: self.format.as_str().try_into()?,
        //     iv: None,
        //     tag: None,
        //     header: Some(self.header),
        // })
    }
}

impl TryFrom<CommandeSauvegarderCle> for CleSecreteRechiffrage {
    type Error = String;

    fn try_from(value: CommandeSauvegarderCle) -> Result<Self, Self::Error> {
        let header = match value.header {
            Some(inner) => inner,
            None => Err(format!("TryFrom<CommandeSauvegarderCle> Header manquant"))?
        };
        let format: &str = value.format.into();

        todo!("fix me")
        // let mut domaines = heapless::Vec::new();
        // domaines.push(value.domaine.try_into().map_err(|_|Error::Str("TryFrom<CommandeSauvegarderCle> Erreur map domaine vers heapless::String"))?)
        //     .map_err(|_|Error::Str("TryFrom<CommandeSauvegarderCle>Erreur ajout domaine dans heapless::Vec"))?;
        // let signature = SignatureDomaines {
        //     domaines,
        //     version: SignatureDomainesVersion::NonSigne,
        //     ca: None,
        //     signature: value.hachage_bytes,
        // };
        //
        // Ok(Self {
        //     signature,
        //     cle_secrete: "".to_string(),
        //     // domaine: value.domaine,
        //     format: format.to_string(),
        //     // hachage_bytes: value.hachage_bytes,
        //     header,
        //     // identificateurs_document: value.identificateurs_document,
        //     // signature_identite: value.signature_identite,
        // })
    }
}

impl CleSecreteRechiffrage {

    // fn try_from(value: CommandeSauvegarderCle) -> Result<Self, Self::Error> {
    pub fn from_commande(cle_secrete: &CleSecreteX25519, value: CommandeSauvegarderCle) -> Result<Self, Error> {
        let header = match value.header {
            Some(inner) => inner,
            None => Err(format!("TryFrom<CommandeSauvegarderCle> Header manquant"))?
        };
        todo!("Fix me")
        // let cle_secrete_string: String = multibase::encode(Base::Base64, &cle_secrete.0);
        // let format: &str = value.format.into();
        // Ok(Self {
        //     cle_secrete: cle_secrete_string,
        //     domaine: value.domaine,
        //     format: format.to_string(),
        //     hachage_bytes: value.hachage_bytes,
        //     header,
        //     identificateurs_document: value.identificateurs_document,
        //     // signature_identite: value.signature_identite,
        // })
    }

    pub fn from_doc_cle(cle_secrete: CleSecreteX25519, value: RowClePartition) -> Result<Self, Error> {
        let header = match value.header {
            Some(inner) => inner,
            None => Err(format!("TryFrom<CommandeSauvegarderCle> Header manquant"))?
        };
        let cle_secrete_string: String = multibase::encode(Base::Base64, &cle_secrete.0);
        todo!("fix me")
        // let format: &str = value.format.into();
        // Ok(Self {
        //     cle_secrete: cle_secrete_string,
        //     domaine: value.domaine,
        //     format: format.to_string(),
        //     hachage_bytes: value.hachage_bytes,
        //     header,
        //     identificateurs_document: value.identificateurs_document,
        //     // signature_identite: value.signature_identite,
        // })
    }

    pub fn get_cle_secrete(&self) -> Result<CleSecreteX25519, Error> {
        let cle_secrete: Vec<u8> = base64_nopad.decode(&self.cle_secrete)?;
        let mut cle_secrete_dechiffree = CleSecrete([0u8; 32]);
        cle_secrete_dechiffree.0.copy_from_slice(&cle_secrete[..]);
        Ok(cle_secrete_dechiffree)
    }

    // fn verifier_identite(&self, cle: &CleSecrete) -> Result<(), Error>{
    //     let identite_cle: IdentiteCle = self.clone().into();
    //     if identite_cle.verifier(cle)? != true {
    //         warn!("maitredescles_common.CleSecreteRechiffrage Erreur verifier identite commande, signature invalide pour cle {}", self.hachage_bytes);
    //         Err(format!("maitredescles_commun.CleSecreteRechiffrage Identite cle mismatch"))?
    //     }
    //     Ok(())
    // }

    pub fn get_cle_ref(&self) -> Result<String, Error> {
        let cle_secrete = self.get_cle_secrete()?;
        let cle_info = CleRefData::from(self);
        Ok(calculer_cle_ref(cle_info, &cle_secrete)?)
    }

    /// Rechiffre la cle secrete dechiffree.
    pub fn rechiffrer_cle(&self, handler_rechiffrage: &HandlerCleRechiffrage) -> Result<(String, CleInterneChiffree), Error> {
        let cle_secrete = self.get_cle_secrete()?;

        // Verifier la signature de la cle. Lance une exception si invalide
        self.signature.verifier_derivee(&cle_secrete.0)?;

        // Recuperer l'identificateur unique de cle.
        let cle_id = self.signature.get_cle_ref()?.to_string();

        // Rechiffrer cle
        let cle_rechiffree = handler_rechiffrage.chiffrer_cle_secrete(&cle_secrete.0[..])?;
        Ok((cle_id, cle_rechiffree))
    }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeRechiffrerBatch {
    pub cles: Vec<CleSecreteRechiffrage>
}

/// Transaction de sauvegarde de cle CA version 2.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionCleV2 {
    pub signature: SignatureDomaines
}

/// Transaction orignale de sauvegarde de cle CA.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

// impl From<RowClePartitionRef<'_>> for TransactionCle {
//     fn from(value: RowClePartitionRef) -> Self {
//         let mut map_iddocs = HashMap::new();
//         for (k, v) in value.identificateurs_document {
//             map_iddocs.insert(k.to_string(), v.to_string());
//         }
//
//         Self {
//             hachage_bytes: value.hachage_bytes.to_string(),
//             domaine: value.domaine.to_string(),
//             identificateurs_document: map_iddocs,
//             cle: value.cle.to_string(),
//             format: value.format,
//             iv: match value.iv { Some(inner) => Some(inner.to_string()), None => None },
//             tag: match value.tag { Some(inner) => Some(inner.to_string()), None => None },
//             header: match value.header { Some(inner) => Some(inner.to_string()), None => None },
//             partition: match value.partition { Some(inner) => Some(inner.to_string()), None => None },
//         }
//     }
// }

// impl Into<IdentiteCle> for TransactionCle {
//     fn into(self) -> IdentiteCle {
//         IdentiteCle {
//             hachage_bytes: self.hachage_bytes,
//             domaine: self.domaine,
//             identificateurs_document: self.identificateurs_document,
//             signature_identite: self.signature_identite
//         }
//     }
// }

impl TransactionCle {
    pub fn new_from_commande(commande: &CommandeSauvegarderCle, fingerprint: &str)
        -> Result<Self, Error>
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
            // signature_identite: commande.signature_identite.clone(),
            cle: cle.to_owned(),
            format: Some(commande.format.clone()),
            iv: commande.iv.clone(),
            tag: commande.tag.clone(),
            header: commande.header.clone(),
            partition: commande.partition.clone(),
        })
    }

    pub fn into_commande<S>(self, fingerprint: S) -> Result<CommandeSauvegarderCle, Error>
        where S: Into<String>
    {
        let fingerprint_ = fingerprint.into();
        let mut cles: HashMap<String, String> = HashMap::new();
        cles.insert(fingerprint_, self.cle);

        let format = match self.format {
            Some(inner) => inner,
            None => Err(Error::Str("TransactionCle.into_commande Format manquant"))?
        };

        Ok(CommandeSauvegarderCle {
            hachage_bytes: self.hachage_bytes,
            domaine: self.domaine,
            identificateurs_document: self.identificateurs_document,
            // signature_identite: self.signature_identite,
            cles,
            format,
            iv: self.iv,
            tag: self.tag,
            header: self.header,
            partition: self.partition,
            fingerprint_partitions: None
        })
    }

    // pub fn verifier_identite(&self, cle_secrete: &CleSecrete) -> Result<bool, String> {
    //     let identite: IdentiteCle = self.clone().into();
    //     Ok(identite.verifier(cle_secrete)?)
    // }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RowClePartition {
    // Identite
    pub cle_id: String,
    pub signature: SignatureDomaines,

    // pub cle_ref: String,
    // pub hachage_bytes: String,
    // pub domaine: String,
    // pub identificateurs_document: HashMap<String, String>,

    // Cle chiffree
    // pub cle: String,

    pub cle_symmetrique: Option<String>,
    pub nonce_symmetrique: Option<String>,

    // Information de dechiffrage contenu (utilise avec signature version 0)
    #[serde(default, with="optionformatchiffragestr")]
    pub format: Option<FormatChiffrage>,
    pub iv: Option<String>,
    pub tag: Option<String>,
    pub header: Option<String>,
}

impl From<CommandeSauvegarderCle> for RowClePartition {
    fn from(value: CommandeSauvegarderCle) -> Self {
        todo!("fix me")
        // Self {
        //     cle_ref: "".to_string(),
        //     hachage_bytes: value.hachage_bytes,
        //     domaine: value.domaine,
        //     identificateurs_document: value.identificateurs_document,
        //     // signature_identite: value.signature_identite,
        //     cle: "".to_string(),
        //     cle_symmetrique: None,
        //     nonce_symmetrique: None,
        //     format: value.format,
        //     iv: value.iv,
        //     tag: value.tag,
        //     header: value.header
        // }
    }
}

impl RowClePartition {

    pub fn into_commande<S>(self, fingerprint: S) -> CommandeSauvegarderCle
        where S: Into<String>
    {
        let fingerprint_ = fingerprint.into();
        let mut cles: HashMap<String, String> = HashMap::new();
        todo!("fix me")
        // cles.insert(fingerprint_.clone(), self.cle);
        // CommandeSauvegarderCle {
        //     hachage_bytes: self.hachage_bytes,
        //     domaine: self.domaine,
        //     identificateurs_document: self.identificateurs_document,
        //     // signature_identite: self.signature_identite,
        //     cles,
        //     format: self.format,
        //     iv: self.iv,
        //     tag: self.tag,
        //     header: self.header,
        //     partition: Some(fingerprint_),
        //     fingerprint_partitions: None
        // }
    }

    pub fn try_into_document_cle_partition<S,T>(value: &DocCleSymmetrique, fingerprint: S, cle_ref: T) -> Result<RowClePartition, String>
        where S: Into<String>,
              T: Into<String>
    {
        let fingerprint = fingerprint.into();
        let cle_ref = cle_ref.into();

        todo!("Chiffrer en cle symmetrique");

        // let cle = match value.cles.get(&fingerprint) {
        //     Some(c) => c.as_str(),
        //     None => Err(format!("DocumentClePartition.try_into_document_cle_partition Erreur cle introuvable {}", fingerprint))?
        // };
        //
        // Ok(DocumentClePartition {
        //     cle_ref,
        //     hachage_bytes: value.hachage_bytes.clone(),
        //     domaine: value.domaine.clone(),
        //     identificateurs_document: value.identificateurs_document.clone(),
        //     signature_identite: value.signature_identite.clone(),
        //     cle: cle.to_string(),
        //     cle_symmetrique: None,
        //     nonce_symmetrique: None,
        //     format: value.format.clone(),
        //     iv: value.iv.clone(),
        //     tag: value.tag.clone(),
        //     header: value.header.clone()
        // })
    }

    pub fn to_cle_secrete_serialisee(self, rechiffrage_handler: &HandlerCleRechiffrage)
                                     -> Result<CleSecreteSerialisee, Error>
    {
        let cle_interne = match self.cle_symmetrique.as_ref() {
            Some(cle) => match self.nonce_symmetrique.as_ref() {
                Some(nonce) => Ok(CleInterneChiffree { cle: cle.clone(), nonce: nonce.clone() }),
                None => Err(Error::Str("to_cle_secrete_serializee cle_symmetrique manquante"))
            },
            None => Err(Error::Str("to_cle_secrete_serializee nonce manquant"))
        }?;

        let cle_secrete = rechiffrage_handler.dechiffer_cle_secrete(cle_interne)?;

        let cle_id = self.cle_id.clone();

        // Retirer le 'm' multibase du iv/header pour convertir en format nonce
        let nonce = match self.iv {
            Some(inner) => Some(inner.as_str()[1..].to_string()),
            None => match self.header {
                Some(inner) => Some(inner.as_str()[1..].to_string()),
                None => None
            }
        };

        let verification = match self.tag {
            Some(inner) => Some(inner),
            None => match self.signature.version {
                SignatureDomainesVersion::NonSigne => Some(self.signature.signature.to_string()),
                _ => None
            }
        };

        Ok(CleSecreteSerialisee::from_cle_secrete(cle_secrete, Some(cle_id), self.format, nonce, verification)?)
    }

}

#[derive(Clone, Deserialize)]
pub struct RowClePartitionRef<'a> {
    // Identite
    pub cle_id: String,
    pub signature: SignatureDomainesRef<'a>,

    // Cle chiffree
    pub cle_symmetrique: Option<&'a str>,
    pub nonce_symmetrique: Option<&'a str>,
    //pub cle: &'a str,

    // Information de dechiffrage contenu (utilise avec signature version 0)
    #[serde(default, skip_serializing_if = "Option::is_none", with = "optionformatchiffragestr")]
    pub format: Option<FormatChiffrage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<&'a str>,

    #[serde(rename(deserialize="_mg-creation"),
    serialize_with="epochseconds::serialize",
    deserialize_with="bson::serde_helpers::chrono_datetime_as_bson_datetime::deserialize")]
    pub date_creation: DateTime<Utc>,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocCleSymmetrique {
    // Identite de la cle
    pub hachage_bytes: String,
    pub domaine: String,
    #[serde(serialize_with = "ordered_map")]
    pub identificateurs_document: HashMap<String, String>,
    // pub signature_identite: String,

    // Cles chiffrees
    //#[serde(serialize_with = "ordered_map")]
    // pub cles: HashMap<String, String>,
    pub cle_symmetrique: Option<String>,
    pub nonce_symmetrique: Option<String>,

    // Information de dechiffrage
    pub format: FormatChiffrage,
    pub iv: Option<String>,
    pub tag: Option<String>,
    pub header: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseCleManquantes {
    pub ok: Option<bool>,
    pub cles: Option<Vec<DocCleSymmetrique>>,
}

impl Into<CommandeSauvegarderCle> for DocCleSymmetrique {
    fn into(self) -> CommandeSauvegarderCle {
        CommandeSauvegarderCle {
            hachage_bytes: self.hachage_bytes.clone(),
            domaine: self.domaine.clone(),
            identificateurs_document: self.identificateurs_document.clone(),
            // signature_identite: self.signature_identite.clone(),
            // cles: self.cles.clone(),
            cles: HashMap::new(),
            format: self.format.clone(),
            iv: self.iv.clone(),
            tag: self.tag.clone(),
            header: self.header.clone(),
            partition: None,
            fingerprint_partitions: None
        }
    }
}

impl From<RowClePartition> for DocCleSymmetrique {
    fn from(value: RowClePartition) -> Self {
        todo!("fix me")
        // Self {
        //     hachage_bytes: value.hachage_bytes,
        //     domaine: value.domaine,
        //     identificateurs_document: value.identificateurs_document,
        //     // signature_identite: value.signature_identite,
        //     // cles: HashMap::new(),
        //     cle_symmetrique: value.cle_symmetrique,
        //     nonce_symmetrique: value.nonce_symmetrique,
        //     format: value.format,
        //     iv: value.iv,
        //     tag: value.tag,
        //     header: value.header
        // }
    }
}

pub struct GestionnaireRessources {
    pub tx_messages: Option<Sender<TypeMessage>>,
    pub tx_triggers: Option<Sender<TypeMessage>>,
    pub routing: Mutex<HashMap<String, Sender<TypeMessage>>>,
}

pub struct CleRefData<'a> {
    hachage_bytes: &'a str,
    iv: Option<&'a str>,
    tag: Option<&'a str>,
    header: Option<&'a str>,
    domaine: &'a str,
}

impl<'a> From<&'a CommandeSauvegarderCle> for CleRefData<'a> {
    fn from(value: &'a CommandeSauvegarderCle) -> Self {
        Self {
            hachage_bytes: value.hachage_bytes.as_str(),
            iv: match value.iv.as_ref() { Some(inner) => Some(inner.as_str()), None => None },
            tag: match value.tag.as_ref() { Some(inner) => Some(inner.as_str()), None => None },
            header: match value.header.as_ref() { Some(inner) => Some(inner.as_str()), None => None },
            domaine: value.domaine.as_str(),
        }
    }
}

impl<'a> From<&'a CleSecreteRechiffrage> for CleRefData<'a> {
    fn from(value: &'a CleSecreteRechiffrage) -> Self {
        todo!("Fix me")
        // Self {
        //     hachage_bytes: value.hachage_bytes.as_str(),
        //     iv: None,
        //     tag: None,
        //     header: Some(value.header.as_str()),
        //     domaine: value.domaine.as_str(),
        // }
    }
}

/// Calcule la cle_ref a partir du hachage et cle_secret d'une cle recue (commande/transaction)
pub fn calculer_cle_ref(info: CleRefData, cle_secrete: &CleSecreteX25519) -> Result<String, String>
{
    let hachage_bytes_str = info.hachage_bytes;
    let mut hachage_src_bytes: Vec<u8> = match multibase::decode(hachage_bytes_str) {
        Ok(b) => b.1,
        Err(e) => Err(format!("calculer_cle_ref Erreur decodage multibase hachage_bytes : {:?}", e))?
    };

    // Ajouter iv, tag, header si presents
    if let Some(iv) = info.iv {
        let mut iv_bytes: Vec<u8> = match multibase::decode(iv) {
            Ok(b) => b.1,
            Err(e) => Err(format!("calculer_cle_ref Erreur decodage multibase iv : {:?}", e))?
        };
        hachage_src_bytes.extend(&iv_bytes[..]);
    }

    if let Some(tag) = info.tag {
        let mut tag_bytes: Vec<u8> = match multibase::decode(tag) {
            Ok(b) => b.1,
            Err(e) => Err(format!("calculer_cle_ref Erreur decodage multibase tag : {:?}", e))?
        };
        hachage_src_bytes.extend(&tag_bytes[..]);
    }

    if let Some(header) = info.header {
        let mut header_bytes: Vec<u8> = match multibase::decode(header) {
            Ok(b) => b.1,
            Err(e) => Err(format!("calculer_cle_ref Erreur decodage multibase header : {:?}", e))?
        };
        hachage_src_bytes.extend(&header_bytes[..]);
    }

    // Ajouter cle secrete
    hachage_src_bytes.extend(cle_secrete.0);

    // Ajouter domaine
    let domaine = info.domaine;
    hachage_src_bytes.extend(domaine.as_bytes());

    // Hacher
    let cle_ref = hacher_bytes(&hachage_src_bytes[..], Some(Code::Blake2s256), Some(Base58Btc));

    Ok(cle_ref)
}

// /// Rechiffre une cle secrete
// // pub fn rechiffrer_cle(cle: &mut DocumentClePartition, privee: &EnveloppePrivee, certificat_destination: &EnveloppeCertificat)
// pub fn rechiffrer_cle(cle: &mut RowClePartition, handler_rechiffrage: &HandlerCleRechiffrage, certificat_destination: &EnveloppeCertificat)
//                       -> Result<(), Error>
// {
//     if certificat_destination.verifier_exchanges(vec![Securite::L4Secure, Securite::L3Protege, Securite::L2Prive, Securite::L1Public])? {
//         // Ok, certificat de composant avec acces MQ
//     } else if certificat_destination.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
//         // Ok, acces global,
//     } else if certificat_destination.verifier_roles(vec![RolesCertificats::ComptePrive])? {
//         // ComptePrive : certificats sont verifies par le domaine (relai de permission)
//     } else {
//         Err(format!("maitredescles_partition.rechiffrer_cle Certificat sans user_id ni L4Secure, acces refuse"))?
//     }
//
//     let cle_interne = CleInterneChiffree::try_from(cle.clone())?;
//     let cle_secrete = handler_rechiffrage.dechiffer_cle_secrete(cle_interne)?;
//
//     // let cle_originale = cle.cle.as_str();
//     // let cle_privee = privee.cle_privee();
//     let cle_publique = certificat_destination.certificat.public_key()?;
//     // let cle_rechiffree = rechiffrer_asymetrique_multibase(cle_privee, &cle_publique, cle_originale)?;
//     let cle_rechiffree = chiffrer_asymetrique_multibase(cle_secrete, &cle_publique)?;
//
//     debug!("rechiffrer_cle Cle {} rechiffree : {}", cle.cle_id, cle_rechiffree);
//
//     todo!("fix me")
//     // // Remplacer cle dans message reponse
//     // cle.cle = cle_rechiffree;
//     //
//     // Ok(())
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentCleRechiffrage {
    #[serde(rename="type")]
    pub type_: String,
    pub instance_id: String,
    pub fingerprint: Option<String>,
    pub cle: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvenementClesRechiffrage {
    pub cle_ca: String,
    pub cles_dechiffrage: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeRotationCertificat {
    pub certificat: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeCleSymmetrique {
    pub cle: String,
    pub fingerprint: String,
}

/// Emettre une demande de rechiffrage de cle symmetrique par un tiers
pub async fn emettre_demande_cle_symmetrique<M,S>(middleware: &M, cle_ca: S) -> Result<(), Error>
    where M: GenerateurMessages, S: AsRef<str>
{
    let cle_privee = middleware.get_enveloppe_signature();
    let instance_id = cle_privee.enveloppe_pub.get_common_name()?;

    debug!("emettre_demande_cle_symmetrique Demander la cle symmetrique pour instance_id : {}", instance_id);

    let evenement = json!({
        "cle_symmetrique_ca": cle_ca.as_ref(),
    });

    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM, EVENEMENT_DEMANDE_CLE_SYMMETRIQUE, vec![Securite::L3Protege])
        .correlation_id(EVENEMENT_DEMANDE_CLE_SYMMETRIQUE)
        .build();

    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(())
}

#[derive(Clone, Deserialize)]
pub struct MessageListeCles {
    pub cles: Vec<CleSecreteRechiffrage>
}

// /// Genere une commande de sauvegarde de cles pour tous les certificats maitre des cles connus
// /// incluant le certificat de millegrille
// pub fn rechiffrer_pour_maitredescles<M>(middleware: &M, handler: &HandlerCleRechiffrage, cle: RowClePartition)
//     -> Result<CommandeTransfertClesV2, Error>
//     where M: GenerateurMessages + CleChiffrageHandler
// {
//     let mut signature = cle.signature.clone();
//
//     // Dechiffrer cle secrete
//     let cle_interne = CleInterneChiffree::try_from(cle.clone())?;
//     let cle_secrete = handler.dechiffer_cle_secrete(cle_interne)?;
//
//     let enveloppe_privee = middleware.get_enveloppe_signature();
//
//     // Verifier si la cle rechiffree CA est deja dans la signature. L'ajouter au besoin.
//     if signature.ca.is_none() {
//         debug!("rechiffrer_pour_maitredescles_ca Rechiffrer la cle pour le CA");
//
//         // Chiffrer pour le CA
//         let cle_publique_ca = &enveloppe_privee.enveloppe_ca.certificat.public_key()?;
//         let cle_rechiffree = chiffrer_asymmetrique_ed25519(&cle_secrete.0[..], cle_publique_ca)?;
//         let cle_ca_str = base64_nopad.encode(cle_rechiffree);
//         signature.ca = Some(cle_ca_str.as_str().try_into().map_err(|_| Error::Str("Erreur conversion cle_ca_str en heapless::String"))?);
//     }
//
//     let fingerprint_local = enveloppe_privee.fingerprint()?;
//     let pk_chiffrage = middleware.get_publickeys_chiffrage();
//     let mut map_cles_chiffrees = HashMap::new();
//     for cle in pk_chiffrage {
//         let fingerprint = cle.fingerprint()?;
//         if fingerprint == fingerprint_local {
//             continue  // On a deja la cle dechiffree localement, skip
//         }
//         let cle_publique = &cle.certificat.public_key()?;
//         let cle_rechiffree = chiffrer_asymmetrique_ed25519(&cle_secrete.0[..], cle_publique)?;
//         let cle_ca_str = base64_nopad.encode(cle_rechiffree);
//         map_cles_chiffrees.insert(fingerprint, cle_ca_str);
//     }
//
//     Ok(CommandeTransfertCle {
//         cles: map_cles_chiffrees,
//         signature,
//         format: cle.format,
//         iv: cle.iv,
//         tag: cle.tag,
//         header: cle.header,
//     })
// }

// /// Dechiffre le message kind:8 d'une batch
// pub fn dechiffrer_batch<M>(middleware: &M, m: MessageValide) -> Result<CommandeRechiffrerBatch, Error>
// pub fn dechiffrer_batch<M>(middleware: &M, m: MessageValide) -> Result<CommandeRechiffrerBatch, Error>
//     where M: GenerateurMessages + CleChiffrageHandler
// {
//     // Dechiffrer la cle asymmetrique pour certificat local
//     let (header, cle_secrete) = match m.message.parsed.dechiffrage.as_ref() {
//         Some(inner) => {
//             let enveloppe_privee = middleware.get_enveloppe_signature();
//             let fingerprint_local = enveloppe_privee.fingerprint().as_str();
//             let header = match inner.header.as_ref() {
//                 Some(inner) => inner.as_str(),
//                 None => Err(format!("maitredescles_partition.commande_rechiffrer_batch Erreur format message, header absent"))?
//             };
//             match inner.cles.as_ref() {
//                 Some(inner) => {
//                     match inner.get(fingerprint_local) {
//                         Some(inner) => {
//                             // Cle chiffree, on dechiffre
//                             let cle_bytes = multibase::decode(inner)?;
//                             let cle_secrete = dechiffrer_asymmetrique_ed25519(&cle_bytes.1[..], enveloppe_privee.cle_privee())?;
//                             (header, cle_secrete)
//                         },
//                         None => Err(format!("maitredescles_partition.commande_rechiffrer_batch Erreur format message, dechiffrage absent"))?
//                     }
//                 },
//                 None => Err(format!("maitredescles_partition.commande_rechiffrer_batch Erreur format message, dechiffrage absent"))?
//             }
//         },
//         None => Err(format!("maitredescles_partition.commande_rechiffrer_batch Erreur format message, dechiffrage absent"))?
//     };
//
//     // Dechiffrer le contenu
//     let data_chiffre = DataChiffre {
//         ref_hachage_bytes: None,
//         data_chiffre: format!("m{}", m.message.parsed.contenu),
//         format: FormatChiffrage::mgs4,
//         header: Some(header.to_owned()),
//         tag: None,
//     };
//     debug!("commande_rechiffrer_batch Data chiffre contenu : {:?}", data_chiffre);
//
//     let cle_dechiffre = CleDechiffree {
//         cle: "m".to_string(),
//         cle_secrete,
//         domaine: "MaitreDesCles".to_string(),
//         format: "mgs4".to_string(),
//         hachage_bytes: "".to_string(),
//         identificateurs_document: None,
//         iv: None,
//         tag: None,
//         header: Some(header.to_owned()),
//         signature_identite: "".to_string(),
//     };
//
//     debug!("commande_rechiffrer_batch Dechiffrer data avec cle dechiffree");
//     let data_dechiffre = dechiffrer_data(cle_dechiffre, data_chiffre)?;
//     debug!("commande_rechiffrer_batch Data dechiffre len {}", data_dechiffre.data_dechiffre.len());
//     debug!("commande_rechiffrer_batch Data dechiffre {:?}", String::from_utf8(data_dechiffre.data_dechiffre.clone()));
//
//     let commande: CommandeRechiffrerBatch = serde_json::from_slice(&data_dechiffre.data_dechiffre[..])?;
//     debug!("commande_rechiffrer_batch Commande parsed : {:?}", commande);
//
//     Ok(commande)
// }

#[derive(Debug)]
pub struct ErrorPermissionRefusee {
    pub code: usize,
    pub err: String,
}

pub enum ErreurPermissionRechiffrage { Refuse(ErrorPermissionRefusee), Error(Error) }

impl<E> From<E> for ErreurPermissionRechiffrage where E: std::error::Error {
    fn from(value: E) -> Self {
        let err = Error::String(format!("ErreurPermissionRechiffrage {:?}", value));
        Self::Error(err)
    }
}

pub async fn verifier_permission_rechiffrage<M>(middleware: &M, m: &MessageValide, requete: &RequeteDechiffrage)
                                                -> Result<(Arc<EnveloppeCertificat>, bool), ErreurPermissionRechiffrage>
    where M: MongoDao + GenerateurMessages + ValidateurX509
{
    debug!("requete_dechiffrage cle parsed : {:?}", requete);
    let certificat_requete = m.certificat.as_ref();

    let extensions = certificat_requete.extensions()?;
    let domaines_permis = extensions.domaines;

    // Trouver le certificat de rechiffrage
    let certificat = match requete.certificat_rechiffrage.as_ref() {
        Some(cr) => {
            debug!("requete_dechiffrage Utilisation certificat dans la requete de dechiffrage");
            middleware.charger_enveloppe(cr, None, None).await?
        },
        None => m.certificat.clone()
    };

    let certificat_valide = middleware.valider_chaine(certificat.as_ref(), None, true).unwrap_or_else(|e| {
        error!("requete_dechiffrage Erreur de validation du certificat : {:?}", e);
        false
    });
    if !certificat_valide {
        // let refuse = json!({"ok": false, "err": "Autorisation refusee - certificat de rechiffrage n'est pas presentement valide", "acces": "0.refuse", "code": 0});
        // return Ok(Some(middleware.build_reponse(&refuse)?.0))
        Err(ErreurPermissionRechiffrage::Refuse(ErrorPermissionRefusee { code: 0, err: "Autorisation refusee - certificat de rechiffrage n'est pas presentement valide".to_string() }) )?
    }

    // Verifier si on a une autorisation de dechiffrage global
    let requete_autorisee_globalement = if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        debug!("verifier_autorisation_dechiffrage Certificat delegation globale proprietaire - toujours autorise");
        true
    } else {
        false
    };

    // Rejeter si global false et permission absente
    // if ! requete_autorisee_globalement && permission.is_none() && domaines_permis.is_none() {
    if !requete_autorisee_globalement && domaines_permis.is_none() {
        debug!("requete_dechiffrage Requete {:?} de dechiffrage {:?} refusee, permission manquante ou aucuns domaines inclus dans le certificat",
            m.type_message, requete.liste_hachage_bytes);
        // let refuse = json!({"ok": false, "err": "Autorisation refusee - permission manquante", "acces": "0.refuse", "code": 0});
        // return Ok(Some(middleware.build_reponse(&refuse)?.0))
        Err(ErreurPermissionRechiffrage::Refuse(ErrorPermissionRefusee { code: 0, err: "Autorisation refusee - permission manquante".to_string() }) )?
    }

    if let Some(domaines_permis) = domaines_permis {
        // S'assurer que le domaine demande et inclus dans la liste des domaines permis
        let mut permis = false;
        for domaine in domaines_permis {
            if requete.domaine.as_str() == domaine.as_str() {
                permis = true;
                break;
            }
        }
        if permis == false {
            debug!("requete_dechiffrage Requete {:?} de dechiffrage refusee, domaine n'est pas autorise", m.type_message);
            // let refuse = json!({"ok": false, "err": "Autorisation refusee - domaine non autorise", "acces": "0.refuse", "code": 0});
            // return Ok(Some(middleware.build_reponse(&refuse)?.0))
            Err(ErreurPermissionRechiffrage::Refuse(ErrorPermissionRefusee { code: 0, err: "Autorisation refusee - domaine non autorise".to_string() }) )?
        }
    }

    Ok((certificat, requete_autorisee_globalement))
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct CommandeTransfertCle {
//     /// Cles chiffrees pour differents destinataires.
//     /// Key : fingerprint hex, Value: cle chiffree base64
//     pub cles: HashMap<String, String>,
//
//     /// Signature des domaines autorises pour le dechiffrage.
//     pub signature: SignatureDomaines,
//
//     // Information de dechiffrage symmetrique (obsolete)
//     #[serde(default, with = "optionformatchiffragestr")]
//     pub format: Option<FormatChiffrage>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub iv: Option<String>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub tag: Option<String>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub header: Option<String>,
// }

/// Requete de dechiffrage de cles par domaine/ids
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteTransfert {
    /// fingerprint du certificat du maitre des cles a l'origine de la requete
    pub fingerprint: String,
    /// Liste de cle_id a rechiffrer
    pub cle_ids: Vec<String>,
    /// Si true, indique qu'on veut une reponse meme si elle est incomplete (incluant 0 cles).
    pub toujours_repondre: Option<bool>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CleTransfert {
    /// Cle secrete dechiffree en format base64 no pad
    pub cle_secrete_base64: String,

    /// Signature des domaines pour cette cle
    #[zeroize(skip)]
    pub signature: SignatureDomaines,

    // Information obsolete (chiffrage V1)

    /// Format de chiffrage.
    #[serde(default, with="optionformatchiffragestr")]
    #[zeroize(skip)]
    pub format: Option<FormatChiffrage>,

    /// Nonce ou header selon l'algorithme.
    #[zeroize(skip)]
    pub nonce: Option<String>,

    /// Element de verification selon le format de chiffrage.
    /// Peut etre un hachage (e.g. blake2s) ou un HMAC (e.g. compute tag de chacha20-poly1305).
    #[zeroize(skip)]
    pub verification: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CommandeTransfertClesV2 {
    /// Fingerprint du maitre des cles emetteur
    pub fingerprint_emetteur: String,

    /// Liste de cles secretes (dechiffrees)
    pub cles: Vec<CleTransfert>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CleTransfertCa {
    /// Signature des domaines pour cette cle
    pub signature: SignatureDomaines,

    // Information obsolete (chiffrage V1)

    /// Format de chiffrage.
    #[serde(default, with="optionformatchiffragestr")]
    pub format: Option<FormatChiffrage>,

    /// Nonce ou header selon l'algorithme.
    pub nonce: Option<String>,

    /// Element de verification selon le format de chiffrage.
    /// Peut etre un hachage (e.g. blake2s) ou un HMAC (e.g. compute tag de chacha20-poly1305).
    pub verification: Option<String>,
}

/// Liste des cles pour le CA. Le contenu est chiffre.
#[derive(Clone, Serialize, Deserialize)]
pub struct CommandeTransfertClesCaV2 {
    /// Liste de cles chiffrees
    pub cles: Vec<CleTransfertCa>,
}
