use millegrilles_common_rust::tracing::{debug, error, info, warn};
use std::collections::HashMap;
use std::str::from_utf8;
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::constants::{DOMAINE_NOM, EVENEMENT_DEMANDE_CLE_SYMMETRIQUE, REQUETE_TRANSFERT_CLES};
use crate::errors::{ErreurPermissionRechiffrage, ErrorPermissionRefusee};
use crate::external::crypto::SymmetricEncryptionHandler;
use crate::models::CleInterneChiffree;
use millegrilles_common_rust::base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as base64_nopad};
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::{Bson, bson, doc};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::common_messages::RequeteDechiffrage;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::{CleSecrete, FormatChiffrage, optionformatchiffragestr};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::{CleChiffrageHandler, CleSecreteSerialisee};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::{SignatureDomaines, SignatureDomainesRef, SignatureDomainesVersion};
use millegrilles_common_rust::millegrilles_cryptographie::x25519::CleSecreteX25519;
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::json;

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
pub async fn emettre_cles_symmetriques<M>(middleware: &M, rechiffreur: &SymmetricEncryptionHandler)
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

pub async fn preparer_rechiffreur<M>(_middleware: &M, handler_rechiffrage: &SymmetricEncryptionHandler)
    -> Result<(), Error>
    where M: GenerateurMessages + ValidateurX509
{
    info!("preparer_rechiffreur Generer nouvelle cle symmetrique de rechiffrage");
    handler_rechiffrage.generer_cle_symmetrique()
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

// impl CleSynchronisation {
//     pub fn get_bson_filter<S>(cles: &Vec<S>) -> Result<Vec<Document>, Error>
//         where S: AsRef<Self>
//     {
//         // Extraire refs
//         let cles: Vec<&Self> = cles.iter().map(|c| c.as_ref()).collect();
//
//         let mut cles_mappees = Vec::new();
//         for cle in cles {
//             cles_mappees.push(cle.cle_id.as_str());
//         }
//
//         let filtre = doc!{"cle_id": {"$in": cles_mappees}};
//         Ok(vec![filtre])
//     }
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseSynchroniserCles {
    pub liste_cle_id: Vec<String>,
    pub done: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseConfirmerClesSurCa {
    pub ok: Option<bool>,
    // pub cles_manquantes: Vec<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CleSecreteRechiffrage {
    pub signature: SignatureDomaines,
    pub cle_secrete: String,
    pub format: Option<String>,
    pub header: Option<String>,
}

impl CleSecreteRechiffrage {

    pub fn get_cle_secrete(&self) -> Result<CleSecreteX25519, Error> {
        let cle_secrete: Vec<u8> = base64_nopad.decode(&self.cle_secrete)?;
        let mut cle_secrete_dechiffree = CleSecrete([0u8; 32]);
        cle_secrete_dechiffree.0.copy_from_slice(&cle_secrete[..]);
        Ok(cle_secrete_dechiffree)
    }

    /// Rechiffre la cle secrete dechiffree.
    pub fn rechiffrer_cle(&self, handler_rechiffrage: &SymmetricEncryptionHandler) -> Result<(String, CleInterneChiffree), Error> {
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
pub struct CommandeRechiffrerBatchChiffree {
    pub cles: EncryptedDocument
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeRechiffrerBatchDechiffree {
    pub cles: HashMap<String, CleSecreteRechiffrage>
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

#[derive(Clone, Deserialize)]
pub struct RowClePartitionRef<'a> {
    // Identite
    pub cle_id: &'a str,
    pub signature: SignatureDomainesRef<'a>,

    // Cle chiffree
    //pub cle_symmetrique: Option<&'a str>,
    //pub nonce_symmetrique: Option<&'a str>,

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
    serialize_with="epochseconds::serialize")] //,
    // deserialize_with="bson::serde_helpers::chrono_datetime_as_bson_datetime::deserialize")]
    #[allow(unused)]
    pub date_creation: DateTime<Utc>,
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

pub async fn effectuer_requete_cles_manquantes<M>(
    middleware: &M, requete_transfert: &RequeteTransfert)
    -> Result<Option<CommandeTransfertClesV2>, Error>
where M: GenerateurMessages
{
    let delai_blocking = match &requete_transfert.toujours_repondre {
        Some(true) => 3_000,  // Requete live, temps court
        _ => 20_000,  // Requete batch, temps long
    };

    let routage_evenement_manquant = RoutageMessageAction::builder(
        DOMAINE_NOM, REQUETE_TRANSFERT_CLES, vec![Securite::L3Protege])
        .timeout_blocking(delai_blocking)
        .build();

    let data_reponse: Option<CommandeTransfertClesV2> = match middleware.transmettre_requete(
        routage_evenement_manquant.clone(), &requete_transfert).await
    {
        Ok(inner) => match inner {
            Some(inner) => match inner {
                TypeMessage::Valide(inner) => {
                    debug!("synchroniser_cles Reponse demande cles manquantes\n{}", from_utf8(inner.message.buffer.as_slice())?);
                    let message_ref = inner.message.parse()?;
                    let enveloppe_privee = middleware.get_enveloppe_signature();
                    match message_ref.dechiffrer(enveloppe_privee.as_ref()) {
                        Ok(inner) => Some(inner),
                        Err(e) => {
                            warn!("synchroniser_cles Erreur dechiffrage reponse : {:?}", e);
                            None
                        }
                    }
                },
                _ => {
                    warn!("synchroniser_cles Erreur reception reponse cles manquantes, mauvais type reponse.");
                    None
                }
            },
            None => {
                warn!("synchroniser_cles Erreur reception reponse cles manquantes, resultat None");
                None
            }
        },
        Err(e) => {
            warn!("synchroniser_cles Erreur reception reponse cles manquantes (e.g. timeout) : {:?}", e);
            None
        },
    };
    Ok(data_reponse)
}
