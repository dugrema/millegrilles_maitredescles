use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::{Arc, Mutex};

use log::{debug, error, info, warn};
use millegrilles_common_rust::certificats::{EnveloppeCertificat, EnveloppePrivee, ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage::{chiffrer_asymetrique_multibase, CleChiffrageHandler, CleSecrete, FormatChiffrage, rechiffrer_asymetrique_multibase};
use millegrilles_common_rust::chiffrage_cle::{CleDechiffree, CommandeSauvegarderCle};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::{MessageMilleGrille, MessageReponseChiffree};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::Middleware;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tokio::{sync::mpsc::Sender, time::{Duration, sleep}};
use millegrilles_common_rust::certificats::ordered_map;
use millegrilles_common_rust::common_messages::{DataChiffre, ReponseSignatureCertificat};
use millegrilles_common_rust::{multibase, multibase::Base, serde_json};
use millegrilles_common_rust::chiffrage_ed25519::{chiffrer_asymmetrique_ed25519, dechiffrer_asymmetrique_ed25519};
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::dechiffrage::dechiffrer_data;
use millegrilles_common_rust::hachages::hacher_bytes;
use millegrilles_common_rust::multibase::Base::Base58Btc;
use millegrilles_common_rust::multihash::Code;
use millegrilles_common_rust::serde_json::json;
use crate::domaines_maitredescles::TypeGestionnaire;
use crate::maitredescles_partition::GestionnaireMaitreDesClesPartition;
use crate::maitredescles_sqlite::GestionnaireMaitreDesClesSQLite;
use crate::maitredescles_volatil::{CleInterneChiffree, HandlerCleRechiffrage};

pub const DOMAINE_NOM: &str = "MaitreDesCles";

pub const NOM_COLLECTION_CONFIGURATION: &str = "MaitreDesCles/configuration";

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
pub const COMMANDE_CLE_SYMMETRIQUE: &str = "cleSymmetrique";

pub const TRANSACTION_CLE: &str = "cle";

pub const CHAMP_CLE_SYMMETRIQUE: &str = "cle_symmetrique";
pub const CHAMP_NONCE_SYMMETRIQUE: &str = "nonce_symmetrique";

// pub const EVENEMENT_RESET_CLES_NON_DECHIFFRABLES: &str = "resetClesNonDechiffrables";
pub const EVENEMENT_CLES_MANQUANTES_PARTITION: &str = "clesManquantesPartition";
pub const EVENEMENT_CLE_RECUE_PARTITION: &str = "cleRecuePartition";
pub const EVENEMENT_DEMANDE_CLE_SYMMETRIQUE: &str = "demandeCleSymmetrique";
pub const COMMANDE_VERIFIER_CLE_SYMMETRIQUE: &str = "verifierCleSymmetrique";

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
pub async fn emettre_certificat_maitredescles<M>(middleware: &M, m: Option<MessageValideAction>)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
{
    debug!("emettre_certificat_maitredescles");

    let reponse = json!({});

    match m {
        Some(demande) => {
            match demande.reply_q.as_ref() {
                Some(reply_q) => {
                    // On utilise une correlation fixe pour permettre au demandeur de recevoir les
                    // reponses de plusieurs partitions de maitre des cles en meme temps.
                    let routage = RoutageMessageReponse::new(
                        reply_q, COMMANDE_CERT_MAITREDESCLES);
                    let message_reponse = middleware.formatter_reponse(&reponse, None)?;
                    middleware.repondre(routage, message_reponse).await?;
                },
                None => {
                    debug!("Mauvais message recu pour emettre_certificat (pas de reply_q)");
                }
            }
        },
        None => {
            let routage = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_CERT_MAITREDESCLES)
                .exchanges(vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])
                .correlation_id(COMMANDE_CERT_MAITREDESCLES)
                .build();
            middleware.emettre_evenement(routage, &reponse).await?;
        }
    }

    Ok(())
}

/// Emettre les cles de l'instance locale pour s'assurer que tous les maitre des cles en ont une copie
pub async fn emettre_cles_symmetriques<M>(middleware: &M, rechiffreur: &HandlerCleRechiffrage)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + CleChiffrageHandler
{
    debug!("emettre_cles_symmetriques");

    let enveloppe_privee = middleware.get_enveloppe_signature();
    let enveloppes_publiques = middleware.get_publickeys_chiffrage();

    // Recuperer cles symmetriques chiffrees pour CA et tous les maitre des cles connus
    let cle_secrete_chiffree_ca = rechiffreur.get_cle_symmetrique_chiffree(&enveloppe_privee.enveloppe_ca.cle_publique)?;
    let mut cles = HashMap::new();
    for cle in enveloppes_publiques.into_iter() {
        let cle_rechiffree = rechiffreur.get_cle_symmetrique_chiffree(&cle.public_key)?;
        cles.insert(cle.fingerprint, cle_rechiffree);
    }

    let evenement = EvenementClesRechiffrage {
        cle_ca: cle_secrete_chiffree_ca,
        cles_dechiffrage: cles,
    };
    // let evenement = json!({
    //     "cle_ca": cle_secrete_chiffree_ca,
    //     "cles_dechiffrage": cles,
    // });

    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_CLES_RECHIFFRAGE)
        .exchanges(vec![Securite::L4Secure])
        .build();

    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(())
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

// pub async fn generer_certificat_volatil<M>(middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage)
//     -> Result<(), Box<dyn Error>>
//     where M: GenerateurMessages + ValidateurX509
// {
//     let idmg = middleware.get_enveloppe_signature().idmg()?;
//     let csr_volatil = handler_rechiffrage.generer_csr(idmg)?;
//     debug!("generer_certificat_volatil Demande de generer un certificat volatil, CSR : {:?}", csr_volatil);
//
//     let routage = RoutageMessageAction::builder(DOMAINE_PKI, "signerCsr")
//         .exchanges(vec![Securite::L3Protege])
//         // .timeout_blocking(20000)
//         .build();
//
//     let reponse: ReponseSignatureCertificat = match middleware.transmettre_commande(routage, &csr_volatil, true).await? {
//         Some(m) => match m {
//             TypeMessage::Valide(m) => m.message.parsed.map_contenu()?,
//             _ => Err(format!("maitredescles_commun.generer_certificat_volatil Mauvais type de reponse"))?
//         },
//         None => Err(format!("maitredescles_commun.generer_certificat_volatil Aucune reponse recue"))?
//     };
//
//     debug!("generer_certificat_volatil Reponse {:?}", reponse);
//     if Some(true) == reponse.ok {
//         match reponse.certificat {
//             Some(vec_certificat_pem) => {
//                 let enveloppe_ca = middleware.get_enveloppe_signature().enveloppe_ca.clone();
//                 let ca_pem = enveloppe_ca.get_pem_vec().get(0).expect("CA").pem.clone();
//                 let enveloppe = middleware.charger_enveloppe(&vec_certificat_pem, None, Some(ca_pem.as_str())).await?;
//                 handler_rechiffrage.set_certificat(enveloppe, enveloppe_ca)?;
//
//                 // Certificat pret
//                 Ok(())
//             },
//             None => Err(format!("maitredescles_commun.generer_certificat_volatil Erreur creation certificat volatil cote serveur, aucun certificat recu"))?
//         }
//     } else {
//         Err(format!("maitredescles_commun.generer_certificat_volatil Erreur creation certificat volatil cote serveur (certissuer ok == false)"))?
//     }
// }

pub async fn preparer_rechiffreur<M>(middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage)
    -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + ValidateurX509
{
    info!("preparer_rechiffreur Generer nouvelle cle symmetrique de rechiffrage");
    handler_rechiffrage.generer_cle_symmetrique()
}

pub async fn traiter_cedule<M>(_middleware: &M, _trigger: &MessageCedule) -> Result<(), Box<dyn Error>>
where M: Middleware + 'static {
    // let message = trigger.message;

    debug!("Traiter cedule {}", DOMAINE_NOM);

    Ok(())
}

/// Emettre evenement de cles inconnues suite a une requete. Permet de faire la difference entre
/// les cles de la requete et les cles connues.
// pub async fn emettre_cles_inconnues<M>(middleware: &M, requete: &RequeteDechiffrage, cles_connues: Vec<String>)
//     -> Result<(), Box<dyn Error>>
//     where M: GenerateurMessages
// {
//     // Faire une demande interne de sync pour voir si les cles inconnues existent (async)
//     let routage_evenement_manquant = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_CLES_MANQUANTES_PARTITION)
//         .exchanges(vec![Securite::L4Secure])
//         .build();
//
//     let mut set_cles = HashSet::new();
//     set_cles.extend(requete.liste_hachage_bytes.iter());
//     let mut set_cles_trouvees = HashSet::new();
//     set_cles_trouvees.extend(&cles_connues);
//     let set_diff = set_cles.difference(&set_cles_trouvees);
//     let liste_cles: Vec<String> = set_diff.into_iter().map(|m| m.to_string()).collect();
//     debug!("emettre_cles_inconnues Requete de cles inconnues : {:?}", liste_cles);
//
//     let evenement_cles_manquantes = ReponseSynchroniserCles { liste_hachage_bytes: liste_cles };
//
//     Ok(middleware.emettre_evenement(routage_evenement_manquant.clone(), &evenement_cles_manquantes).await?)
// }

/// Emettre evenement de cles inconnues suite a une requete. Permet de faire la difference entre
/// les cles de la requete et les cles connues.
pub async fn requete_cles_inconnues<M>(middleware: &M, requete: &RequeteDechiffrage, cles_connues: Vec<String>)
    -> Result<MessageListeCles, Box<dyn Error>>
    where M: GenerateurMessages + CleChiffrageHandler
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
    debug!("maitredescles_commun.requete_cles_inconnues Requete de cles inconnues : {:?}", liste_cles);

    let evenement_cles_manquantes = ReponseSynchroniserCles { liste_hachage_bytes: liste_cles };

    let reponse = match middleware.transmettre_requete(routage_evenement_manquant.clone(), &evenement_cles_manquantes).await? {
        TypeMessage::Valide(m) => {
            debug!("maitredescles_commun.requete_cles_inconnues Reponse recue {:?}", m);
            match MessageReponseChiffree::try_from(m.message.parsed) {
                Ok(inner) => {
                    let message_dechiffre = inner.dechiffrer(middleware)?;
                    let reponse: MessageListeCles = serde_json::from_slice(&message_dechiffre.data_dechiffre[..])?;
                    reponse
                },
                Err(e) => {
                    Err(format!("maitredescles_commun.requete_cles_inconnues synchroniser_cles Erreur dechiffrage reponse : {:?}", e))?
                }
            }
        },
        _ => Err(format!("maitredescles_commun.requete_cles_inconnues Erreur reponse pour requete cle manquante, mauvais type de reponse"))?
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
pub struct CleSecreteRechiffrage {
    #[serde(rename="cleSecrete")]
    pub cle_secrete: String,
    pub domaine: String,
    pub format: String,
    pub hachage_bytes: String,
    pub header: String,
    pub identificateurs_document: HashMap<String, String>,
    // pub signature_identite: String,
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

impl TryInto<DocumentClePartition> for CleSecreteRechiffrage {
    type Error = String;

    fn try_into(self) -> Result<DocumentClePartition, Self::Error> {
        Ok(DocumentClePartition {
            cle_ref: self.hachage_bytes.clone(),
            hachage_bytes: self.hachage_bytes,
            domaine: self.domaine,
            identificateurs_document: self.identificateurs_document,
            // signature_identite: self.signature_identite,
            cle: "".to_string(),
            cle_symmetrique: None,
            nonce_symmetrique: None,
            format: self.format.as_str().try_into()?,
            iv: None,
            tag: None,
            header: Some(self.header),
        })
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

        Ok(Self {
            cle_secrete: "".to_string(),
            domaine: value.domaine,
            format: format.to_string(),
            hachage_bytes: value.hachage_bytes,
            header,
            identificateurs_document: value.identificateurs_document,
            // signature_identite: value.signature_identite,
        })
    }
}

impl CleSecreteRechiffrage {

    // fn try_from(value: CommandeSauvegarderCle) -> Result<Self, Self::Error> {
    pub fn from_commande(cle_secrete: &CleSecrete, value: CommandeSauvegarderCle) -> Result<Self, Box<dyn Error>> {
        let header = match value.header {
            Some(inner) => inner,
            None => Err(format!("TryFrom<CommandeSauvegarderCle> Header manquant"))?
        };
        let cle_secrete_string: String = multibase::encode(Base::Base64, &cle_secrete.0);
        let format: &str = value.format.into();
        Ok(Self {
            cle_secrete: cle_secrete_string,
            domaine: value.domaine,
            format: format.to_string(),
            hachage_bytes: value.hachage_bytes,
            header,
            identificateurs_document: value.identificateurs_document,
            // signature_identite: value.signature_identite,
        })
    }

    pub fn from_doc_cle(cle_secrete: CleSecrete, value: DocumentClePartition) -> Result<Self, Box<dyn Error>> {
        let header = match value.header {
            Some(inner) => inner,
            None => Err(format!("TryFrom<CommandeSauvegarderCle> Header manquant"))?
        };
        let cle_secrete_string: String = multibase::encode(Base::Base64, &cle_secrete.0);
        let format: &str = value.format.into();
        Ok(Self {
            cle_secrete: cle_secrete_string,
            domaine: value.domaine,
            format: format.to_string(),
            hachage_bytes: value.hachage_bytes,
            header,
            identificateurs_document: value.identificateurs_document,
            // signature_identite: value.signature_identite,
        })
    }

    pub fn get_cle_secrete(&self) -> Result<CleSecrete, Box<dyn Error>> {
        let cle_secrete: Vec<u8> = multibase::decode(&self.cle_secrete)?.1;
        let mut cle_secrete_dechiffree = CleSecrete([0u8; 32]);
        cle_secrete_dechiffree.0.copy_from_slice(&cle_secrete[..]);
        Ok(cle_secrete_dechiffree)
    }

    // fn verifier_identite(&self, cle: &CleSecrete) -> Result<(), Box<dyn Error>>{
    //     let identite_cle: IdentiteCle = self.clone().into();
    //     if identite_cle.verifier(cle)? != true {
    //         warn!("maitredescles_common.CleSecreteRechiffrage Erreur verifier identite commande, signature invalide pour cle {}", self.hachage_bytes);
    //         Err(format!("maitredescles_commun.CleSecreteRechiffrage Identite cle mismatch"))?
    //     }
    //     Ok(())
    // }

    pub fn get_cle_ref(&self) -> Result<String, Box<dyn Error>> {
        let cle_secrete = self.get_cle_secrete()?;
        let cle_info = CleRefData::from(self);
        Ok(calculer_cle_ref(cle_info, &cle_secrete)?)
    }

    /// Rechiffre la cle secrete dechiffree.
    pub fn rechiffrer_cle(&self, handler_rechiffrage: &HandlerCleRechiffrage) -> Result<(String, CleInterneChiffree), Box<dyn Error>> {
        let cle_secrete = self.get_cle_secrete()?;

        // // Verifier identite. Lance exception si invalide.
        // self.verifier_identite(&cle_secrete)?;

        // Calculer cle_ref
        let cle_info = CleRefData::from(self);
        let cle_ref = calculer_cle_ref(cle_info, &cle_secrete)?;

        // Rechiffrer cle
        let cle_rechiffree = handler_rechiffrage.chiffrer_cle_secrete(&cle_secrete.0[..])?;

        Ok((cle_ref, cle_rechiffree))
    }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeRechiffrerBatch {
    pub cles: Vec<CleSecreteRechiffrage>
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
    // pub signature_identite: String,

    // Cle chiffree
    pub cle: String,

    // Dechiffrage contenu
    pub format: FormatChiffrage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
}

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
            // signature_identite: commande.signature_identite.clone(),
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
            // signature_identite: self.signature_identite,
            cles,
            format: self.format,
            iv: self.iv,
            tag: self.tag,
            header: self.header,
            partition: self.partition,
            fingerprint_partitions: None
        }
    }

    // pub fn verifier_identite(&self, cle_secrete: &CleSecrete) -> Result<bool, String> {
    //     let identite: IdentiteCle = self.clone().into();
    //     Ok(identite.verifier(cle_secrete)?)
    // }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentClePartition {
    // Identite
    pub cle_ref: String,
    pub hachage_bytes: String,
    pub domaine: String,
    pub identificateurs_document: HashMap<String, String>,
    // pub signature_identite: String,

    // Cle chiffree
    pub cle: String,

    pub cle_symmetrique: Option<String>,
    pub nonce_symmetrique: Option<String>,

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
            // signature_identite: value.signature_identite,
            cle: "".to_string(),
            cle_symmetrique: None,
            nonce_symmetrique: None,
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
            // signature_identite: self.signature_identite,
            cles,
            format: self.format,
            iv: self.iv,
            tag: self.tag,
            header: self.header,
            partition: Some(fingerprint_),
            fingerprint_partitions: None
        }
    }

    pub fn try_into_document_cle_partition<S,T>(value: &DocCleSymmetrique, fingerprint: S, cle_ref: T) -> Result<DocumentClePartition, String>
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

impl From<DocumentClePartition> for DocCleSymmetrique {
    fn from(value: DocumentClePartition) -> Self {
        Self {
            hachage_bytes: value.hachage_bytes,
            domaine: value.domaine,
            identificateurs_document: value.identificateurs_document,
            // signature_identite: value.signature_identite,
            // cles: HashMap::new(),
            cle_symmetrique: value.cle_symmetrique,
            nonce_symmetrique: value.nonce_symmetrique,
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
        Self {
            hachage_bytes: value.hachage_bytes.as_str(),
            iv: None,
            tag: None,
            header: Some(value.header.as_str()),
            domaine: value.domaine.as_str(),
        }
    }
}

/// Calcule la cle_ref a partir du hachage et cle_secret d'une cle recue (commande/transaction)
pub fn calculer_cle_ref(info: CleRefData, cle_secrete: &CleSecrete) -> Result<String, String>
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

/// Rechiffre une cle secrete
// pub fn rechiffrer_cle(cle: &mut DocumentClePartition, privee: &EnveloppePrivee, certificat_destination: &EnveloppeCertificat)
pub fn rechiffrer_cle(cle: &mut DocumentClePartition, handler_rechiffrage: &HandlerCleRechiffrage, certificat_destination: &EnveloppeCertificat)
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

    let cle_interne = CleInterneChiffree::try_from(cle.clone())?;
    let cle_secrete = handler_rechiffrage.dechiffer_cle_secrete(cle_interne)?;

    // let cle_originale = cle.cle.as_str();
    // let cle_privee = privee.cle_privee();
    let cle_publique = certificat_destination.certificat().public_key()?;
    // let cle_rechiffree = rechiffrer_asymetrique_multibase(cle_privee, &cle_publique, cle_originale)?;
    let cle_rechiffree = chiffrer_asymetrique_multibase(cle_secrete, &cle_publique)?;

    debug!("rechiffrer_cle Cle {} rechiffree : {}", cle.hachage_bytes, cle_rechiffree);

    // Remplacer cle dans message reponse
    cle.cle = cle_rechiffree;

    Ok(())
}

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
pub async fn emettre_demande_cle_symmetrique<M,S>(middleware: &M, cle_ca: S) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages, S: AsRef<str>
{
    let cle_privee = middleware.get_enveloppe_signature();
    let instance_id = cle_privee.enveloppe.get_common_name()?;

    debug!("emettre_demande_cle_symmetrique Demander la cle symmetrique pour instance_id : {}", instance_id);

    let evenement = json!({
        "cle_symmetrique_ca": cle_ca.as_ref(),
    });

    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM, EVENEMENT_DEMANDE_CLE_SYMMETRIQUE)
        .exchanges(vec![Securite::L3Protege])
        .correlation_id(EVENEMENT_DEMANDE_CLE_SYMMETRIQUE)
        .build();

    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(())
}

#[derive(Clone, Deserialize)]
pub struct MessageListeCles {
    pub cles: Vec<CleSecreteRechiffrage>
}

/// Genere une commande de sauvegarde de cles pour tous les certificats maitre des cles connus
/// incluant le certificat de millegrille
pub fn rechiffrer_pour_maitredescles_ca<M>(middleware: &M, handler: &HandlerCleRechiffrage, cle: DocumentClePartition)
    -> Result<CommandeSauvegarderCle, Box<dyn Error>>
    where M: GenerateurMessages + CleChiffrageHandler
{
    let enveloppe_privee = middleware.get_enveloppe_signature();
    // let fingerprint_local = enveloppe_privee.fingerprint().as_str();
    // let pk_chiffrage = middleware.get_publickeys_chiffrage();
    // let cle_locale = cle.cle.to_owned();
    // let cle_privee = enveloppe_privee.cle_privee();
    //
    // let mut fingerprint_partitions = Vec::new();

    // Convertir la commande
    // let mut commande_transfert = DocCleSymmetrique::from(cle);
    let mut commande_transfert = cle.clone().into_commande("");
    commande_transfert.cles = HashMap::new();

    // Ajouter cle rechiffree pour CA
    {
        let cle_interne = CleInterneChiffree::try_from(cle.clone())?;
        let cle_secrete = handler.dechiffer_cle_secrete(cle_interne)?;
        let cle_publique_ca = &enveloppe_privee.enveloppe_ca.cle_publique;

        let cle_rechiffree = chiffrer_asymmetrique_ed25519(&cle_secrete.0[..], cle_publique_ca)?;
        let cle_ca_str = multibase::encode(Base::Base64, cle_rechiffree);
        let cle_ca_fingerprint = enveloppe_privee.enveloppe_ca.fingerprint.as_str();
        commande_transfert.cles.insert(cle_ca_fingerprint.to_owned(), cle_ca_str);
    };

    // Cles rechiffrees
    // for pk_item in pk_chiffrage {
    //     let fp = pk_item.fingerprint;
    //     let pk = pk_item.public_key;
    //
    //     // Conserver liste des partitions
    //     if ! pk_item.est_cle_millegrille {
    //         fingerprint_partitions.push(fp.clone());
    //     }
    //
    //     // Rechiffrer cle
    //     if fp.as_str() != fingerprint_local {
    //         // match chiffrer_asymetrique(&pk, &cle_secrete) {
    //         match rechiffrer_asymetrique_multibase(cle_privee, &pk, cle_locale.as_str()) {
    //             Ok(cle_rechiffree) => {
    //                 // let cle_mb = multibase::encode(Base::Base64, cle_rechiffree);
    //                 map_cles.insert(fp, cle_rechiffree);
    //             },
    //             Err(e) => error!("Erreur rechiffrage cle : {:?}", e)
    //         }
    //     }
    // }

    Ok(commande_transfert)
}

// /// Dechiffre le message kind:8 d'une batch
// pub fn dechiffrer_batch<M>(middleware: &M, m: MessageValideAction) -> Result<CommandeRechiffrerBatch, Box<dyn Error>>
// pub fn dechiffrer_batch<M>(middleware: &M, m: MessageValideAction) -> Result<CommandeRechiffrerBatch, Box<dyn Error>>
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
