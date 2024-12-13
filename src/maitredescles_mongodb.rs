use crate::ca_manager::MaitreDesClesCaManager;
use crate::constants::*;
use crate::maitredescles_commun::{effectuer_requete_cles_manquantes, emettre_demande_cle_symmetrique, preparer_rechiffreur, verifier_permission_rechiffrage, CleSecreteRechiffrage, CleSynchronisation, CleTransfert, CleTransfertCa, CommandeCleSymmetrique, CommandeRechiffrerBatch, CommandeRechiffrerBatchChiffree, CommandeRechiffrerBatchDechiffree, CommandeRotationCertificat, CommandeTransfertClesCaV2, CommandeTransfertClesV2, DocumentCleRechiffrage, ErreurPermissionRechiffrage, EvenementClesRechiffrage, ReponseConfirmerClesSurCa, ReponseSynchroniserCles, RequeteSynchroniserCles, RequeteTransfert, RowCleCaRef, RowClePartition, RowClePartitionRef, TransactionCle, TransactionCleV2};
use crate::maitredescles_rechiffrage::HandlerCleRechiffrage;
use crate::messages::{RecupererCleCa, RequeteClesNonDechiffrable};
use crate::mongodb_manager::MaitreDesClesMongoDbManager;
use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::base64::{engine::general_purpose::STANDARD_NO_PAD as base64_nopad, Engine as _};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chiffrage_cle::CommandeAjouterCleDomaine;
use millegrilles_common_rust::chrono::{DateTime, Duration, Utc};
use millegrilles_common_rust::common_messages::{ReponseRequeteDechiffrageV2, RequeteDechiffrage, ResponseRequestDechiffrageV2Cle};
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{RolesCertificats, Securite, CHAMP_CREATION, CHAMP_MODIFICATION, COMMANDE_TRANSFERT_CLE, COMMANDE_TRANSFERT_CLE_CA};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, GestionnaireDomaineV2};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::jwt_simple::prelude::Serialize;
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction_serializable_v2;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::{SignatureDomaines, SignatureDomainesVersion};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::optionepochseconds;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::millegrilles_cryptographie::x25519::{dechiffrer_asymmetrique_ed25519, CleSecreteX25519};
use millegrilles_common_rust::millegrilles_cryptographie::{deser_message_buffer, heapless};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, start_transaction_regular, verifier_erreur_duplication_mongo, ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::mongodb::options::{CountOptions, FindOneOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::{millegrilles_cryptographie, multibase, serde_json};
use std::collections::HashSet;
use std::str::from_utf8;
use millegrilles_common_rust::dechiffrage::decrypt_document;
use millegrilles_common_rust::mongodb::ClientSession;

pub const NOM_COLLECTION_TRANSACTIONS: &str = DOMAINE_NOM;
pub const NOM_COLLECTION_TRANSACTIONS_CA: &str = "MaitreDesCles/CA";
pub const NOM_COLLECTION_CA_CLES: &str = "MaitreDesCles/CA/cles";
pub const NOM_COLLECTION_SYMMETRIQUE_CLES: &str = "MaitreDesCles/cles";

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

pub async fn preparer_index_mongodb_partition<M>(middleware: &M) -> Result<(), Error>
where M: MongoDao + ConfigMessages
{
    let collection_cles = NOM_COLLECTION_SYMMETRIQUE_CLES;

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
        collection_cles,
        champs_index_confirmation_ca,
        Some(options_confirmation_ca)
    ).await?;

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

pub async fn preparer_rechiffreur_mongo<M>(middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage)
    -> Result<(), Error>
    where M: GenerateurMessages + ValidateurX509 + MongoDao
{
    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;
    let result = preparer_rechiffreur_mongo_session(middleware, handler_rechiffrage, &mut session).await;
    match result {
        Ok(()) => {
            session.commit_transaction().await?;
            Ok(())
        },
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)
        }
    }
}

async fn preparer_rechiffreur_mongo_session<M>(middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage, session: &mut ClientSession)
    -> Result<(), Error>
    where M: GenerateurMessages + ValidateurX509 + MongoDao
{

    let enveloppe_privee = middleware.get_enveloppe_signature();
    let instance_id = enveloppe_privee.enveloppe_pub.get_common_name()?;

    // Verifier si les cles de dechiffrage existent deja.
    let collection = middleware.get_collection(NOM_COLLECTION_CONFIGURATION)?;
    let filtre = doc!{"type": "CA", "instance_id": instance_id.as_str()};
    match collection.find_one_with_session(filtre, None, session).await? {
        Some(doc_cle_ca) => {
            info!("preparer_rechiffreur_mongo Cle de rechiffrage CA est presente");

            let filtre = doc!{
                "type": "local",
                "instance_id": instance_id.as_str(),
                "fingerprint": enveloppe_privee.fingerprint()?,
            };

            match collection.find_one_with_session(filtre, None, session).await? {
                Some(doc_cle_locale) => {
                    let cle_locale: DocumentCleRechiffrage = convertir_bson_deserializable(doc_cle_locale)?;
                    handler_rechiffrage.set_cle_symmetrique(cle_locale.cle)?;
                    info!("preparer_rechiffreur_mongo Cle de rechiffrage locale est chargee");
                },
                None => {
                    let cle_ca: DocumentCleRechiffrage = convertir_bson_deserializable(doc_cle_ca)?;

                    info!("preparer_rechiffreur_mongo Demander la cle de rechiffrage");
                    emettre_demande_cle_symmetrique(middleware, cle_ca.cle).await?;
                    Err(format!("preparer_rechiffreur_mongo Attente cle de rechiffrage"))?;
                }
            }

        },
        None => {
            // Initialiser la base de donnees
            info!("preparer_rechiffreur_mongo Initiliser cle de rechiffrage");

            preparer_rechiffreur(middleware, handler_rechiffrage).await?;

            // Conserver la cle de rechiffrage
            let cle_secrete_chiffree_ca = handler_rechiffrage.get_cle_symmetrique_chiffree(&enveloppe_privee.enveloppe_ca.certificat.public_key()?)?;
            let cle_secrete_chiffree_local = handler_rechiffrage.get_cle_symmetrique_chiffree(&enveloppe_privee.enveloppe_pub.certificat.public_key()?)?;
            debug!("Cle secrete chiffree pour instance {} :\nCA = {}\n local = {}", instance_id, cle_secrete_chiffree_ca, cle_secrete_chiffree_local);

            let cle_ca = doc! {
                "type": "CA",
                "instance_id": instance_id.as_str(),
                "cle": cle_secrete_chiffree_ca,
            };
            collection.insert_one_with_session(cle_ca, None, session).await?;

            let cle_locale = doc! {
                "type": "local",
                "instance_id": instance_id.as_str(),
                "fingerprint": enveloppe_privee.fingerprint()?,
                "cle": cle_secrete_chiffree_local,
            };
            collection.insert_one_with_session(cle_locale, None, session).await?;
        }
    }

    Ok(())
}

pub async fn synchroniser_cles<M>(middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage) -> Result<(), Error>
where M: GenerateurMessages + MongoDao +  CleChiffrageHandler
{
    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;
    let result = synchroniser_cles_session(middleware, handler_rechiffrage, &mut session).await;
    match result {
        Ok(()) => {
            session.commit_transaction().await?;
            Ok(())
        }
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)
        }
    }
}

async fn synchroniser_cles_session<M>(middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage, session: &mut ClientSession) -> Result<(), Error>
where M: GenerateurMessages + MongoDao +  CleChiffrageHandler
{
    debug!("synchroniser_cles Debut");
    if ! handler_rechiffrage.is_ready() {
        Err(format!("maitredescles_partition.synchroniser_cles Rechiffreur n'est pas initialise"))?
    }

    // Requete vers CA pour obtenir la liste des cles connues
    let mut requete_sync = RequeteSynchroniserCles {page: 0, limite: 1000};
    let routage_sync = RoutageMessageAction::builder(DOMAINE_NOM, REQUETE_SYNCHRONISER_CLES, vec![Securite::L4Secure])
        .build();

    loop {
        let reponse: ReponseSynchroniserCles = match middleware.transmettre_requete(routage_sync.clone(), &requete_sync).await? {
            Some(inner) => match inner {
                TypeMessage::Valide(reponse) => deser_message_buffer!(reponse.message),
                _ => {
                    warn!("synchroniser_cles Mauvais type de reponse recu, on abort");
                    break
                }
            },
            None => {
                warn!("synchroniser_cles Aucune reponse recue, on abort");
                break
            }
        };
        requete_sync.page += 1;  // Incrementer page pour prochaine requete

        if reponse.liste_cle_id.len() == 0 {
            debug!("Traitement sync termine");
            break
        }

        if let Err(e) = traiter_batch_synchroniser_cles(middleware, handler_rechiffrage, reponse, session).await {
            error!("synchroniser_cles Erreur traitement batch cles : {:?}", e);
        }
    }

    debug!("synchroniser_cles Fin");

    Ok(())
}

async fn traiter_batch_synchroniser_cles<M>(middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage, reponse: ReponseSynchroniserCles, session: &mut ClientSession)
                                            -> Result<(), Error>
where M: MongoDao + GenerateurMessages
{
    let liste_cles = reponse.liste_cle_id;

    let mut cles_hashset = HashSet::new();
    for item in &liste_cles {
        cles_hashset.insert(item.as_str());
    }

    debug!("traiter_batch_synchroniser_cles Recu liste_hachage_bytes a verifier : {} cles", liste_cles.len());
    let filtre_cles = doc! {"cle_id": { "$in": &liste_cles } };
    let projection = doc! { CHAMP_CLE_ID: 1 };
    let find_options = FindOptions::builder().projection(projection).build();

    let nom_collection = NOM_COLLECTION_SYMMETRIQUE_CLES;

    let collection = middleware.get_collection_typed::<CleSynchronisation>(nom_collection)?;
    let mut cles = collection.find_with_session(filtre_cles, Some(find_options), session).await?;
    while let Some(row) = cles.next(session).await {
        match row {
            Ok(inner) => {
                cles_hashset.remove(inner.cle_id.as_str());
            },
            Err(e) => {
                info!("traiter_batch_synchroniser_cles Erreur mapping cle : {:?}", e);
                continue
            }
        }
    }

    if cles_hashset.len() > 0 {
        debug!("traiter_batch_synchroniser_cles Cles absentes localement : {} cles", cles_hashset.len());

        let enveloppe_signature = middleware.get_enveloppe_signature();
        let fingerprint = enveloppe_signature.fingerprint()?;

        // Emettre requete pour indiquer que ces cles sont manquantes dans la partition
        let liste_cles: Vec<String> = cles_hashset.iter().map(|m| m.to_string()).collect();
        let requete_transfert = RequeteTransfert {
            fingerprint,
            cle_ids: liste_cles,
            toujours_repondre: Some(false),
        };

        let data_reponse = effectuer_requete_cles_manquantes(
            middleware, &requete_transfert).await.unwrap_or_else(|e| {
            error!("traiter_batch_synchroniser_cles Erreur requete cles manquantes : {:?}", e);
            None
        });

        if let Some(data_reponse) = data_reponse {
            debug!("traiter_batch_synchroniser_cles Recu {} cles suite a la requete de cles manquantes", data_reponse.cles.len());
            for cle in data_reponse.cles {
                sauvegarder_cle_transfert(middleware, handler_rechiffrage, &cle, session).await?;
            }
        }

        if cles_hashset.len() > 0 {
            info!("traiter_batch_synchroniser_cles Il reste {} cles non dechiffrables", cles_hashset.len());
        }
    }

    Ok(())
}

pub async fn sauvegarder_cle_transfert<M>(
    middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage, cle: &CleTransfert, session: &mut ClientSession)
    -> Result<(), Error>
where M: MongoDao
{
    let cle_id = cle.signature.get_cle_ref()?;
    match cle.signature.version {
        SignatureDomainesVersion::NonSigne => {
            // Obsolete, ancienne methode avec header/format
            let nom_collection_cles = NOM_COLLECTION_SYMMETRIQUE_CLES;

            let format: Option<String> = match cle.format.clone() {
                Some(inner) => {
                    let format_str: &str = inner.into();
                    Some(format_str.to_string())
                },
                None => None
            };

            let header = match cle.nonce.clone() {
                Some(inner) => Some(format!("m{}", inner)),  // Ajouter 'm' multibase,
                None => None
            };

            let cle_secrete_rechiffrage = CleSecreteRechiffrage {
                signature: cle.signature.clone(),
                cle_secrete: cle.cle_secrete_base64.clone(),
                format,
                header,
            };

            if let Err(e) = sauvegarder_cle_rechiffrage(middleware, handler_rechiffrage, nom_collection_cles, cle_secrete_rechiffrage, session).await {
                error!("traiter_batch_synchroniser_cles Erreur sauvegarde cle {} : {:?}", cle_id, e);
            }
        }
        _ => {
            // Methode courante
            let mut cle_secrete_bytes = [0u8; 32];
            cle_secrete_bytes.copy_from_slice(&base64_nopad.decode(cle.cle_secrete_base64.as_str())?[0..32]);
            let cle_secrete = CleSecreteX25519 { 0: cle_secrete_bytes };
            if let Err(e) = sauvegarder_cle_secrete(middleware, handler_rechiffrage, cle.signature.clone(), &cle_secrete, session).await {
                error!("traiter_batch_synchroniser_cles Erreur sauvegarde cle {} : {:?}", cle_id, e);
            }
        }
    }
    Ok(())
}

pub async fn sauvegarder_cle_rechiffrage<M>(middleware: &M,
                                        handler_rechiffrage: &HandlerCleRechiffrage,
                                        nom_collection_cles: &str,
                                        cle: CleSecreteRechiffrage, session: &mut ClientSession)
                                        -> Result<String, Error>
where M: MongoDao
{
    let collection = middleware.get_collection(nom_collection_cles)?;
    let (cle_id, cle_rechiffree) = cle.rechiffrer_cle(handler_rechiffrage)?;

    let filtre = doc!{CHAMP_CLE_ID: &cle_id};
    let mut set_on_insert = doc!{
        "dirty": true,
        "confirmation_ca": false,
        CHAMP_CREATION: Utc::now(),
        // CHAMP_CLE_ID: &cle_id,
        CHAMP_CLE_SYMMETRIQUE: cle_rechiffree.cle,
        CHAMP_NONCE_SYMMETRIQUE: cle_rechiffree.nonce,
        "signature": convertir_to_bson(&cle.signature)?,
    };

    // Supporter l'ancienne version de cles
    match cle.signature.version {
        SignatureDomainesVersion::NonSigne => {
            // set_on_insert.insert(CHAMP_HACHAGE_BYTES, cle.signature.signature.as_str());
            set_on_insert.insert("format", cle.format.as_ref());
            set_on_insert.insert("header", cle.header.as_ref());
        },
        _ => ()
    }

    let ops = doc! {
        "$setOnInsert": set_on_insert,
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let opts = UpdateOptions::builder().upsert(true).build();
    collection.update_one_with_session(filtre, ops, opts, session).await?;

    Ok(cle_id)
}

pub async fn sauvegarder_cle_secrete<M>(
    middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage,
    signature: SignatureDomaines, cle_secrete: &CleSecreteX25519, session: &mut ClientSession
)
    -> Result<(), Error>
where M: MongoDao
{
    // Rechiffrer avec le handler de rechiffrage
    let cle_rechiffree = handler_rechiffrage.chiffrer_cle_secrete(&cle_secrete.0)?;

    let nom_collection_cles = NOM_COLLECTION_SYMMETRIQUE_CLES;
    let collection = middleware.get_collection(nom_collection_cles)?;

    let cle_id = signature.get_cle_ref()?;

    let filtre = doc! {"cle_id": cle_id.as_str()};
    let set_on_insert_ops = doc! {
        "cle_id": cle_id.as_str(),
        "signature": convertir_to_bson(signature)?,
        "cle_symmetrique": cle_rechiffree.cle,
        "nonce_symmetrique": cle_rechiffree.nonce,
        CHAMP_CREATION: Utc::now(),
        "dirty": true,
        "confirmation_ca": false,
    };
    let ops = doc! {
        "$setOnInsert": set_on_insert_ops,
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let options = UpdateOptions::builder().upsert(true).build();
    collection.update_one_with_session(filtre, ops, options, session).await?;
    Ok(())
}

pub async fn confirmer_cles_ca<M>(middleware: &M, reset_flag: Option<bool>) -> Result<(), Error>
where M: GenerateurMessages + MongoDao +  CleChiffrageHandler
{
    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;
    let result = confirmer_cles_ca_session(middleware, reset_flag, &mut session).await;
    match result {
        Ok(()) => {
            session.commit_transaction().await?;
            Ok(())
        }
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)
        }
    }
}

/// S'assurer que le CA a toutes les cles de la partition. Permet aussi de resetter le flag non-dechiffrable.
async fn confirmer_cles_ca_session<M>(middleware: &M, reset_flag: Option<bool>, session: &mut ClientSession) -> Result<(), Error>
where M: GenerateurMessages + MongoDao +  CleChiffrageHandler
{
    let batch_size = 200;
    let nom_collection = NOM_COLLECTION_SYMMETRIQUE_CLES;

    debug!("confirmer_cles_ca Debut confirmation cles locales avec confirmation_ca=false (reset flag: {:?}", reset_flag);
    if let Some(true) = reset_flag {
        info!("Reset flag confirmation_ca a false");
        let filtre = doc! { CHAMP_CONFIRMATION_CA: true };
        let ops = doc! { "$set": {CHAMP_CONFIRMATION_CA: false } };
        let collection = middleware.get_collection(nom_collection)?;
        collection.update_many_with_session(filtre, ops, None, session).await?;
    }

    let mut curseur = {
        // let limit_cles = 1000000;
        let filtre = doc! { CHAMP_CONFIRMATION_CA: false };
        let opts = FindOptions::builder()
            // .limit(limit_cles)
            .build();
        let collection = middleware.get_collection(nom_collection)?;
        let curseur = collection.find_with_session(filtre, opts, session).await?;
        curseur
    };

    let mut cles = Vec::new();
    while let Some(d) = curseur.next(session).await {
        match d {
            Ok(cle) => {
                let cle_synchronisation: CleSynchronisation = convertir_bson_deserializable(cle)?;
                cles.push(cle_synchronisation.cle_id);

                if cles.len() == batch_size {
                    emettre_cles_vers_ca(middleware, &cles, session).await?;
                    cles.clear();  // Retirer toutes les cles pour prochaine page
                }
            },
            Err(e) => Err(format!("maitredescles_partition.confirmer_cles_ca Erreur traitement {:?}", e))?
        };
    }

    // Derniere batch de cles
    if cles.len() > 0 {
        emettre_cles_vers_ca(middleware, &cles, session).await?;
        cles.clear();
    }

    debug!("confirmer_cles_ca Fin confirmation cles locales");

    Ok(())
}

/// Emet un message vers CA pour verifier quels cles sont manquantes (sur le CA)
/// Marque les cles presentes sur la partition et CA comme confirmation_ca=true
/// Rechiffre et emet vers le CA les cles manquantes
async fn emettre_cles_vers_ca<M>(
    middleware: &M, liste_cles: &Vec<String>, session: &mut ClientSession)
    -> Result<(), Error>
where M: GenerateurMessages + MongoDao +  CleChiffrageHandler
{
    // let hachage_bytes: Vec<String> = cles.keys().into_iter().map(|h| h.to_owned()).collect();
    // let liste_cles: Vec<CleSynchronisation> = cles.into_iter().map(|h| {
    //     CleSynchronisation { hachage_bytes: h.hachage_bytes.clone(), domaine: h.domaine.clone() }
    // }).collect();
    debug!("emettre_cles_vers_ca Batch {:?} cles", liste_cles.len());

    let commande = ReponseSynchroniserCles { liste_cle_id: liste_cles.clone() };
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_CONFIRMER_CLES_SUR_CA, vec![Securite::L4Secure])
        .build();
    let option_reponse = middleware.transmettre_commande(routage, &commande).await?;
    match option_reponse {
        Some(r) => {
            match r {
                TypeMessage::Valide(reponse) => {
                    debug!("emettre_cles_vers_ca Reponse confirmer cle sur CA : {:?}", reponse.type_message);
                    let reponse_cles_manquantes: ReponseConfirmerClesSurCa = deser_message_buffer!(reponse.message);
                    let cles_manquantes = reponse_cles_manquantes.cles_manquantes;
                    traiter_cles_manquantes_ca(middleware, &commande.liste_cle_id, &cles_manquantes, session).await?;
                },
                _ => Err(Error::Str("emettre_cles_vers_ca Recu mauvais type de reponse "))?
            }
        },
        None => info!("emettre_cles_vers_ca Aucune reponse du serveur")
    }

    // liste_cles.clear();  // Retirer toutes les cles pour prochaine page

    Ok(())
}

/// Marque les cles emises comme confirmees par le CA sauf si elles sont dans la liste de cles manquantes.
async fn traiter_cles_manquantes_ca<M>(
    middleware: &M,
    cles_emises: &Vec<String>,
    cles_manquantes: &Vec<String>, session: &mut ClientSession
)
    -> Result<(), Error>
where M: MongoDao + GenerateurMessages + CleChiffrageHandler
{
    let nom_collection = NOM_COLLECTION_SYMMETRIQUE_CLES;

    // Marquer cles emises comme confirmees par CA si pas dans la liste de manquantes
    {
        let cles_confirmees: Vec<&String> = cles_emises.iter()
            .filter(|c| !cles_manquantes.contains(c))
            .collect();
        debug!("traiter_cles_manquantes_ca Cles confirmees par le CA: {} cles", cles_confirmees.len());
        if ! cles_confirmees.is_empty() {
            // let filtre_confirmees = doc! {CHAMP_HACHAGE_BYTES: {"$in": cles_confirmees}};
            // let filtre_confirmees = doc! { "$or": CleSynchronisation::get_bson_filter(&cles_confirmees)? };
            let filtre_confirmees = doc! { "cle_id": { "$in": &cles_confirmees } };
            let ops = doc! {
                "$set": {CHAMP_CONFIRMATION_CA: true},
                "$currentDate": {CHAMP_MODIFICATION: true}
            };
            let collection = middleware.get_collection(nom_collection)?;
            let resultat_confirmees = collection.update_many_with_session(filtre_confirmees, ops, None, session).await?;
            debug!("traiter_cles_manquantes_ca Resultat maj cles confirmees: {:?}", resultat_confirmees);
        }
    }

    // Rechiffrer et emettre les cles manquantes.
    if ! cles_manquantes.is_empty() {
        let filtre_manquantes = doc! { "cle_id": { "$in": &cles_manquantes } };
        let collection = middleware.get_collection_typed::<RowClePartition>(nom_collection)?;
        let mut curseur = collection.find_with_session(filtre_manquantes, None, session).await?;
        let mut cles = Vec::new();
        while let Some(d) = curseur.next(session).await {
            match d {
                Ok(cle) => {
                    let cle_transfert_ca = CleTransfertCa {
                        signature: cle.signature,
                        format: cle.format,
                        nonce: cle.header,
                        verification: cle.tag,
                    };
                    cles.push(cle_transfert_ca)
                },
                Err(e) => {
                    warn!("traiter_cles_manquantes_ca Erreur conversion document en cle : {:?}", e);
                    continue
                }
            };
        }

        let routage_commande = RoutageMessageAction::builder(
            DOMAINE_NOM, COMMANDE_TRANSFERT_CLE_CA, vec![Securite::L3Protege]
        )
            .blocking(false)
            .build();

        let commande = CommandeTransfertClesCaV2 { cles };
        debug!("traiter_cles_manquantes_ca Emettre {} cles rechiffrees pour CA", commande.cles.len());
        middleware.transmettre_commande(routage_commande.clone(), &commande).await?;
    }

    Ok(())
}


pub async fn requete_compter_cles_non_dechiffrables_ca<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_compter_cles_non_dechiffrables Consommer commande : {:?}", & m.type_message);
    // let requete: RequeteDechiffrage = m.message.get_msg().map_contenu(None)?;
    // debug!("requete_compter_cles_non_dechiffrables cle parsed : {:?}", requete);

    let filtre = doc! { CHAMP_NON_DECHIFFRABLE: true };
    let hint = Hint::Name(INDEX_NON_DECHIFFRABLES.into());
    // let sort_doc = doc! {
    //     CHAMP_NON_DECHIFFRABLE: 1,
    //     CHAMP_CREATION: 1,
    // };
    let opts = CountOptions::builder().hint(hint).build();
    let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
    let compte = collection.count_documents(filtre, opts).await?;

    let reponse = json!({ "compte": compte });
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

pub async fn requete_cles_non_dechiffrables<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_cles_non_dechiffrables Consommer commande : {:?}", m.type_message);
    let requete: RequeteClesNonDechiffrable = deser_message_buffer!(m.message);
    // debug!("requete_cles_non_dechiffrables cle parsed : {:?}", requete);

    let mut curseur = {
        let limite_docs = requete.limite.unwrap_or_else(|| 1000 as u64);

        let (skip_docs, mut filtre) = match requete.skip {
            Some(inner) => {
                let filtre = doc! {};
                (inner, filtre)
            },
            None => {
                let filtre = doc! {CHAMP_NON_DECHIFFRABLE: true};
                (0u64, filtre)
            }
        };

        match requete.date_creation_min {
            Some(d) => {
                filtre.insert(CHAMP_CREATION, doc!{"$gte": d});
            },
            None => ()
        }

        match requete.exclude_hachage_bytes {
            Some(e) => {
                filtre.insert(CHAMP_HACHAGE_BYTES, doc!{"$nin": e});
            },
            None => ()
        }

        let hint = Hint::Name(INDEX_NON_DECHIFFRABLES.into());
        // let sort_doc = doc! {
        //     CHAMP_NON_DECHIFFRABLE: 1,
        //     CHAMP_CREATION: 1,
        // };
        let opts = FindOptions::builder()
            .hint(hint)
            // .sort(sort_doc)
            .skip(skip_docs)
            .limit(Some(limite_docs as i64))
            .build();
        debug!("requete_cles_non_dechiffrables filtre cles a rechiffrer : filtre {:?} opts {:?}", filtre, opts);
        let collection = middleware.get_collection_typed::<RowClePartitionRef>(NOM_COLLECTION_CA_CLES)?;
        collection.find_with_session(filtre, opts, session).await?
    };

    let mut cles = Vec::new();
    let mut date_creation = None;
    while curseur.advance(session).await? {
        let cle = curseur.deserialize_current()?;

        // Conserver date de creation - On est juste interesse en la derniere date (plus recente).
        date_creation = Some(cle.date_creation.clone());

        let cle: RecupererCleCa = cle.try_into()?;  // Version owned
        cles.push(cle);
    }

    let reponse = json!({ "cles": cles, "date_creation_max": date_creation.as_ref() });
    debug!("requete_cles_non_dechiffrables Reponse {} cles rechiffrable", cles.len());
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Serialize)]
struct ReponseClesNonDechiffrables {
    cles: Vec<RecupererCleCa>,
    #[serde(default, skip_serializing_if="Option::is_none", with="optionepochseconds")]
    date_creation_max: Option<DateTime<Utc>>,
    idx: u64,
}

pub async fn requete_cles_non_dechiffrables_v2<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_rechiffrer_cles Consommer requete : {:?}", m.type_message);
    let requete: RequeteClesNonDechiffrable = deser_message_buffer!(m.message);
    let limite_docs = requete.limite.unwrap_or_else(|| 1000) as usize;

    let mut curseur = {
        let skip_docs_opts = requete.skip.unwrap_or_else(|| 0 as u64);

        let hint = Hint::Name("_id_".to_string());
        let opts = FindOptions::builder()
            .hint(hint)
            .skip(skip_docs_opts)
            // .limit(Some(limite_docs as i64))
            .build();
        let collection = middleware.get_collection_typed::<RowCleCaRef>(NOM_COLLECTION_CA_CLES)?;
        collection.find_with_session(None, opts, session).await?
    };

    let mut idx = requete.skip.unwrap_or_else(||0);

    let mut cles = Vec::new();
    let mut date_creation = None;
    while curseur.advance(session).await? {
        idx += 1;  // Compter toutes les cles pour permettre d'aller chercher la suite dans la prochaine requete.
        let cle = curseur.deserialize_current()?;
        // Verifier si la cle est non dechiffrable, skip sinon.
        if Some(true) == cle.non_dechiffrable {
            // Conserver date de creation - On est juste interesse en la derniere date (plus recente).
            date_creation = Some(cle.date_creation.clone());

            let cle: RecupererCleCa = cle.try_into()?;  // Version owned
            cles.push(cle);
        }
        if cles.len() >= limite_docs {
            break;
        }
    }

    let reponse = ReponseClesNonDechiffrables {
        cles,
        date_creation_max: date_creation,
        idx,
    };

    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

pub async fn requete_synchronizer_cles<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_synchronizer_cles Consommer requete : {:?}", m.type_message);
    let requete: RequeteSynchroniserCles = deser_message_buffer!(m.message);
    // debug!("requete_synchronizer_cles cle parsed : {:?}", requete);

    let mut curseur = {
        let limite_docs = requete.limite;
        let page = requete.page;
        let start_index = page * limite_docs;

        let filtre = doc! {};
        let hint = Hint::Keys(doc!{"_id": 1});  // Index _id
        //let sort_doc = doc! {"_id": 1};
        let projection = doc!{CHAMP_CLE_ID: 1};
        let opts = FindOptions::builder()
            .hint(hint)
            //.sort(sort_doc)
            .skip(Some(start_index as u64))
            .limit(Some(limite_docs as i64))
            .projection(Some(projection))
            .build();
        let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;

        collection.find_with_session(filtre, opts, session).await?
    };

    let mut cles = Vec::new();
    while let Some(d) = curseur.next(session).await {
        match d {
            Ok(doc_cle) => {
                match convertir_bson_deserializable::<CleSynchronisation>(doc_cle) {
                    Ok(h) => {
                        cles.push(h.cle_id);
                    },
                    Err(e) => {
                        info!("requete_synchronizer_cles Erreur mapping CleSynchronisation : {:?}", e);
                    }
                }
            },
            Err(e) => error!("requete_synchronizer_cles Erreur lecture doc cle : {:?}", e)
        }
    }

    let reponse = ReponseSynchroniserCles { liste_cle_id: cles };
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

pub async fn commande_ajouter_cle_domaines_ca<M, G>(middleware: &M, m: MessageValide, gestionnaire: &G, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao + ValidateurX509,
      G: GestionnaireDomaineV2 + AiguillageTransactions
{
    debug!("commande_ajouter_cle_domaines Consommer commande : {:?}", &m.type_message);
    let commande: CommandeAjouterCleDomaine = deser_message_buffer!(m.message);

    // Verifier si on a deja la cle - sinon, creer une nouvelle transaction
    let cle_id = commande.signature.get_cle_ref()?.to_string();

    let filtre = doc! { CHAMP_CLE_ID: &cle_id };
    let options = FindOneOptions::builder()
        .hint(Hint::Name("index_cle_id".to_string()))
        .projection(doc!{CHAMP_CLE_ID: 1})
        .build();
    let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
    let resultat = collection.find_one_with_session(filtre, options, session).await?;

    if resultat.is_none() {
        let transaction_cle = TransactionCleV2 { signature: commande.signature };
        debug!("commande_ajouter_cle_domaines Sauvegarder transaction nouvelle cle {}", cle_id);
        sauvegarder_traiter_transaction_serializable_v2(
            middleware, &transaction_cle, gestionnaire, session, DOMAINE_NOM, TRANSACTION_CLE_V2).await?;
    }

    // Confirmer le traitement de la cle
    Ok(Some(middleware.reponse_ok(None, None)?))
}

/// Conserver la presence d'une cle dechiffrable par au moins une partition.
pub async fn commande_confirmer_cles_sur_ca<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("commande_confirmer_cles_sur_ca Consommer commande : {:?}", m.type_message);
    let requete: ReponseSynchroniserCles = deser_message_buffer!(m.message);
    // debug!("requete_synchronizer_cles cle parsed : {:?}", requete);

    let mut cles_manquantes = HashSet::new();
    cles_manquantes.extend(&requete.liste_cle_id);

    let filtre_update = doc! {
        // CHAMP_HACHAGE_BYTES: {"$in": &requete.liste_hachage_bytes },
        // "$or": CleSynchronisation::get_bson_filter(&requete.liste_cle_id)?,
        "cle_id": {"$in": &requete.liste_cle_id},
        // CHAMP_NON_DECHIFFRABLE: true,
    };

    // Marquer les cles recues comme dechiffrables sur au moins une partition
    let ops = doc! {
        "$set": { CHAMP_NON_DECHIFFRABLE: false},
        "$currentDate": { CHAMP_MODIFICATION: true, CHAMP_DERNIERE_PRESENCE: true }
    };
    let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
    let resultat_update = collection.update_many_with_session(filtre_update, ops, None, session).await?;
    debug!("commande_confirmer_cles_sur_ca Resultat update : {:?}", resultat_update);

    // let filtre = doc! { "$or": CleSynchronisation::get_bson_filter(&requete.liste_cle_id)? };
    let filtre = doc! { "cle_id": {"$in": &requete.liste_cle_id } };
    debug!("commande_confirmer_cles_sur_ca Filtre cles CA: {:?}", filtre);
    let projection = doc! { CHAMP_CLE_ID: 1 };
    let opts = FindOptions::builder().projection(projection).build();
    let mut curseur = collection.find_with_session(filtre, opts, session).await?;
    while let Some(d) = curseur.next(session).await {
        match d {
            Ok(d) => {
                match convertir_bson_deserializable::<CleSynchronisation>(d) {
                    //match d.get(CHAMP_HACHAGE_BYTES) {
                    Ok(c) => {
                        // Enlever la cle de la liste de cles manquantes
                        trace!("Cle CA confirmee (presente) : {:?}", c);
                        cles_manquantes.remove(&c.cle_id);
                    },
                    Err(e) => {
                        info!("commande_confirmer_cles_sur_ca Erreur conversion CleSynchronisation : {:?}", e);
                    }
                }
            },
            Err(e) => warn!("commande_confirmer_cles_sur_ca Erreur traitement curseur mongo : {:?}", e)
        }
    }

    let mut vec_cles_manquantes = Vec::new();
    debug!("commande_confirmer_cles_sur_ca Demander {} cles manquantes sur CA", cles_manquantes.len());
    vec_cles_manquantes.extend(cles_manquantes.iter().map(|v| v.to_string()));
    let reponse = ReponseConfirmerClesSurCa { cles_manquantes: vec_cles_manquantes };
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

pub async fn commande_transfert_cle_ca<M,G>(middleware: &M, m: MessageValide, gestionnaire: &G, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509,
          G: GestionnaireDomaineV2 + AiguillageTransactions
{
    debug!("commande_transfert_cle Consommer commande : {:?}", &m.type_message);
    if !m.certificat.verifier_exchanges(vec![Securite::L3Protege])? ||
        !m.certificat.verifier_roles(vec![RolesCertificats::MaitreDesCles])?
    {
        Err(Error::Str("commande_transfert_cle Exchange/Role non autorise"))?
    }
    let commande: CommandeTransfertClesCaV2 = deser_message_buffer!(m.message);

    for cle in commande.cles {
        // Verifier si on a deja la cle - sinon, creer une nouvelle transaction
        let cle_id = cle.signature.get_cle_ref()?.to_string();

        let filtre = doc! { CHAMP_CLE_ID: &cle_id };
        let options = FindOneOptions::builder()
            .hint(Hint::Name("index_cle_id".to_string()))
            .projection(doc! {CHAMP_CLE_ID: 1})
            .build();
        let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
        let resultat = collection.find_one_with_session(filtre.clone(), options, session).await?;

        if resultat.is_none() {
            match cle.signature.version {
                SignatureDomainesVersion::NonSigne => {
                    // Ancienne version
                    let cle_id = cle.signature.signature.to_string();

                    let cle_ca = match cle.signature.ca.as_ref() {
                        Some(inner) => format!("m{}", inner),  // Ajoute 'm' multibase base64 no pad
                        None => Err(Error::Str("commande_transfert_cle Cle pour le CA manquante"))?
                    };

                    let domaine = match cle.signature.domaines.get(0) {
                        Some(inner) => inner.to_string(),
                        None => Err(Error::Str("Domaine manquant"))?
                    };

                    debug!("commande_transfert_cle Sauvegarder cle transferee {}", cle_id);
                    let transaction_cle = TransactionCle {
                        hachage_bytes: cle_id,
                        domaine,
                        identificateurs_document: Default::default(),
                        cle: cle_ca,
                        format: cle.format.clone(),
                        iv: None,
                        tag: cle.verification.clone(),
                        header: cle.nonce.clone(),
                        partition: None,
                    };
                    sauvegarder_traiter_transaction_serializable_v2(
                        middleware, &transaction_cle, gestionnaire, session, DOMAINE_NOM, TRANSACTION_CLE).await?;
                },
                _ => {
                    // Version courante
                    let transaction_cle = TransactionCleV2 { signature: cle.signature.clone() };
                    debug!("commande_ajouter_cle_domaines Sauvegarder transaction nouvelle cle {}", cle_id);
                    sauvegarder_traiter_transaction_serializable_v2(
                        middleware, &transaction_cle, gestionnaire, session, DOMAINE_NOM, TRANSACTION_CLE_V2).await?;
                }
            }

            // Mettre la jour la derniere presence
            let ops = doc! {"$currentDate": {CHAMP_DERNIERE_PRESENCE: true}};
            collection.update_one_with_session(filtre, ops, None, session).await?;
        } else {
            // TODO - Voir comment gerer cette situation
            warn!("commande_transfert_cle Transfert de cle existante: {:?}, SKIPPED", cle_id);
        }
    }

    Ok(None)
}

/// Reset toutes les cles a non_dechiffrable=true
pub async fn commande_reset_non_dechiffrable_ca<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao,
{
    debug!("commande_reset_non_dechiffrable Consommer commande : {:?}", & m.message);
    //let commande: CommandeSauvegarderCle = m.message.get_msg().map_contenu(None)?;
    //debug!("Commande sauvegarder cle parsed : {:?}", commande);

    let filtre = doc! {CHAMP_NON_DECHIFFRABLE: false};
    let ops = doc! {
        "$set": {CHAMP_NON_DECHIFFRABLE: true},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
    collection.update_many_with_session(filtre, ops, None, session).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

pub async fn evenement_cle_manquante<M>(middleware: &M, m: &MessageValide, session: &mut ClientSession) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("evenement_cle_manquante Marquer cles comme non dechiffrables correlation_id : {:?}", m.type_message);
    let event_non_dechiffrables: ReponseSynchroniserCles = deser_message_buffer!(m.message);

    // let filtre = doc! { CHAMP_HACHAGE_BYTES: { "$in": event_non_dechiffrables.liste_hachage_bytes }};
    let filtre = doc! {"cle_id": { "$in": &event_non_dechiffrables.liste_cle_id } };

    let ops = doc! {
        "$set": { CHAMP_NON_DECHIFFRABLE: true },
        "$currentDate": { CHAMP_MODIFICATION: true },
    };
    let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
    let resultat_update = collection.update_many_with_session(filtre, ops, None, session).await?;
    debug!("evenement_cle_manquante Resultat update : {:?}", resultat_update);

    Ok(None)
}

/// Marquer les cles existantes comme recues (implique dechiffrable) par au moins une partition
pub async fn evenement_cle_recue_partition<M>(middleware: &M, m: &MessageValide, session: &mut ClientSession) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("evenement_cle_recue_partition Marquer cle comme confirmee (dechiffrable) par la partition {:?}", m.type_message);
    debug!("evenement_cle_recue_partition Contenu\n{}", from_utf8(&m.message.buffer)?);
    let event_cles_recues: ReponseSynchroniserCles = deser_message_buffer!(m.message);

    // let filtre = doc! { CHAMP_HACHAGE_BYTES: { "$in": event_cles_recues.liste_hachage_bytes }};
    // let filtre = doc! { "$or": CleSynchronisation::get_bson_filter(&event_cles_recues.liste_cle_id)? };
    let filtre = doc! { "cle_id": {"$in": &event_cles_recues.liste_cle_id} };

    let ops = doc! {
        "$set": { CHAMP_NON_DECHIFFRABLE: false },
        "$currentDate": { CHAMP_MODIFICATION: true },
    };
    let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
    let resultat_update = collection.update_many_with_session(filtre, ops, None, session).await?;
    debug!("evenement_cle_recue_partition Resultat update : {:?}", resultat_update);

    Ok(None)
}

/// Transaction cle Version 1 (obsolete)
pub async fn transaction_cle<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao
{
    debug!("transaction_cle Consommer transaction : {:?}", transaction.transaction.routage);
    let transaction_cle: TransactionCle = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let hachage_bytes = transaction_cle.hachage_bytes.as_str();

    let filtre = doc! {"cle_id": hachage_bytes};
    let format: Option<&str> = match transaction_cle.format.clone() { Some(inner) => Some(inner.into()), None => None };

    let mut domaines = heapless::Vec::new();
    domaines.push(
        transaction_cle.domaine.as_str().try_into()
            .map_err(|_|Error::Str("transaction_cle Erreur mapping domaine to heapless::String"))?
    ).map_err(|_|Error::Str("transaction_cle Erreur ajout domaine to heapless::Vec"))?;

    // Convertir la cle dans le nouveau format de SignatureDomaine
    // Retirer le marqueur 'm' multibase pour obtenir base64 no pad.
    let cle_str = &transaction_cle.cle.as_str()[1..];
    let cle_heapless = cle_str.try_into().map_err(|_|Error::Str("transaction_cle Erreur mapping cle to heapless::String"))?;

    let signature = SignatureDomaines {
        domaines,
        version: SignatureDomainesVersion::NonSigne,
        ca: Some(cle_heapless),
        signature: hachage_bytes.try_into().map_err(|_|Error::Str("transaction_cle Erreur mapping hachage_bytes to heapless::String"))?,
    };

    // let mut set_on_insert = doc! {
    //     // CHAMP_HACHAGE_BYTES: hachage_bytes,
    //     // "domaine": &transaction_cle.domaine,
    //     // "cle": &transaction_cle.cle,
    //     "signature": convertir_to_bson(signature)?,
    //     CHAMP_NON_DECHIFFRABLE: true,
    //     CHAMP_CREATION: Utc::now(),
    // };

    let mut set_on_insert = doc! {
        "cle_id": hachage_bytes,
        "dirty": false,
        "signature": convertir_to_bson(signature)?,
        CHAMP_NON_DECHIFFRABLE: true,
        CHAMP_CREATION: Utc::now(),
        CHAMP_MODIFICATION: Utc::now(),
    };

    if let Some(inner) = transaction_cle.iv { set_on_insert.insert("iv", inner); }
    if let Some(inner) = transaction_cle.tag { set_on_insert.insert("tag", inner); }
    if let Some(inner) = transaction_cle.header { set_on_insert.insert("header", inner); }
    if let Some(inner) = format { set_on_insert.insert("format", inner); }

    // let mut doc_bson_transaction = match convertir_to_bson(transaction_cle) {
    //     Ok(inner) => inner,
    //     Err(e) => Err(format!("maitredescles_ca.transaction_cle Erreur convertir_to_bson : {:?}", e))?
    // };
    // doc_bson_transaction.insert(CHAMP_NON_DECHIFFRABLE, true);  // Flag non-dechiffrable par defaut (setOnInsert seulement)
    // doc_bson_transaction.insert(CHAMP_CREATION, DateTime::now());  // Flag non-dechiffrable par defaut (setOnInsert seulement)

    // let filtre = doc! {CHAMP_HACHAGE_BYTES: hachage_bytes};
    let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
    // if middleware.get_mode_regeneration() {
    //     let mut doc = set_on_insert;
    //     doc.insert("dirty", false);
    //     doc.insert(CHAMP_MODIFICATION, Utc::now());
    if middleware.get_mode_regeneration() {
        // Ignore session - this allows handling key duplication errors (by cle_id)
        match collection.insert_one(set_on_insert, None).await {
            Ok(r) => (),
            Err(e) => Err(format!("maitredescles_ca.transaction_cle Erreur update_one sur transaction : {:?}", e))?
        }
    } else {
        match collection.insert_one_with_session(set_on_insert, None, session).await {
            Ok(r) => (),
            Err(e) => Err(format!("maitredescles_ca.transaction_cle Erreur update_one sur transaction : {:?}", e))?
        }
    }
    // } else {
    //     let ops = doc! {
    //         "$set": {"dirty": false},
    //         "$setOnInsert": set_on_insert,
    //         "$currentDate": {CHAMP_MODIFICATION: true}
    //     };
    //     debug!("transaction_cle update ops : {:?}", ops);
    //     let opts = UpdateOptions::builder().upsert(true).build();
    //     let resultat = match collection.update_one_with_session(filtre, ops, opts, session).await {
    //         Ok(r) => r,
    //         Err(e) => Err(format!("maitredescles_ca.transaction_cle Erreur update_one sur transaction : {:?}", e))?
    //     };
    //     debug!("transaction_cle Resultat transaction update : {:?}", resultat);
    // }

    Ok(None)
}

pub async fn transaction_cle_v2<M>(middleware: &M, transaction: TransactionValide, session: &mut ClientSession) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao
{
    debug!("transaction_cle Consommer transaction : {:?}\n{}", transaction.transaction.routage,
        transaction.transaction.contenu.as_str());
    let transaction_cle: TransactionCleV2 = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let signature = transaction_cle.signature;
    let cle_id = signature.get_cle_ref()?.to_string();

    let set_on_insert = doc! {
        "cle_id": cle_id,
        "dirty": false,
        "signature": convertir_to_bson(signature)?,
        CHAMP_NON_DECHIFFRABLE: true,
        CHAMP_CREATION: Utc::now(),
        CHAMP_MODIFICATION: Utc::now(),
    };

    // let filtre = doc! {"cle_id": cle_id};
    // let ops = doc! {
    //     "$set": {"dirty": false},
    //     "$setOnInsert": set_on_insert,
    //     "$currentDate": {CHAMP_MODIFICATION: true}
    // };
    // let opts = UpdateOptions::builder().upsert(true).build();
    let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
    // debug!("transaction_cle update ops : {:?}", ops);
    // let resultat = if middleware.get_mode_regeneration() {
    //     let mut doc = set_on_insert;
    //     doc.insert("dirty", false);
    //     doc.insert(CHAMP_MODIFICATION, Utc::now());
    if middleware.get_mode_regeneration() {
        // Ignore session - this allows handling key duplication errors (by cle_id)
        match collection.insert_one(set_on_insert, None).await {
            Ok(r) => (),
            Err(e) => Err(format!("maitredescles_ca.transaction_cle_v2 Erreur update_one sur transaction : {:?}", e))?
        }
    } else {
        match collection.insert_one_with_session(set_on_insert, None, session).await {
            Ok(r) => (),
            Err(e) => Err(format!("maitredescles_ca.transaction_cle_v2 Erreur update_one sur transaction : {:?}", e))?
        }
    }
    // } else {
    //     match collection.update_one_with_session(filtre, ops, opts, session).await {
    //         Ok(r) => r,
    //         Err(e) => Err(format!("maitredescles_ca.transaction_cle Erreur update_one sur transaction : {:?}", e))?
    //     }
    // };
    // debug!("transaction_cle Resultat transaction update : {:?}", resultat);

    Ok(None)
}

pub async fn requete_dechiffrage_v2<M>(middleware: &M, m: MessageValide, handler_rechiffrage: &HandlerCleRechiffrage, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + CleChiffrageHandler
{
    debug!("requete_dechiffrage_v2 Consommer requete : {:?}", & m.type_message);
    let message_ref = m.message.parse()?;
    let requete: RequeteDechiffrage = match message_ref.contenu()?.deserialize() {
        Ok(inner) => inner,
        Err(e) => {
            info!("requete_dechiffrage_v2 Erreur mapping ParametresGetPermissionMessages : {:?}", e);
            // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": format!("Erreur mapping requete : {:?}", e)}), None)?))
            return Ok(Some(middleware.reponse_err(None, None, Some(format!("Erreur mapping requete : {:?}", e).as_str()))?))
        }
    };

    let inclure_signature = Some(true) == requete.inclure_signature;

    // Supporter l'ancien format de requete (liste_hachage_bytes) avec le nouveau (cle_ids)
    let cle_ids = match requete.cle_ids.as_ref() {
        Some(inner) => inner,
        None => match requete.liste_hachage_bytes.as_ref() {
            Some(inner) => inner,
            None => Err(Error::Str("Aucunes cles demandees pour le rechiffrage"))?
        }
    };

    // Verifier que la requete est autorisee
    let (certificat, requete_autorisee_globalement) = match verifier_permission_rechiffrage(middleware, &m, &requete).await {
        Ok(inner) => inner,
        Err(ErreurPermissionRechiffrage::Refuse(e)) => {
            let refuse = json!({"ok": false, "err": e.err, "acces": "0.refuse", "code": e.code});
            return Ok(Some(middleware.build_reponse(&refuse)?.0))
        },
        Err(ErreurPermissionRechiffrage::Error(e)) => Err(e)?
    };

    let enveloppe_privee = middleware.get_enveloppe_signature();
    let fingerprint = enveloppe_privee.fingerprint()?;

    // Recuperer les cles et dechiffrer
    let mut cles: Vec<ResponseRequestDechiffrageV2Cle> = Vec::new();

    let nom_collection = NOM_COLLECTION_SYMMETRIQUE_CLES;

    let requete_cle_ids = match requete.cle_ids.as_ref() {
        Some(inner) => inner,
        None => match requete.liste_hachage_bytes.as_ref() {
            Some(inner) => inner,
            None => {
                info!("requete_dechiffrage_v2 requete sans cle_ids ni liste_hachage_bytes");
                return Ok(Some(middleware.reponse_err(1, None, Some("Requete sans cle_ids ni liste_hachage_bytes"))?))
            }
        }
    };

    let filtre = doc! {
        CHAMP_CLE_ID: {"$in": requete_cle_ids},
        // "signature.domaines": {"$in": vec![&requete.domaine]}
    };
    // filtre.insert("signature.domaines", doc!{"$in": vec![&requete.domaine]});
    let collection = middleware.get_collection_typed::<RowClePartition>(nom_collection)?;
    let mut curseur = collection.find_with_session(filtre, None, session).await?;
    let domaine: heapless::String<40> = requete.domaine.as_str().try_into()
        .map_err(|_| Error::Str("Erreur map domain dans heapless::String<40>"))?;

    // Compter les cles trouvees separement de la liste. On rejete des cles qui ont un mismatch de domaine
    // mais elles comptent sur le total trouve.
    let mut cles_trouvees = 0;

    while let Some(row) = curseur.next(session).await {
        match row {
            Ok(inner) => {
                cles_trouvees += 1;
                if inner.signature.domaines.contains(&domaine) {
                    let signature = inner.signature.clone();
                    match inner.to_cle_secrete_serialisee(handler_rechiffrage) {
                        Ok(inner) => {
                            let mut cle: ResponseRequestDechiffrageV2Cle = inner.into();
                            if inclure_signature { cle.signature = Some(signature); }
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

    // Verifier si on a des cles inconnues
    // En cas de cles inconnues, et si on a plusieurs maitre des cles, faire une requete
    let nombre_maitre_des_cles = middleware.get_publickeys_chiffrage().len();
    if cles_trouvees < cle_ids.len() && nombre_maitre_des_cles > 1 {
        debug!("requete_dechiffrage_v2 Cles manquantes, on a {} trouvees sur {} demandees", cles.len(), cle_ids.len());

        // Identifier les cles manquantes
        let mut cles_hashset = HashSet::new();
        for item in cle_ids {
            cles_hashset.insert(item.as_str());
        }
        for item in &cles {
            if let Some(cle_id) = &item.cle_id {
                cles_hashset.remove(cle_id.as_str());
            }
        }

        // Effectuer une requete pour verifier si les cles sont connues d'un autre maitre des cles
        let liste_cles: Vec<String> = cles_hashset.iter().map(|m| m.to_string()).collect();
        let requete_transfert = RequeteTransfert {
            fingerprint,
            cle_ids: liste_cles,
            toujours_repondre: Some(true),
        };
        let data_reponse = effectuer_requete_cles_manquantes(
            middleware, &requete_transfert).await.unwrap_or_else(|e| {
            error!("traiter_batch_synchroniser_cles Erreur requete cles manquantes : {:?}", e);
            None
        });
        if let Some(data_reponse) = data_reponse {
            debug!("traiter_batch_synchroniser_cles Recu {}/{} cles suite a requete de cles manquantes",
                data_reponse.cles.len(), cles_hashset.len());
            for cle in data_reponse.cles {
                sauvegarder_cle_transfert(middleware, handler_rechiffrage, &cle, session).await?;
            }
        }
    }

    // Preparer la reponse
    // Verifier si on a au moins une cle dans la reponse
    let reponse = if cles.len() > 0 {
        let reponse = ReponseRequeteDechiffrageV2 { ok: true, code: 1, cles: Some(cles), err: None };
        middleware.build_reponse_chiffree(reponse, certificat.as_ref())?.0
    } else {
        // On n'a pas trouve de cles
        debug!("requete_dechiffrage_v2 Requete {:?} de dechiffrage {:?}, cles inconnues", m.type_message, &cle_ids);

        // Retourner cle inconnu a l'usager
        let inconnu = json!({"ok": false, "err": "Cles inconnues", "acces": CHAMP_ACCES_CLE_INCONNUE, "code": 4});
        let reponse = ReponseRequeteDechiffrageV2 {
            ok: false,
            code: 4,
            cles: None,
            err: Some("Cles inconnues".to_string())
        };
        middleware.build_reponse(&inconnu)?.0
    };

    Ok(Some(reponse))
}

/// Methode qui repond a un maitre des cles avec la liste complete des cles demandees. Si la liste
/// ne peut etre completee, une commande de transfert de cles emets la liste partielle chiffrees
/// pour tous les maitre des cles.
pub async fn requete_transfert_cles<M>(middleware: &M, m: MessageValide, handler_rechiffrage: &HandlerCleRechiffrage, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + CleChiffrageHandler
{
    debug!("requete_transfert_cles Consommer requete : {:?}", & m.type_message);

    // Verifier que la requete provient d'un maitre des cles
    if ! m.certificat.verifier_roles(vec![RolesCertificats::MaitreDesCles])? {
        Err(Error::Str("requete_transfert_cles Requete qui ne provient pas d'un maitre des cles (role), SKIP"))?
    }
    if ! m.certificat.verifier_domaines(vec![DOMAINE_NOM.to_string()])? {
        Err(Error::Str("requete_transfert_cles Requete qui ne provient pas d'un maitre des cles (domaine), SKIP"))?
    }
    if ! m.certificat.verifier_exchanges(vec![Securite::L3Protege])? {
        Err(Error::Str("requete_transfert_cles Requete qui ne provient pas d'un certificat 3.protege, SKIP"))?
    }

    let message_ref = m.message.parse()?;
    let requete: RequeteTransfert = match message_ref.contenu()?.deserialize() {
        Ok(inner) => inner,
        Err(e) => {
            error!("requete_transfert_cles Erreur mapping RequeteTransfert : {:?}", e);
            return Ok(Some(middleware.reponse_err(None, None, Some(format!("requete_transfert_cles Erreur mapping requete : {:?}", e).as_str()))?))
        }
    };

    // Verifier si on a emis cette requete de transfert (localement)
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let fingerprint = enveloppe_privee.fingerprint()?;
    if requete.fingerprint.as_str() == fingerprint.as_str() {
        debug!("requete_transfert_cles Requete emise par le maitre de cle local (c'est notre requete), on l'ignore");
        return Ok(None)
    }

    // Recuperer les cles et dechiffrer
    let mut cles = Vec::new();

    let nom_collection = NOM_COLLECTION_SYMMETRIQUE_CLES;

    let filtre = doc! { CHAMP_CLE_ID: {"$in": &requete.cle_ids} };
    let collection = middleware.get_collection_typed::<RowClePartition>(nom_collection)?;
    let mut curseur = collection.find_with_session(filtre, None, session).await?;

    while let Some(row) = curseur.next(session).await {
        match row {
            Ok(row_cle) => {
                let signature = row_cle.signature.clone();
                match row_cle.to_cle_secrete_serialisee(handler_rechiffrage) {
                    Ok(inner) => {
                        let cle = CleTransfert {
                            cle_secrete_base64: inner.cle_secrete_base64.to_string(),
                            signature,
                            format: inner.format.clone(),
                            nonce: match inner.nonce.as_ref() { Some(inner) => Some(inner.to_string()), None => None },
                            verification: match inner.verification.as_ref() { Some(inner) => Some(inner.to_string()), None => None },
                        };
                        cles.push(cle)
                    },
                    Err(e) => {
                        warn!("requete_transfert_cles Erreur mapping / dechiffrage cle - SKIP : {:?}", e);
                        continue
                    }
                }
            },
            Err(e) => {
                warn!("requete_transfert_cles Erreur mapping cle, SKIP : {:?}", e);
                continue
            }
        }
    }

    // Verifier si on a des cles inconnues
    let toujours_repondre = requete.toujours_repondre.unwrap_or_else(||false);
    let nombre_cles_trouvees = cles.len();
    let toutes_cles_trouvees = nombre_cles_trouvees == requete.cle_ids.len();
    let repondre = toujours_repondre || toutes_cles_trouvees;

    let reponse = CommandeTransfertClesV2 {
        fingerprint_emetteur: fingerprint,
        cles,
    };

    if repondre {
        // On a la liste complete ou on doit toujours repondre.
        info!("requete_transfert_cles Repondre avec {} cles", nombre_cles_trouvees);
        Ok(Some(middleware.build_reponse_chiffree(reponse, m.certificat.as_ref())?.0))
    } else if ! toutes_cles_trouvees {
        info!("requete_transfert_cles Cles manquantes, on a {} trouvees sur {} demandees", nombre_cles_trouvees, requete.cle_ids.len());
        // Generer une commande de transfert de cles pour tous les maitres des cles avec la liste partielle
        // Va permettre a plusieurs maitres des cles de repondre avec leur liste au besoin
        let cles_chiffrage_vec = middleware.get_publickeys_chiffrage();
        let routage = RoutageMessageAction::builder(DOMAINE_NOM, COMMANDE_TRANSFERT_CLE, vec![Securite::L3Protege])
            .build();
        let commande_chiffree = middleware.build_message_action_chiffre(
            millegrilles_cryptographie::messages_structs::MessageKind::CommandeInterMillegrille,
            routage, reponse, cles_chiffrage_vec)?.0;
        Ok(Some(commande_chiffree))
    } else {
        debug!("requete_transfert_cles Cles manquantes, on n'a aucunes cles a transmettre, SKIP");
        Ok(None)
    }
}

async fn sauvegarder_cle_domaine<M>(
    middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage,
    commande: CommandeAjouterCleDomaine, session: &mut ClientSession
)
    -> Result<(), Error>
where M: GenerateurMessages + MongoDao
{
    let enveloppe_signature = middleware.get_enveloppe_signature();

    // Dechiffrer la cle
    let cle_secrete = commande.get_cle_secrete(enveloppe_signature.as_ref())?;

    sauvegarder_cle_secrete(middleware, &handler_rechiffrage, commande.signature, &cle_secrete, session).await?;

    Ok(())
}

pub async fn commande_ajouter_cle_domaines<M>(middleware: &M, m: MessageValide, handler_rechiffrage: &HandlerCleRechiffrage, session: &mut ClientSession)
                                              -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao + CleChiffrageHandler
{
    debug!("commande_ajouter_cle_domaines Consommer commande : {:?}", &m.type_message);
    let commande: CommandeAjouterCleDomaine = deser_message_buffer!(m.message);

    let enveloppe_signature = middleware.get_enveloppe_signature();

    // Dechiffrer la cle - confirme qu'elle est valide et qu'on peut y acceder.
    let cle_secrete = commande.get_cle_secrete(enveloppe_signature.as_ref())?;

    // Valider la signature des domaines.
    if let Err(e) = commande.verifier_signature(cle_secrete.0) {
        warn!("commande_ajouter_cle_domaines Signature domaines invalide : {:?}", e);
        return Ok(Some(middleware.reponse_err(2, None, Some("Signature domaines invalide"))?))
    }

    if let Err(e) = sauvegarder_cle_domaine(middleware, handler_rechiffrage, commande, session).await {
        warn!("commande_ajouter_cle_domaines Erreur sauvegarde cle : {:?}", e);
        return Ok(Some(middleware.reponse_err(3, None, Some("Erreur sauvegarde cle"))?))
    }

    // On ne retourne pas de confirmation - les transactions de cles sont sauvegardees et
    // confirmees par le CA.
    Ok(None)
}

/// Commande recue d'un client (e.g. Coup D'Oeil) avec une batch de cles secretes dechiffrees.
/// La commande est chiffree pour tous les MaitreDesComptes (kind:8)
pub async fn commande_rechiffrer_batch<M>(middleware: &M, mut m: MessageValide, handler_rechiffrage: &HandlerCleRechiffrage, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + CleChiffrageHandler
{
    debug!("commande_rechiffrer_batch Message {:?}\n{}", m.type_message, from_utf8(m.message.buffer.as_slice())?);
    let message_ref = m.message.parse()?;
    let correlation_id = match &m.type_message {
        TypeMessageOut::Commande(r) => {
            match r.correlation_id.as_ref() { Some(inner) => inner.clone(), None => message_ref.id.to_owned() }
        },
        _ => Err(Error::Str("commande_rechiffrer_batch Mauvais type de message - doit etre commande"))?
    };

    let commande: CommandeRechiffrerBatchChiffree = deser_message_buffer!(m.message);
    let cles_dechiffrees: CommandeRechiffrerBatchDechiffree = decrypt_document(middleware, commande.cles)?;

    let nom_collection_cles = NOM_COLLECTION_SYMMETRIQUE_CLES;
    // Traiter chaque cle individuellement
    let mut liste_cle_id: Vec<String> = Vec::new();
    for (cle_id, cle) in cles_dechiffrees.cles {
        sauvegarder_cle_rechiffrage(middleware, handler_rechiffrage, nom_collection_cles, cle, session).await?;
        liste_cle_id.push(cle_id);
    }

    // Emettre un evenement pour confirmer le traitement.
    // Utilise par le CA (confirme que les cles sont dechiffrables) et par le client (batch traitee)
    let routage_event = RoutageMessageAction::builder(
        DOMAINE_NOM, EVENEMENT_CLE_RECUE_PARTITION, vec![Securite::L4Secure])
        .build();
    let event_contenu = json!({
        "correlation": correlation_id,
        CHAMP_LISTE_CLE_ID: liste_cle_id,
    });
    middleware.emettre_evenement(routage_event, &event_contenu).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

pub async fn commande_cle_symmetrique<M>(middleware: &M, m: MessageValide, handler_rechiffrage: &HandlerCleRechiffrage, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    let commande: CommandeCleSymmetrique = deser_message_buffer!(m.message);

    // Verifier que le certificat est pour l'instance locale
    // (note : pas garanti - confusion entre plusieurs certificats locaux possible, e.g. mongo et sqlite)
    let enveloppe_secrete = middleware.get_enveloppe_signature();
    let fingerprint = enveloppe_secrete.fingerprint()?;
    let instance_id = enveloppe_secrete.enveloppe_pub.get_common_name()?;

    if commande.fingerprint.as_str() != fingerprint.as_str() {
        Err("commande_cle_symmetrique Mauvais fingerprint, skip")?
    }

    // Dechiffrage de la cle, mise en memoire - si echec, on ne peut pas dechiffrer la cle
    handler_rechiffrage.set_cle_symmetrique(commande.cle.as_str())?;

    let cle_locale = doc! {
        "type": "local",
        "instance_id": instance_id,
        "fingerprint": fingerprint.as_str(),
        "cle": commande.cle.as_str(),
    };

    debug!("commande_cle_symmetrique Inserer cle configuration locale {:?}", commande.cle);

    let collection = middleware.get_collection(NOM_COLLECTION_CONFIGURATION)?;
    collection.insert_one_with_session(cle_locale, None, session).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

pub async fn commande_transfert_cle<M>(middleware: &M, m: MessageValide, handler_rechiffrage: &HandlerCleRechiffrage, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + CleChiffrageHandler + ValidateurX509
{
    debug!("commande_transfert_cle Consommer commande : {:?}", &m.type_message);
    if !m.certificat.verifier_exchanges(vec![Securite::L3Protege])? ||
        !m.certificat.verifier_roles(vec![RolesCertificats::MaitreDesCles])?
    {
        Err(Error::Str("commande_transfert_cle Exchange/Role non autorise"))?
    }

    let message_ref = m.message.parse()?;
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let commande: CommandeTransfertClesV2 = match message_ref.dechiffrer(enveloppe_privee.as_ref()) {
        Ok(inner) => inner,
        Err(e) => Err(Error::String(format!("commande_transfert_cle  Erreur dechiffrage commande, skip : {:?}", e)))?
    };

    let enveloppe_signature = middleware.get_enveloppe_signature();
    let fingerprint_local = enveloppe_signature.fingerprint()?;
    if commande.fingerprint_emetteur == fingerprint_local {
        debug!("commande_transfert_cle Commande transfert cle emise par local, on l'ignore");
        return Ok(None)
    }

    for cle in commande.cles {
        let cle_id = cle.signature.get_cle_ref()?.to_string();

        // Verifier si on a deja la cle - sinon, creer une nouvelle transaction
        let filtre = doc! { CHAMP_CLE_ID: &cle_id };
        let options = FindOneOptions::builder()
            .hint(Hint::Name("index_cle_id".to_string()))
            .projection(doc!{CHAMP_CLE_ID: 1})
            .build();
        let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
        let resultat = collection.find_one_with_session(filtre, options, session).await?;

        if resultat.is_none() {
            let cle_secrete_vec = base64_nopad.decode(&cle.cle_secrete_base64)?;

            // Valider la signature
            if let Err(e) = cle.signature.verifier_derivee(cle_secrete_vec.as_slice()) {
                warn!("commande_transfert_cle Signature cle {} invalide, SKIP. {:?}", cle_id, e);
                continue
            }

            let mut cle_secrete = CleSecreteX25519 {0: [0u8;32]};
            cle_secrete.0.copy_from_slice(&cle_secrete_vec[0..32]);
            sauvegarder_cle_secrete(middleware, &handler_rechiffrage, cle.signature.clone(), &cle_secrete, session).await?;
        }
    }

    Ok(None)
}

pub async fn commande_rotation_certificat<M>(middleware: &M, m: MessageValide, handler_rechiffrage: &HandlerCleRechiffrage, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_rotation_certificat Consommer commande : {:?}", & m.message);
    let commande: CommandeRotationCertificat = deser_message_buffer!(m.message);

    // Verifier que le certificat est pour l'instance locale
    // (note : pas garanti - confusion entre plusieurs certificats locaux possible, e.g. mongo et sqlite)
    let enveloppe_secrete = middleware.get_enveloppe_signature();
    let instance_id = enveloppe_secrete.enveloppe_pub.get_common_name()?;
    let certificat = middleware.charger_enveloppe(
        &commande.certificat, None, None).await?;
    let certificat_instance_id = certificat.get_common_name()?;

    if certificat_instance_id.as_str() == instance_id {
        debug!("commande_rotation_certificat Recu commande de rotation de certificat MaitreDesCles local");
        // let public_keys = certificat.fingerprint_cert_publickeys()?;
        let public_key = &certificat.certificat.public_key()?;
        let cle_secrete_chiffree_local = handler_rechiffrage.get_cle_symmetrique_chiffree(public_key)?;
        debug!("Cle secrete chiffree pour instance {}:\n local = {}", instance_id, cle_secrete_chiffree_local);
        let cle_locale = doc! {
            "type": "local",
            "instance_id": certificat_instance_id.as_str(),
            "fingerprint": certificat.fingerprint()?,
            "cle": cle_secrete_chiffree_local,
        };

        debug!("commande_rotation_certificat Inserer cle configuration locale {:?}", cle_locale);

        let collection = middleware.get_collection(NOM_COLLECTION_CONFIGURATION)?;
        collection.insert_one_with_session(cle_locale, None, session).await?;

        Ok(Some(middleware.reponse_ok(None, None)?))
    } else {
        debug!("commande_rotation_certificat Recu commande de rotation de certificat MaitreDesCles tiers - skip");
        Ok(None)
    }
}

pub async fn evenement_cle_rechiffrage<M>(middleware: &M, m: MessageValide, handler_rechiffrage: &HandlerCleRechiffrage, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + CleChiffrageHandler + ConfigMessages
{
    debug!("evenement_cle_rechiffrage Conserver cles de rechiffrage {:?}", &m.type_message);

    let enveloppe_signature = middleware.get_enveloppe_signature();
    let fingerprint_local = enveloppe_signature.fingerprint()?;

    let instance_id = m.certificat.get_common_name()?;
    let fingerprint = m.certificat.fingerprint()?;

    if fingerprint_local.as_str() == fingerprint.as_str() {
        debug!("evenement_cle_rechiffrage Evenement pour cle locale (fingerprint {}), skip", fingerprint);
        return Ok(None);
    }

    // Mapper evenement
    let evenement: EvenementClesRechiffrage = deser_message_buffer!(m.message);

    let collection = middleware.get_collection(NOM_COLLECTION_CONFIGURATION)?;
    let filtre_ca = doc! { "type": "CA-tiers", "instance_id": &instance_id };
    let ops_ca = doc! {
        "$set": {
            "cle": evenement.cle_ca,
        },
        "$setOnInsert": {
            CHAMP_CREATION: Utc::now(),
            "type": "CA-tiers",
            "instance_id": &instance_id,
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let options_ca = UpdateOptions::builder().upsert(true).build();
    collection.update_one_with_session(filtre_ca, ops_ca, Some(options_ca), session).await?;

    // Dechiffrer cle du tiers, rechiffrer en symmetrique local
    if let Some(cle_tierce) = evenement.cles_dechiffrage.get(fingerprint_local.as_str()) {

        let cle_tierce_vec = multibase::decode(cle_tierce)?;
        let cle_dechiffree = dechiffrer_asymmetrique_ed25519(
            &cle_tierce_vec.1[..], &enveloppe_signature.cle_privee)?;
        let cle_chiffree = handler_rechiffrage.chiffrer_cle_secrete(&cle_dechiffree.0[..])?;

        let filtre_cle = doc! {
            "type": "tiers",
            "instance_id": &instance_id,
            // "fingerprint": "tiers"
        };
        let ops_cle = doc! {
            "$set": {
                "cle_symmetrique": cle_chiffree.cle,
                "nonce_symmetrique": cle_chiffree.nonce,
            },
            "$setOnInsert": {
                CHAMP_CREATION: Utc::now(),
                "type": "tiers",
                "instance_id": &instance_id,
                // "fingerprint": "tiers",
            },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        let options_cle = UpdateOptions::builder().upsert(true).build();
        collection.update_one_with_session(filtre_cle, ops_cle, Some(options_cle), session).await?;
    }

    Ok(None)
}

pub async fn marquer_cles_ca_timeout<M>(middleware: &M) -> Result<(), Error>
    where M: MongoDao
{
    let expired = Utc::now() - Duration::hours(12);
    let filtre = doc!{CHAMP_DERNIERE_PRESENCE: {"$lte": expired}};
    let ops = doc!{
        "$set": {CHAMP_NON_DECHIFFRABLE: true},
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
    let mut session = middleware.get_session().await?;
    start_transaction_regular(&mut session).await?;
    match collection.update_many_with_session(filtre, ops, None, &mut session).await {
        Ok(_) => {
            session.commit_transaction().await?;
            Ok(())
        }
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)?
        }
    }
}

pub async fn query_repair_symmetric_key<M>(middleware: &M, m: MessageValide, handler_rechiffrage: &HandlerCleRechiffrage, session: &mut ClientSession)
                                           -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao + ValidateurX509 + CleChiffrageHandler
{
    if handler_rechiffrage.is_ready() {
        // Nothing to do, symmetric key already loaded
        return Ok(None);
    }

    let enveloppe_privee = middleware.get_enveloppe_signature();
    let instance_id = enveloppe_privee.enveloppe_pub.get_common_name()?;

    // Load the CA key
    let collection = middleware.get_collection_typed::<DocumentCleRechiffrage>(NOM_COLLECTION_CONFIGURATION)?;
    let filtre = doc!{"type": "CA", "instance_id": instance_id.as_str()};
    if let Some(cle_ca) = collection.find_one_with_session(filtre, None, session).await? {
        info!("preparer_rechiffreur_mongo CA symmetric key is present");
        // Emit the symmetric key that was encrypted for the CA.
        emettre_demande_cle_symmetrique(middleware, cle_ca.cle).await?;
    }

    // The reply goes through an event - multiple keymasters may be in the same situation
    Ok(None)
}
