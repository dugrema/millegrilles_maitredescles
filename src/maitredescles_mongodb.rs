use std::collections::HashSet;
use log::{debug, error, info, warn};
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::constantes::{Securite, CHAMP_CREATION, CHAMP_MODIFICATION, COMMANDE_TRANSFERT_CLE_CA};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::{SignatureDomaines, SignatureDomainesVersion};
use millegrilles_common_rust::millegrilles_cryptographie::x25519::CleSecreteX25519;
use millegrilles_common_rust::mongodb::options::{FindOptions, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::TypeMessage;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::base64::{engine::general_purpose::STANDARD_NO_PAD as base64_nopad, Engine as _};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, verifier_erreur_duplication_mongo, ChampIndex, IndexOptions, MongoDao};

use crate::constants::*;
use crate::maitredescles_commun::{effectuer_requete_cles_manquantes, emettre_demande_cle_symmetrique, preparer_rechiffreur, CleSecreteRechiffrage, CleSynchronisation, CleTransfert, CleTransfertCa, CommandeTransfertClesCaV2, DocumentCleRechiffrage, ReponseConfirmerClesSurCa, ReponseSynchroniserCles, RequeteSynchroniserCles, RequeteTransfert, RowClePartition};
use crate::maitredescles_partition::GestionnaireMaitreDesClesPartition;
use crate::maitredescles_rechiffrage::HandlerCleRechiffrage;
use crate::mongodb_manager::MaitreDesClesMongoDbManager;

pub const NOM_COLLECTION_TRANSACTIONS: &str = DOMAINE_NOM;
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

    let enveloppe_privee = middleware.get_enveloppe_signature();
    let instance_id = enveloppe_privee.enveloppe_pub.get_common_name()?;

    // Verifier si les cles de dechiffrage existent deja.
    let collection = middleware.get_collection(NOM_COLLECTION_CONFIGURATION)?;
    let filtre = doc!{"type": "CA", "instance_id": instance_id.as_str()};
    match collection.find_one(filtre, None).await? {
        Some(doc_cle_ca) => {
            info!("preparer_rechiffreur_mongo Cle de rechiffrage CA est presente");

            let filtre = doc!{
                "type": "local",
                "instance_id": instance_id.as_str(),
                "fingerprint": enveloppe_privee.fingerprint()?,
            };

            match collection.find_one(filtre, None).await? {
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
            collection.insert_one(cle_ca, None).await?;

            let cle_locale = doc! {
                "type": "local",
                "instance_id": instance_id.as_str(),
                "fingerprint": enveloppe_privee.fingerprint()?,
                "cle": cle_secrete_chiffree_local,
            };
            collection.insert_one(cle_locale, None).await?;
        }
    }

    Ok(())
}

pub async fn synchroniser_cles<M>(middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage) -> Result<(), Error>
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

        if let Err(e) = traiter_batch_synchroniser_cles(middleware, handler_rechiffrage, reponse).await {
            error!("synchroniser_cles Erreur traitement batch cles : {:?}", e);
        }
    }

    debug!("synchroniser_cles Fin");

    Ok(())
}

async fn traiter_batch_synchroniser_cles<M>(middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage, reponse: ReponseSynchroniserCles)
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
    let mut cles = collection.find(filtre_cles, Some(find_options)).await?;
    while let Some(row) = cles.next().await {
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
                sauvegarder_cle_transfert(middleware, handler_rechiffrage, &cle).await?;
            }
        }

        if cles_hashset.len() > 0 {
            info!("traiter_batch_synchroniser_cles Il reste {} cles non dechiffrables", cles_hashset.len());
        }
    }

    Ok(())
}

pub async fn sauvegarder_cle_transfert<M>(
    middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage, cle: &CleTransfert)
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

            if let Err(e) = sauvegarder_cle_rechiffrage(middleware, handler_rechiffrage, nom_collection_cles, cle_secrete_rechiffrage).await {
                error!("traiter_batch_synchroniser_cles Erreur sauvegarde cle {} : {:?}", cle_id, e);
            }
        }
        _ => {
            // Methode courante
            let mut cle_secrete_bytes = [0u8; 32];
            cle_secrete_bytes.copy_from_slice(&base64_nopad.decode(cle.cle_secrete_base64.as_str())?[0..32]);
            let cle_secrete = CleSecreteX25519 { 0: cle_secrete_bytes };
            if let Err(e) = sauvegarder_cle_secrete(middleware, handler_rechiffrage, cle.signature.clone(), &cle_secrete).await {
                error!("traiter_batch_synchroniser_cles Erreur sauvegarde cle {} : {:?}", cle_id, e);
            }
        }
    }
    Ok(())
}

pub async fn sauvegarder_cle_rechiffrage<M>(middleware: &M,
                                        handler_rechiffrage: &HandlerCleRechiffrage,
                                        nom_collection_cles: &str,
                                        cle: CleSecreteRechiffrage)
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
    collection.update_one(filtre, ops, opts).await?;

    Ok(cle_id)
}

pub async fn sauvegarder_cle_secrete<M>(
    middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage,
    signature: SignatureDomaines, cle_secrete: &CleSecreteX25519
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
    collection.update_one(filtre, ops, options).await?;
    Ok(())
}

/// S'assurer que le CA a toutes les cles de la partition. Permet aussi de resetter le flag non-dechiffrable.
pub async fn confirmer_cles_ca<M>(middleware: &M, reset_flag: Option<bool>) -> Result<(), Error>
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
        collection.update_many(filtre, ops, None).await?;
    }

    let mut curseur = {
        // let limit_cles = 1000000;
        let filtre = doc! { CHAMP_CONFIRMATION_CA: false };
        let opts = FindOptions::builder()
            // .limit(limit_cles)
            .build();
        let collection = middleware.get_collection(nom_collection)?;
        let curseur = collection.find(filtre, opts).await?;
        curseur
    };

    let mut cles = Vec::new();
    while let Some(d) = curseur.next().await {
        match d {
            Ok(cle) => {
                let cle_synchronisation: CleSynchronisation = convertir_bson_deserializable(cle)?;
                cles.push(cle_synchronisation.cle_id);

                if cles.len() == batch_size {
                    emettre_cles_vers_ca(middleware, &cles).await?;
                    cles.clear();  // Retirer toutes les cles pour prochaine page
                }
            },
            Err(e) => Err(format!("maitredescles_partition.confirmer_cles_ca Erreur traitement {:?}", e))?
        };
    }

    // Derniere batch de cles
    if cles.len() > 0 {
        emettre_cles_vers_ca(middleware, &cles).await?;
        cles.clear();
    }

    debug!("confirmer_cles_ca Fin confirmation cles locales");

    Ok(())
}

/// Emet un message vers CA pour verifier quels cles sont manquantes (sur le CA)
/// Marque les cles presentes sur la partition et CA comme confirmation_ca=true
/// Rechiffre et emet vers le CA les cles manquantes
async fn emettre_cles_vers_ca<M>(
    middleware: &M, liste_cles: &Vec<String>)
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
                    traiter_cles_manquantes_ca(middleware, &commande.liste_cle_id, &cles_manquantes).await?;
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
    cles_manquantes: &Vec<String>
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
            let resultat_confirmees = collection.update_many(filtre_confirmees, ops, None).await?;
            debug!("traiter_cles_manquantes_ca Resultat maj cles confirmees: {:?}", resultat_confirmees);
        }
    }

    // Rechiffrer et emettre les cles manquantes.
    if ! cles_manquantes.is_empty() {
        let filtre_manquantes = doc! { "cle_id": { "$in": &cles_manquantes } };
        let collection = middleware.get_collection_typed::<RowClePartition>(nom_collection)?;
        let mut curseur = collection.find(filtre_manquantes, None).await?;
        let mut cles = Vec::new();
        while let Some(d) = curseur.next().await {
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
