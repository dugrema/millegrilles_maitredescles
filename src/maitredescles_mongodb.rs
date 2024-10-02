use std::collections::HashSet;
use std::str::from_utf8;
use log::{debug, error, info, trace, warn};
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::constantes::{RolesCertificats, Securite, CHAMP_CREATION, CHAMP_MODIFICATION, COMMANDE_TRANSFERT_CLE_CA};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::millegrilles_cryptographie::{deser_message_buffer, heapless};
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::{SignatureDomaines, SignatureDomainesVersion};
use millegrilles_common_rust::millegrilles_cryptographie::x25519::CleSecreteX25519;
use millegrilles_common_rust::mongodb::options::{CountOptions, FindOneOptions, FindOptions, Hint, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::base64::{engine::general_purpose::STANDARD_NO_PAD as base64_nopad, Engine as _};
use millegrilles_common_rust::chiffrage_cle::CommandeAjouterCleDomaine;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, GestionnaireDomaineV2};
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction_serializable_v2;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, verifier_erreur_duplication_mongo, ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::json;
use crate::ca_manager::MaitreDesClesCaManager;
use crate::constants::*;
use crate::maitredescles_ca::GestionnaireMaitreDesClesCa;
use crate::maitredescles_commun::{effectuer_requete_cles_manquantes, emettre_demande_cle_symmetrique, preparer_rechiffreur, CleSecreteRechiffrage, CleSynchronisation, CleTransfert, CleTransfertCa, CommandeTransfertClesCaV2, DocumentCleRechiffrage, ReponseConfirmerClesSurCa, ReponseSynchroniserCles, RequeteSynchroniserCles, RequeteTransfert, RowClePartition, RowClePartitionRef, TransactionCle, TransactionCleV2};
use crate::maitredescles_partition::GestionnaireMaitreDesClesPartition;
use crate::maitredescles_rechiffrage::HandlerCleRechiffrage;
use crate::messages::{RecupererCleCa, RequeteClesNonDechiffrable};
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

pub async fn requete_cles_non_dechiffrables<M>(middleware: &M, m: MessageValide)
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
        collection.find(filtre, opts).await?
    };

    let mut cles = Vec::new();
    let mut date_creation = None;
    while curseur.advance().await? {
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

pub async fn requete_synchronizer_cles<M>(middleware: &M, m: MessageValide)
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

        collection.find(filtre, opts).await?
    };

    let mut cles = Vec::new();
    while let Some(d) = curseur.next().await {
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

pub async fn commande_ajouter_cle_domaines<M, G>(middleware: &M, m: MessageValide, gestionnaire: &G)
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
    let resultat = collection.find_one(filtre, options).await?;

    if resultat.is_none() {
        let transaction_cle = TransactionCleV2 { signature: commande.signature };
        debug!("commande_ajouter_cle_domaines Sauvegarder transaction nouvelle cle {}", cle_id);
        sauvegarder_traiter_transaction_serializable_v2(
            middleware, &transaction_cle, gestionnaire, DOMAINE_NOM, TRANSACTION_CLE_V2).await?;
    }

    // Confirmer le traitement de la cle
    Ok(Some(middleware.reponse_ok(None, None)?))
}

pub async fn commande_confirmer_cles_sur_ca<M>(middleware: &M, m: MessageValide)
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
        CHAMP_NON_DECHIFFRABLE: true,
    };

    // Marquer les cles recues comme dechiffrables sur au moins une partition
    let ops = doc! {
        "$set": { CHAMP_NON_DECHIFFRABLE: false},
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
    let resultat_update = collection.update_many(filtre_update, ops, None).await?;
    debug!("commande_confirmer_cles_sur_ca Resultat update : {:?}", resultat_update);

    // let filtre = doc! { "$or": CleSynchronisation::get_bson_filter(&requete.liste_cle_id)? };
    let filtre = doc! { "cle_id": {"$in": &requete.liste_cle_id } };
    debug!("commande_confirmer_cles_sur_ca Filtre cles CA: {:?}", filtre);
    let projection = doc! { CHAMP_CLE_ID: 1 };
    let opts = FindOptions::builder().projection(projection).build();
    let mut curseur = collection.find(filtre, opts).await?;
    while let Some(d) = curseur.next().await {
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

pub async fn commande_transfert_cle_ca<M,G>(middleware: &M, m: MessageValide, gestionnaire: &G)
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
        let resultat = collection.find_one(filtre, options).await?;

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
                        middleware, &transaction_cle, gestionnaire, DOMAINE_NOM, TRANSACTION_CLE).await?;
                },
                _ => {
                    // Version courante
                    let transaction_cle = TransactionCleV2 { signature: cle.signature.clone() };
                    debug!("commande_ajouter_cle_domaines Sauvegarder transaction nouvelle cle {}", cle_id);
                    sauvegarder_traiter_transaction_serializable_v2(
                        middleware, &transaction_cle, gestionnaire, DOMAINE_NOM, TRANSACTION_CLE_V2).await?;
                }
            }
        }
    }

    Ok(None)
}

/// Reset toutes les cles a non_dechiffrable=true
pub async fn commande_reset_non_dechiffrable_ca<M>(middleware: &M, m: MessageValide)
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
    collection.update_many(filtre, ops, None).await?;

    Ok(Some(middleware.reponse_ok(None, None)?))
}

pub async fn evenement_cle_manquante<M>(middleware: &M, m: &MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
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
    let resultat_update = collection.update_many(filtre, ops, None).await?;
    debug!("evenement_cle_manquante Resultat update : {:?}", resultat_update);

    Ok(None)
}

/// Marquer les cles existantes comme recues (implique dechiffrable) par au moins une partition
pub async fn evenement_cle_recue_partition<M>(middleware: &M, m: &MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
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
    let resultat_update = collection.update_many(filtre, ops, None).await?;
    debug!("evenement_cle_recue_partition Resultat update : {:?}", resultat_update);

    Ok(None)
}

/// Transaction cle Version 1 (obsolete)
pub async fn transaction_cle<M>(middleware: &M, transaction: TransactionValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
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

    let mut set_on_insert = doc! {
        // CHAMP_HACHAGE_BYTES: hachage_bytes,
        // "domaine": &transaction_cle.domaine,
        // "cle": &transaction_cle.cle,
        "signature": convertir_to_bson(signature)?,
        CHAMP_NON_DECHIFFRABLE: true,
        CHAMP_CREATION: Utc::now(),
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
    let ops = doc! {
        "$set": {"dirty": false},
        "$setOnInsert": set_on_insert,
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let opts = UpdateOptions::builder().upsert(true).build();
    let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
    debug!("transaction_cle update ops : {:?}", ops);
    let resultat = match collection.update_one(filtre, ops, opts).await {
        Ok(r) => r,
        Err(e) => Err(format!("maitredescles_ca.transaction_cle Erreur update_one sur transaction : {:?}", e))?
    };
    debug!("transaction_cle Resultat transaction update : {:?}", resultat);

    Ok(None)
}

pub async fn transaction_cle_v2<M>(middleware: &M, transaction: TransactionValide) -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao
{
    debug!("transaction_cle Consommer transaction : {:?}\n{}", transaction.transaction.routage,
        transaction.transaction.contenu.as_str());
    let transaction_cle: TransactionCleV2 = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let signature = transaction_cle.signature;
    let cle_id = signature.get_cle_ref()?.to_string();

    let mut set_on_insert = doc! {
        "signature": convertir_to_bson(signature)?,
        CHAMP_NON_DECHIFFRABLE: true,
        CHAMP_CREATION: Utc::now(),
    };

    let filtre = doc! {"cle_id": cle_id};
    let ops = doc! {
        "$set": {"dirty": false},
        "$setOnInsert": set_on_insert,
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let opts = UpdateOptions::builder().upsert(true).build();
    let collection = middleware.get_collection(NOM_COLLECTION_CA_CLES)?;
    debug!("transaction_cle update ops : {:?}", ops);
    let resultat = match collection.update_one(filtre, ops, opts).await {
        Ok(r) => r,
        Err(e) => Err(format!("maitredescles_ca.transaction_cle Erreur update_one sur transaction : {:?}", e))?
    };
    debug!("transaction_cle Resultat transaction update : {:?}", resultat);

    Ok(None)
}
