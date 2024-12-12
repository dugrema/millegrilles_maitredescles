use log::{debug, warn};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use crate::maitredescles_mongodb::preparer_rechiffreur_mongo;
use crate::maitredescles_rechiffrage::HandlerCleRechiffrage;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::messages_generiques::{CommandeCleRechiffree, CommandeDechiffrerCle};
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::millegrilles_cryptographie::x25519::{chiffrer_asymmetrique_ed25519, dechiffrer_asymmetrique_ed25519};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::multibase;
use millegrilles_common_rust::multibase::Base;
// use crate::maitredescles_partition::GestionnaireMaitreDesClesPartition;

pub async fn commande_verifier_cle_symmetrique<M>(middleware: &M, handler_rechiffrage: &HandlerCleRechiffrage, session: &mut ClientSession)
                                                  -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("evenement_verifier_cle_symmetrique Verifier si la cle symmetrique est chargee");

    if handler_rechiffrage.is_ready() == false {
        // Cle symmetrique manquante, on l'emet
        debug!("evenement_verifier_cle_symmetrique Cle symmetrique manquante");
        preparer_rechiffreur_mongo(middleware, &handler_rechiffrage).await?;
    } else {
        debug!("evenement_verifier_cle_symmetrique Cle symmetrique OK");
    }

    Ok(None)
}

pub async fn commande_dechiffrer_cle<M>(middleware: &M, m: MessageValide, session: &mut ClientSession)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages
{
    debug!("commande_dechiffrer_cle Dechiffrer cle {:?}", &m.type_message);
    let commande: CommandeDechiffrerCle = deser_message_buffer!(m.message);

    let enveloppe_signature = middleware.get_enveloppe_signature();
    let enveloppe_destinataire = m.certificat.as_ref();

    // verifier que le destinataire est de type L4Secure
    if enveloppe_destinataire.verifier_exchanges(vec![Securite::L4Secure])? == false {
        warn!("commande_dechiffrer_cle Certificat mauvais type (doit etre L4Secure)");
        // return Ok(Some(middleware.formatter_reponse(&json!({"ok": false}), None)?));
        return Ok(Some(middleware.reponse_err(None, None, None)?))
    }

    let (_, cle_chiffree) = multibase::decode(commande.cle.as_str())?;
    let cle_secrete = dechiffrer_asymmetrique_ed25519(&cle_chiffree[..], &enveloppe_signature.cle_privee)?;
    let cle_rechiffree = chiffrer_asymmetrique_ed25519(
        &cle_secrete.0[..], &enveloppe_destinataire.certificat.public_key()?)?;
    let cle_rechiffree_str: String = multibase::encode(Base::Base64, cle_rechiffree);

    let cle_reponse = CommandeCleRechiffree { ok: true, cle: Some(cle_rechiffree_str) };

    Ok(Some(middleware.build_reponse(&cle_reponse)?.0))
}
