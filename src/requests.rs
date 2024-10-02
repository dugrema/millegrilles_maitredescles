use log::{debug, info};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::common_messages::RequeteDechiffrageMessage;
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::jwt_simple::prelude::Serialize;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::millegrilles_cryptographie::x25519::dechiffrer_asymmetrique_ed25519;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::base64::{engine::general_purpose::STANDARD_NO_PAD as base64_nopad, Engine as _};

// use crate::maitredescles_ca::GestionnaireMaitreDesClesCa;

pub async fn requete_certificat_maitredescles<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages
{
    debug!("emettre_certificat_maitredescles: {:?}", &m.type_message);
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let chaine_pem = enveloppe_privee.enveloppe_pub.chaine_pem()?;

    let reponse = json!({ "certificat": chaine_pem });

    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Serialize)]
struct ReponseDechiffrageMessage {
    ok: bool,
    cle_secrete_base64: String
}

pub async fn requete_dechiffrage_message<M>(middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + ValidateurX509 + CleChiffrageHandler
{
    debug!("requete_dechiffrage_message Consommer requete : {:?}", & m.type_message);

    // Une requete de dechiffrage de message doit etre effectuee par un module backend (Securite 3 ou 4).
    if ! m.certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
        return Ok(Some(middleware.reponse_err(401, None, Some("Acces refuse"))?))
    }

    let message_ref = m.message.parse()?;
    let requete: RequeteDechiffrageMessage = match message_ref.contenu()?.deserialize() {
        Ok(inner) => inner,
        Err(e) => {
            info!("requete_dechiffrage_message Erreur mapping RequeteDechiffrageMessage : {:?}", e);
            return Ok(Some(middleware.reponse_err(Some(500), None, Some(format!("Erreur mapping requete : {:?}", e).as_str()))?))
        }
    };

    let enveloppe_signature = middleware.get_enveloppe_signature();
    let fingerprint = enveloppe_signature.fingerprint()?;

    let cle_chiffree = match requete.cles.get(fingerprint.as_str()) {
        Some(inner) => inner.as_str(),
        None => return Ok(Some(middleware.reponse_err(3, None, Some("Cles non supportees"))?))
    };

    debug!("requete_dechiffrage_message Decoder cle chiffree {}", cle_chiffree);

    let cle_bytes = base64_nopad.decode(cle_chiffree)?;
    let cle_dechiffree = dechiffrer_asymmetrique_ed25519(cle_bytes.as_slice(), &enveloppe_signature.cle_privee)?;

    // Verifier que le domaine est inclus dans la signature
    if let Err(_) = requete.signature.verifier_derivee(&cle_dechiffree.0) {
        return Ok(Some(middleware.reponse_err(4, None, Some("Signature domaines invalide"))?))
    }

    // Verifier que le certificat donne acces a au moins 1 domaine dans la signature
    let domaines_permis: Vec<String> = requete.signature.domaines.iter().map(|d| d.to_string()).collect();
    if ! m.certificat.verifier_domaines(domaines_permis)? {
        return Ok(Some(middleware.reponse_err(5, None, Some("Acces pour domaines refuse"))?))
    }

    let cle_secrete_base64 = base64_nopad.encode(cle_dechiffree.0);

    let reponse = ReponseDechiffrageMessage { ok: true, cle_secrete_base64 };
    Ok(Some(middleware.build_reponse_chiffree(reponse, m.certificat.as_ref())?.0))
}
