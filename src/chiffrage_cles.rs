use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::millegrilles_cryptographie::x25519::{chiffrer_asymmetrique_ed25519, CleSecreteX25519, dechiffrer_asymmetrique_ed25519};
use millegrilles_common_rust::multibase;
use millegrilles_common_rust::multibase::Base;
use millegrilles_common_rust::openssl::pkey::{Id, PKey, Private, Public};

/// Rechiffre une cle asymetrique pour une nouvelle cle publique
pub fn rechiffrer_asymetrique_multibase(private_key: &PKey<Private>, public_key: &PKey<Public>, cle: &str)
    -> Result<String, Error>
{
    let cle_rechiffree = {
        let cle_secrete = extraire_cle_secrete(private_key, cle)?;

        // Determiner le type de cle. Supporte RSA et ED25519.
        match private_key.id() {
            Id::ED25519 => chiffrer_asymmetrique_ed25519(&cle_secrete.0[..], public_key)?.to_vec(),
            // Id::RSA => chiffrer_asymetrique_aesgcm(public_key, &cle_secrete.0[..])?,
            _ => Err(Error::Str("Unsupported key format - only Ed25519 is supported"))?
        }
    };

    Ok(multibase::encode(Base::Base64, &cle_rechiffree[..]))
}

pub fn chiffrer_asymetrique_multibase(cle_secrete: CleSecreteX25519, public_key: &PKey<Public>)
    -> Result<String, Error>
{
    let cle_rechiffree = {
        // Determiner le type de cle. Supporte RSA et ED25519.
        match public_key.id() {
            Id::ED25519 => chiffrer_asymmetrique_ed25519(&cle_secrete.0[..], public_key)?.to_vec(),
            // Id::RSA => chiffrer_asymetrique_aesgcm(public_key, &cle_secrete.0[..])?,
            _ => Err(Error::Str("Unsupported key format - only Ed25519 and RSA are supported"))?
        }
    };

    Ok(multibase::encode(Base::Base64, &cle_rechiffree[..]))
}

pub fn extraire_cle_secrete(private_key: &PKey<Private>, cle: &str)
    -> Result<CleSecreteX25519, Error>
{
    let cle_secrete = {
        let cle_bytes = match multibase::decode(cle) {
            Ok(inner) => inner.1,
            Err(e) => Err(Error::Multibase(e))?
        };

        // Determiner le type de cle. Supporte RSA et ED25519.
        match private_key.id() {
            Id::ED25519 => dechiffrer_asymmetrique_ed25519(&cle_bytes[..], private_key)?,
            // Id::RSA => dechiffrer_asymetrique_aesgcm(private_key, cle_bytes.as_slice()),
            _ => Err(Error::Str("Unsupported key format - only Ed25519 and RSA are supported"))?
        }
    };

    Ok(cle_secrete)
}
