use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use millegrilles_common_rust::chiffrage::CleSecrete;
use millegrilles_common_rust::chiffrage_ed25519::{CleDerivee, deriver_asymetrique_ed25519};
use millegrilles_common_rust::{openssl, openssl::pkey::{Id, PKey, Private, Public}};
use millegrilles_common_rust::certificats::EnveloppeCertificat;

#[derive(Clone)]
pub struct HandlerCleRechiffrage {
    cle_rechiffrage: PKey<Private>,
    pub certificat_maitredescles: Option<Arc<EnveloppeCertificat>>,
}

impl Debug for HandlerCleRechiffrage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.certificat_maitredescles.as_ref() {
            Some(c) => {
                let fingerprint = c.fingerprint.as_str();
                f.write_str(format!("HandlerCleRechiffrage fingerprint {}", fingerprint).as_str())
            },
            None => f.write_str(format!("HandlerCleRechiffrage sans certificat").as_str())
        }
    }
}

impl HandlerCleRechiffrage {

    pub fn new_volatil_memoire() -> Result<Self, Box<dyn Error>> {
        let cle_rechiffrage = PKey::generate_x25519()?;
        Ok(Self {
            cle_rechiffrage,
            certificat_maitredescles: None,
        })
    }

    pub fn with_certificat(
        cle_rechiffrage: PKey<Private>,
        certificat: Arc<EnveloppeCertificat>,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            cle_rechiffrage,
            certificat_maitredescles: Some(certificat),
        })
    }

}
