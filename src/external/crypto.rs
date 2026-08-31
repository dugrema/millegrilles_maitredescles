use crate::models::CleInterneChiffree;
use millegrilles_common_rust::chacha20poly1305::aead::{Aead, OsRng};
use millegrilles_common_rust::chacha20poly1305::{AeadCore, KeyInit, XChaCha20Poly1305};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::CleSecrete;
use millegrilles_common_rust::millegrilles_cryptographie::x25519::{CleSecreteX25519, chiffrer_asymmetrique_ed25519, dechiffrer_asymmetrique_ed25519};
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppePrivee;
use millegrilles_common_rust::multibase::Base;
use millegrilles_common_rust::openssl::pkey::{PKey, Public};
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, Mutex};
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::constantes::RolesCertificats;
use millegrilles_common_rust::multibase;

pub struct SymmetricEncryptionHandler {
    /// Enveloppe de la cle prive locale.
    /// Utiliser pour dechiffrer messages recus (e.g. cles a conserver).
    enveloppe_privee: Arc<EnveloppePrivee>,
    /// Cle symmetrique utilisee pour chiffrer/dechiffrer la table MaitreDesCles/cles
    cle_symmetrique: Mutex<Option<CleSecreteX25519>>,
}

impl Clone for SymmetricEncryptionHandler {
    fn clone(&self) -> Self {
        let guard = self.cle_symmetrique.lock().expect("lock");
        let cle_secrete = match &*guard {
            Some(inner) => Some(CleSecrete(inner.0)),
            None => None
        };
        Self {
            // cle_rechiffrage: self.cle_rechiffrage.clone(),
            enveloppe_privee: self.enveloppe_privee.clone(),
            cle_symmetrique: Mutex::new(cle_secrete),
        }
    }
}

impl Debug for SymmetricEncryptionHandler {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let fingerprint = match self.fingerprint() {
            Ok(inner) => inner,
            Err(_e) => Err(std::fmt::Error{})?
        };
        f.write_str(format!("HandlerCleRechiffrage fingerprint {}", fingerprint).as_str())
    }
}

impl SymmetricEncryptionHandler {
    pub fn with_certificate(enveloppe_privee: Arc<EnveloppePrivee>) -> Self {
        // Ensure the certificate is for KeyMasters
        let is_keymaster = enveloppe_privee.enveloppe_pub.verifier_roles(
            vec![RolesCertificats::MaitreDesCles]).expect("Failure on verifier roles");
        if ! is_keymaster {
            panic!("The certificate is not for KeyMasters (must be RolesCertificats::MaitreDesCles)");
        }

        Self {
            enveloppe_privee,
            cle_symmetrique: Mutex::new(None),
        }
    }

    pub fn fingerprint(&self) -> Result<String, Error> {
        Ok(self.enveloppe_privee.fingerprint()?)
    }

    pub fn is_ready(&self) -> bool {
        // Si on a un certificat, le rechiffreur est pret
        self.cle_symmetrique.lock().expect("lock").is_some()
    }

    pub fn generer_cle_symmetrique(&self) -> Result<(), Error> {
        // Generer une cle secrete 32 bytes pour chiffrage symmetrique
        let mut guard = self.cle_symmetrique.lock().expect("lock");
        *guard = Some(CleSecrete::generer());
        Ok(())
    }

    pub fn get_cle_symmetrique_chiffree(&self, cle_publique: &PKey<Public>) -> Result<String, Error> {
        // Conserver versions asymmetriques de la cle privee
        match self.cle_symmetrique.lock().expect("lock").as_ref() {
            Some(inner) => {
                let cle_symmetrique = &inner.0[..];
                let cle_chiffree = chiffrer_asymmetrique_ed25519(
                    cle_symmetrique, cle_publique)?;
                Ok(multibase::encode(Base::Base64, &cle_chiffree[..]))
            },
            None => Err(format!("SymmetricEncryptionHandler.get_cle_symmetrique_chiffree Cle symmetrique non initialisee"))?
        }
    }

    pub fn set_cle_symmetrique<S>(&self, cle: S) -> Result<(), Error>
        where S: AsRef<str>
    {
        let cle = cle.as_ref();
        let enveloppe_privee = self.enveloppe_privee.as_ref();
        let cle_bytes = multibase::decode(cle)?;
        let cle_secrete = dechiffrer_asymmetrique_ed25519(&cle_bytes.1[..], &enveloppe_privee.cle_privee)?;
        let mut guard = self.cle_symmetrique.lock().expect("lock");
        *guard = Some(cle_secrete);

        Ok(())
    }

    pub fn chiffrer_cle_secrete(&self, cle: &[u8]) -> Result<CleInterneChiffree, Error> {
        let (nonce, ciphertext) = {
            let guard = self.cle_symmetrique.lock().expect("lock");
            match guard.as_ref() {
                Some(inner) => {
                    // let key = XChaCha20Poly1305::generate_key(&mut OsRng);
                    // let cipher = XChaCha20Poly1305::new(&inner.0[0..32]);
                    let cipher = XChaCha20Poly1305::new((&inner.0).into());
                    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
                    let ciphertext = match cipher.encrypt(&nonce, cle) {
                        Ok(inner) => inner,
                        Err(e) => Err(format!("maitredescles_volatil chiffrer_cle_secrete Erreur encrypt {:?}", e))?
                    };
                    (nonce, ciphertext)
                },
                None => panic!("Cle secrete non initialisee")
            }
        };

        let nonce_string: String = multibase::encode(Base::Base64, &nonce[..]);
        let cle_chiffree = multibase::encode(Base::Base64, &ciphertext[..]);

        // Ok((nonce_string, cle_chiffree))
        Ok(CleInterneChiffree {cle: cle_chiffree, nonce: nonce_string})
    }

    pub fn dechiffer_cle_secrete(&self, cle: CleInterneChiffree) -> Result<CleSecreteX25519, Error> {
        let nonce = multibase::decode(cle.nonce)?;
        let cle_chiffree = multibase::decode(cle.cle)?;

        let guard = self.cle_symmetrique.lock().expect("lock");
        match guard.as_ref() {
            Some(inner) => {
                let cipher = XChaCha20Poly1305::new((&inner.0).into());
                let cle_secrete = match cipher.decrypt((&nonce.1[..]).into(), &cle_chiffree.1[..]) {
                    Ok(inner) => {
                        let mut buffer = [0u8; 32];
                        buffer.copy_from_slice(&inner[0..32]);
                        CleSecrete(buffer)
                    },
                    Err(e) => Err(format!("maitredescles_volatil chiffrer_cle_secrete Erreur encrypt {:?}", e))?
                };

                Ok(cle_secrete)
            },
            None => panic!("Cle secrete non initialisee")
        }
    }
}