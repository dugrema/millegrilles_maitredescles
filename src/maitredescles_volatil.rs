use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, Mutex};
use log::debug;
use millegrilles_common_rust::chiffrage::CleSecrete;
use millegrilles_common_rust::chiffrage_ed25519::{CleDerivee, deriver_asymetrique_ed25519};
use millegrilles_common_rust::{openssl, openssl::pkey::{Id, PKey, Private, Public}};
use millegrilles_common_rust::certificats::{EnveloppeCertificat, EnveloppePrivee};
use millegrilles_common_rust::common_messages::DemandeSignature;
use millegrilles_common_rust::constantes::{ROLE_MAITRE_DES_CLES, ROLE_MAITRE_DES_CLES_VOLATIL};
use millegrilles_common_rust::openssl::hash::MessageDigest;
use millegrilles_common_rust::openssl::nid::Nid;
use millegrilles_common_rust::openssl::symm::Mode;
use millegrilles_common_rust::openssl::x509::{X509Algorithm, X509Name, X509ReqBuilder};

pub struct HandlerCleRechiffrage {
    cle_rechiffrage: PKey<Private>,
    certificat_maitredescles: Mutex<Option<Arc<EnveloppeCertificat>>>,
}

impl Clone for HandlerCleRechiffrage {
    fn clone(&self) -> Self {
        let guard = self.certificat_maitredescles.lock().expect("lock");
        let clone_enveloppe = guard.clone();
        Self {
            cle_rechiffrage: self.cle_rechiffrage.clone(),
            certificat_maitredescles: Mutex::new(clone_enveloppe),
        }
    }
}

impl Debug for HandlerCleRechiffrage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.fingerprint() {
            Some(fingerprint) => {
                f.write_str(format!("HandlerCleRechiffrage fingerprint {}", fingerprint).as_str())
            },
            None => f.write_str(format!("HandlerCleRechiffrage sans certificat").as_str())
        }
    }
}

impl HandlerCleRechiffrage {

    pub fn new_volatil_memoire() -> Result<Self, Box<dyn Error>> {
        let cle_rechiffrage = PKey::generate_ed25519()?;
        Ok(Self {
            cle_rechiffrage,
            certificat_maitredescles: Mutex::new(None),
        })
    }

    pub fn with_certificat(enveloppe_privee: &EnveloppePrivee) -> Self {
        let cle_privee = enveloppe_privee.cle_privee().to_owned();
        let enveloppe = enveloppe_privee.enveloppe.clone();
        Self {
            cle_rechiffrage: cle_privee,
            certificat_maitredescles: Mutex::new(Some(enveloppe)),
        }
    }

    pub fn fingerprint(&self) -> Option<String> {
        match self.certificat_maitredescles.lock().expect("lock fingerprint").as_ref() {
            Some(c) => Some(c.fingerprint.to_owned()),
            None => None
        }
    }

    pub fn generer_csr<S>(&self, idmg_: S) -> Result<DemandeSignature, Box<dyn Error>>
        where S: AsRef<str>
    {
        debug!("Generer csr");

        let idmg = idmg_.as_ref();
        let mut cn_builder = X509Name::builder()?;
        cn_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, idmg)?;
        cn_builder.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, "MaitreDesCles".into())?;
        cn_builder.append_entry_by_nid(Nid::COMMONNAME, "volatil".into())?;
        let cn = cn_builder.build();

        let mut builder = X509ReqBuilder::new()?;
        builder.set_subject_name(cn.as_ref())?;
        builder.set_pubkey(self.cle_rechiffrage.as_ref())?;
        builder.set_version(0)?;

        builder.sign(self.cle_rechiffrage.as_ref(), MessageDigest::null())?;

        let req = builder.build();
        let csr = String::from_utf8(req.to_pem()?)?;

        let commande = DemandeSignature {
            csr,
            roles: Some(vec![ROLE_MAITRE_DES_CLES.to_string(), ROLE_MAITRE_DES_CLES_VOLATIL.to_string()]),
            domaines: None,
            exchanges: None,
            dns: None
        };

        Ok(commande)
    }

    pub fn set_certificat(&self, enveloppe: Arc<EnveloppeCertificat>) -> Result<(), String> {
        // Verifier que la cle publique correpond a la cle privee
        if ! self.cle_rechiffrage.public_eq(enveloppe.cle_publique.as_ref()) {
            Err(format!("maitredescles_volatil.set_certificat La cle publique ne correspond pas a la cle privee"))?
        }

        let mut guard = self.certificat_maitredescles.lock().expect("lock");
        *guard = Some(enveloppe);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        // Si on a un certificat, le rechiffreur est pret
        let guard = self.certificat_maitredescles.lock().expect("maitredescles_volatil.is_ready lock");
        guard.is_some()
    }

}
