use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, Mutex};
use log::debug;
use millegrilles_common_rust::chiffrage::{CleSecrete, rechiffrer_asymetrique_multibase};
use millegrilles_common_rust::chiffrage_ed25519::{chiffrer_asymmetrique_ed25519, CleDerivee, dechiffrer_asymmetrique_ed25519, deriver_asymetrique_ed25519};
use millegrilles_common_rust::{multibase, openssl, openssl::pkey::{Id, PKey, Private, Public}};
use millegrilles_common_rust::certificats::{EnveloppeCertificat, EnveloppePrivee};
use millegrilles_common_rust::chiffrage_rsa::dechiffrer_asymetrique;
use millegrilles_common_rust::common_messages::DemandeSignature;
use millegrilles_common_rust::constantes::{ROLE_MAITRE_DES_CLES, ROLE_MAITRE_DES_CLES_VOLATIL, SECURITE_4_SECURE};
use millegrilles_common_rust::multibase::Base;
use millegrilles_common_rust::openssl::hash::MessageDigest;
use millegrilles_common_rust::openssl::nid::Nid;
use millegrilles_common_rust::openssl::symm::Mode;
use millegrilles_common_rust::openssl::x509::{X509Algorithm, X509Name, X509ReqBuilder};

pub struct HandlerCleRechiffrage {
    /// Cle privee utilisee pour dechiffrer cles recues
    //cle_rechiffrage: PKey<Private>,  // Obsolete

    /// Enveloppe de la cle prive locale.
    /// Utiliser pour dechiffrer messages recus (e.g. cles a conserver).
    enveloppe_privee: Arc<EnveloppePrivee>,

    /// Cle symmetrique utilisee pour chiffrer/dechiffrer la table MaitreDesCles/cles
    cle_symmetrique: Mutex<Option<CleSecrete>>,
}

impl Clone for HandlerCleRechiffrage {
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

impl Debug for HandlerCleRechiffrage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("HandlerCleRechiffrage fingerprint {}", self.fingerprint()).as_str())
        // match self.fingerprint() {
        //     Some(fingerprint) => {
        //         f.write_str(format!("HandlerCleRechiffrage fingerprint {}", fingerprint).as_str())
        //     },
        //     None => f.write_str(format!("HandlerCleRechiffrage sans certificat").as_str())
        // }
    }
}

impl HandlerCleRechiffrage {

    // pub fn new_volatil_memoire() -> Result<Self, Box<dyn Error>> {
    //     let cle_rechiffrage = PKey::generate_ed25519()?;
    //     Ok(Self {
    //         cle_rechiffrage,
    //         // certificat_maitredescles: Mutex::new(None),
    //         enveloppe_privee: Mutex::new(None),
    //         cle_symmetrique: Mutex::new(None),
    //     })
    // }

    pub fn with_certificat(enveloppe_privee: Arc<EnveloppePrivee>) -> Self {
        let cle_privee = enveloppe_privee.cle_privee().to_owned();
        Self {
            // cle_rechiffrage: cle_privee,
            // certificat_maitredescles: Mutex::new(Some(enveloppe)),
            enveloppe_privee: enveloppe_privee,
            cle_symmetrique: Mutex::new(None),
        }
    }

    // pub fn fingerprint(&self) -> Option<String> {
    pub fn fingerprint(&self) -> &str {
        // match self.certificat_maitredescles.lock().expect("lock fingerprint").as_ref() {
        //     Some(c) => Some(c.fingerprint.to_owned()),
        //     None => None
        // }
        // match self.enveloppe_privee.lock().expect("lock fingerprint").as_ref() {
        //     Some(c) => Some(c.fingerprint().to_owned()),
        //     None => None
        // }
        self.enveloppe_privee.fingerprint().as_str()
    }

    // pub fn generer_csr<S>(&self, idmg_: S) -> Result<DemandeSignature, Box<dyn Error>>
    //     where S: AsRef<str>
    // {
    //     debug!("Generer csr");
    //
    //     let idmg = idmg_.as_ref();
    //     let mut cn_builder = X509Name::builder()?;
    //     cn_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, idmg)?;
    //     cn_builder.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, "MaitreDesCles".into())?;
    //     cn_builder.append_entry_by_nid(Nid::COMMONNAME, "volatil".into())?;
    //     let cn = cn_builder.build();
    //
    //     let mut builder = X509ReqBuilder::new()?;
    //     builder.set_subject_name(cn.as_ref())?;
    //     builder.set_pubkey(self.cle_rechiffrage.as_ref())?;
    //     builder.set_version(0)?;
    //
    //     builder.sign(self.cle_rechiffrage.as_ref(), MessageDigest::null())?;
    //
    //     let req = builder.build();
    //     let csr = String::from_utf8(req.to_pem()?)?;
    //
    //     let commande = DemandeSignature {
    //         csr,
    //         roles: Some(vec![ROLE_MAITRE_DES_CLES.to_string(), ROLE_MAITRE_DES_CLES_VOLATIL.to_string()]),
    //         domaines: None,
    //         exchanges: Some(vec![SECURITE_4_SECURE.into()]),
    //         dns: None
    //     };
    //
    //     Ok(commande)
    // }

    // pub fn set_certificat(&self, enveloppe: Arc<EnveloppeCertificat>, enveloppe_ca: Arc<EnveloppeCertificat>) -> Result<(), String> {
    //     // Verifier que la cle publique correpond a la cle privee
    //     if ! self.cle_rechiffrage.public_eq(enveloppe.cle_publique.as_ref()) {
    //         Err(format!("maitredescles_volatil.set_certificat La cle publique ne correspond pas a la cle privee"))?
    //     }
    //
    //     let chaine_pem: Vec<String> = enveloppe.get_pem_vec().iter().map(|fp| fp.pem.clone()).collect();
    //     let pem_str: String = chaine_pem.join("\n");
    //
    //     let cle_privee_pem = match self.cle_rechiffrage.private_key_to_pem_pkcs8() {
    //         Ok(p) => match String::from_utf8(p) {
    //             Ok(pem) => pem,
    //             Err(e) => Err(format!("maitredescles_volatil.set_certificat Erreur conversion cle privee PEM en string : {:?}", e))?
    //         },
    //         Err(e) => Err(format!("maitredescles_volatil.set_certificat Erreur sauvegarde cle privee en PEM : {:?}",e))?
    //     };
    //     let clecert_pem = format!("{}\n{}", cle_privee_pem, pem_str);
    //
    //     let ca_pem = enveloppe_ca.get_pem_vec().get(0).expect("CA").pem.to_owned();
    //
    //     let enveloppe_privee = EnveloppePrivee::new(
    //         enveloppe.clone(), self.cle_rechiffrage.clone(), chaine_pem, clecert_pem,
    //         ca_pem, enveloppe_ca
    //     );
    //
    //     // let mut guard = self.certificat_maitredescles.lock().expect("lock");
    //     let mut guard = self.enveloppe_privee.lock().expect("lock");
    //     *guard = Some(Arc::new(enveloppe_privee));
    //     Ok(())
    // }

    pub fn is_ready(&self) -> bool {
        // Si on a un certificat, le rechiffreur est pret
        // let guard = self.certificat_maitredescles.lock().expect("maitredescles_volatil.is_ready lock");
        // let guard = self.enveloppe_privee.lock().expect("maitredescles_volatil.is_ready lock");
        // guard.is_some()
        self.cle_symmetrique.lock().expect("lock").is_some()
    }

    pub fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {
        // let guard = self.enveloppe_privee.lock().expect("maitredescles_volatil.is_ready lock");
        // match guard.as_ref() {
        //     Some(e) => Some(e.clone()),
        //     None => None
        // }
        self.enveloppe_privee.clone()
    }

    pub fn generer_cle_symmetrique(&self) -> Result<(), Box<dyn Error>> {
        // Generer une cle secrete 32 bytes pour chiffrage symmetrique
        let mut guard = self.cle_symmetrique.lock().expect("lock");
        *guard = Some(CleSecrete::generer());
        Ok(())
    }

    pub fn get_cle_symmetrique_chiffree(&self, cle_publique: &PKey<Public>) -> Result<String, Box<dyn Error>> {
        // Conserver versions asymmetriques de la cle privee
        match self.cle_symmetrique.lock().expect("lock").as_ref() {
            Some(inner) => {
                let cle_symmetrique = &inner.0[..];
                let cle_chiffree = chiffrer_asymmetrique_ed25519(
                    cle_symmetrique, cle_publique)?;
                Ok(multibase::encode(Base::Base64, &cle_chiffree[..]))
            },
            None => Err(format!("maitredescles_volatil.get_cle_symmetrique_chiffree Cle symmetrique non initialisee"))?
        }
    }

    pub fn set_cle_symmetrique<S>(&self, cle: S) -> Result<(), Box<dyn Error>>
        where S: AsRef<str>
    {
        let cle = cle.as_ref();
        let enveloppe_privee = self.enveloppe_privee.as_ref();
        let cle_bytes = multibase::decode(cle)?;
        let cle_secrete = dechiffrer_asymmetrique_ed25519(&cle_bytes.1[..], enveloppe_privee.cle_privee())?;
        let mut guard = self.cle_symmetrique.lock().expect("lock");
        *guard = Some(cle_secrete);

        Ok(())
    }
}
