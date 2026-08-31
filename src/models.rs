use crate::external::crypto::SymmetricEncryptionHandler;
use crate::maitredescles_commun::RowClePartitionRef;
use millegrilles_common_rust::{bson, chrono};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::{FormatChiffrage, optionformatchiffragestr};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleSecreteSerialisee;
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::{SignatureDomaines, SignatureDomainesRef, SignatureDomainesVersion};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::optionepochseconds;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use bson::serde_helpers::datetime::FromChrono04DateTime;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteClesNonDechiffrable {
    pub limite: Option<u64>,
    // pub page: Option<u64>,
    pub skip: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "optionepochseconds")]
    pub date_creation_min: Option<chrono::DateTime<Utc>>,
    pub exclude_hachage_bytes: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecupererCleCa {
    pub signature: SignatureDomaines,
    pub cle_id: String,

    // Valeurs dechiffrage contenu V1 (obsolete)
    #[serde(default, skip_serializing_if="Option::is_none", with="optionformatchiffragestr")]
    pub format: Option<FormatChiffrage>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub iv: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub header: Option<String>,
}

impl<'a> TryFrom<RowClePartitionRef<'a>> for RecupererCleCa {
    type Error = Error;
    fn try_from(value: RowClePartitionRef<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            signature: value.signature.try_into()?,
            cle_id: value.cle_id.to_string(),
            format: value.format,
            iv: match value.iv { Some(inner) => Some(inner.to_string()), None => None },
            tag: match value.tag { Some(inner) => Some(inner.to_string()), None => None },
            header: match value.header { Some(inner) => Some(inner.to_string()), None => None },
        })
    }
}

impl<'a> TryFrom<RowCleCaRef<'a>> for RecupererCleCa {
    type Error = Error;
    fn try_from(value: RowCleCaRef<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            signature: value.signature.try_into()?,
            cle_id: value.cle_id.to_string(),
            format: value.format,
            iv: match value.iv { Some(inner) => Some(inner.to_string()), None => None },
            tag: match value.tag { Some(inner) => Some(inner.to_string()), None => None },
            header: match value.header { Some(inner) => Some(inner.to_string()), None => None },
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorMessage {
    pub ok: bool,
    pub code: Option<u16>,
    pub err: Option<String>,
}

impl ErrorMessage {
    pub fn ok() -> Self { Self { ok: true, code: None, err: None } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyDecryptionRefused {
    pub ok: bool,
    pub code: Option<usize>,
    pub err: Option<String>,
    pub acces: Option<String>,
}

pub struct CleInterneChiffree {
    pub cle: String,
    pub nonce: String,
}

impl TryFrom<RowClePartition> for CleInterneChiffree {
    type Error = Error;

    fn try_from(value: RowClePartition) -> Result<Self, Self::Error> {
        match value.cle_symmetrique.as_ref() {
            Some(cle) => match value.nonce_symmetrique.as_ref() {
                Some(nonce) => Ok(CleInterneChiffree { cle: cle.clone(), nonce: nonce.clone() }),
                None => Err(Error::Str("TryFrom<RowClePartition> cle_symmetrique manquante"))
            },
            None => Err(Error::Str("TryFrom<RowClePartition> nonce manquant"))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RowClePartition {
    // Identite
    pub cle_id: String,
    pub signature: SignatureDomaines,

    pub cle_symmetrique: Option<String>,
    pub nonce_symmetrique: Option<String>,

    // Information de dechiffrage contenu (utilise avec signature version 0)
    #[serde(default, with="optionformatchiffragestr", skip_serializing_if="Option::is_none")]
    pub format: Option<FormatChiffrage>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub iv: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub header: Option<String>,

    pub confirmation_ca: Option<bool>,
}

impl RowClePartition {

    pub fn to_cle_secrete_serialisee(self, rechiffrage_handler: &SymmetricEncryptionHandler)
                                     -> Result<CleSecreteSerialisee, Error>
    {
        let cle_interne = match self.cle_symmetrique.as_ref() {
            Some(cle) => match self.nonce_symmetrique.as_ref() {
                Some(nonce) => Ok(CleInterneChiffree { cle: cle.clone(), nonce: nonce.clone() }),
                None => Err(Error::Str("to_cle_secrete_serializee cle_symmetrique manquante"))
            },
            None => Err(Error::Str("to_cle_secrete_serializee nonce manquant"))
        }?;

        let cle_secrete = rechiffrage_handler.decrypt(cle_interne)?;

        let cle_id = self.cle_id.clone();

        // Retirer le 'm' multibase du iv/header pour convertir en format nonce
        let nonce = match self.iv {
            Some(inner) => Some(inner.as_str()[1..].to_string()),
            None => match self.header {
                Some(inner) => Some(inner.as_str()[1..].to_string()),
                None => None
            }
        };

        let verification = match self.tag {
            Some(inner) => Some(inner),
            None => match self.signature.version {
                SignatureDomainesVersion::NonSigne => Some(self.signature.signature.to_string()),
                _ => None
            }
        };

        Ok(CleSecreteSerialisee::from_cle_secrete(cle_secrete, Some(cle_id), self.format, nonce, verification)?)
    }

}

#[derive(Serialize, Deserialize)]
pub struct RowCleCaRef<'a> {
    pub cle_id: &'a str,
    pub signature: SignatureDomainesRef<'a>,
    //pub dirty: Option<bool>,
    pub non_dechiffrable: Option<bool>,
    #[serde(with = "FromChrono04DateTime")]
    pub date_creation: DateTime<Utc>,

    // Information de dechiffrage contenu (utilise avec signature version 0)
    #[serde(default, skip_serializing_if = "Option::is_none", with = "optionformatchiffragestr")]
    pub format: Option<FormatChiffrage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<&'a str>,

}

/// Transaction de sauvegarde de cle CA version 2.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionCleV2 {
    pub signature: SignatureDomaines
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentCleRechiffrage {
    #[serde(rename="type")]
    pub type_: String,
    pub instance_id: String,
    pub fingerprint: Option<String>,
    pub cle: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymmetricKeyDecryptionRequest {
    pub cle_symmetrique_ca: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UndecipherableKeyCountResponse {
    pub compte: usize,
}

#[derive(Serialize)]
pub struct ReponseClesNonDechiffrables {
    pub cles: Vec<RecupererCleCa>,
    #[serde(default, skip_serializing_if="Option::is_none", with="optionepochseconds")]
    pub date_creation_max: Option<DateTime<Utc>>,
    pub idx: u64,
}