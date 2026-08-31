use crate::maitredescles_commun::{RowCleCaRef, RowClePartition, RowClePartitionRef};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::{FormatChiffrage, optionformatchiffragestr};
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::SignatureDomaines;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::optionepochseconds;
use millegrilles_common_rust::chrono;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

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

