use crate::maitredescles_commun::{RowCleCaRef, RowClePartitionRef};
use log::{debug, error};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::common_messages::DataDechiffre;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::hachages::verifier_multihash;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::{optionformatchiffragestr, FormatChiffrage};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::millegrilles_cryptographie::maitredescles::SignatureDomaines;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::epochseconds;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::optionepochseconds;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{DechiffrageInterMillegrilleOwned, MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageMilleGrillesRef, MessageMilleGrillesRefDefault};
use millegrilles_common_rust::millegrilles_cryptographie::x25519::{dechiffrer_asymmetrique_ed25519, CleSecreteX25519};
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_common_rust::{chrono, hex, multibase};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::from_utf8;

#[derive(Clone, Debug, Deserialize)]
pub struct RequeteVerifierPreuve {
    pub fingerprint: String,                    // fingerprint inclues dans la preuve
    pub preuves: HashMap<String, PreuveCle>,    // fuuid, preuve
}

#[derive(Clone, Debug, Deserialize)]
pub struct PreuveCle {
    #[serde(with = "epochseconds")]
    pub date: DateTime<Utc>,
    pub preuve: String,
}

impl PreuveCle {
    pub fn verifier_preuve<S>(&self, fingerprint: S, cle: &CleSecreteX25519) -> Result<bool, String>
        where S: AsRef<str>
    {
        let fingerprint = fingerprint.as_ref();
        let mut buffer = [0u8; 72];

        // let fingerprint_bytes: Vec<u8> = match multibase::decode(fingerprint) {
        let fingerprint_bytes: Vec<u8> = match hex::decode(fingerprint) {
            Ok(inner) => inner,
            Err(e) => Err(format!("common_messages.verifier_preuve Erreur decoder fingerprint : {:?}", e))?
        };
        debug!("Verifier preuve fingerprint bytes {:?}", fingerprint_bytes);

        let datetime_preuve = &self.date;
        let datetime_i64 = datetime_preuve.timestamp();
        let datetime_bytes = datetime_i64.to_le_bytes();
        debug!("Datetime bytes {:?}", datetime_bytes);

        // Copier date
        buffer[0..8].copy_from_slice(&datetime_bytes[0..8]);

        // Copier fingerprint
        buffer[8..40].copy_from_slice(&fingerprint_bytes[0..32]);

        // Copier cle secrete
        buffer[40..72].copy_from_slice(&cle.0);

        // Hachage avec blake2s
        let valide = verifier_multihash(self.preuve.as_str(), &buffer).unwrap_or_else(|e| {
            error!("common_messages.verifier_preuve Erreur verifier_multihash : {:?}", e);
            false
        });

        Ok(valide)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageReponseChiffree {
    pub contenu: Vec<u8>,  // Contenu compresse/chiffre
    pub dechiffrage: DechiffrageInterMillegrilleOwned,
}

impl TryFrom<MessageMilleGrillesRefDefault<'_>> for MessageReponseChiffree {
    type Error = Error;

    fn try_from<'a>(mut value: MessageMilleGrillesRefDefault<'a>) -> Result<Self, Self::Error> {
        let dechiffrage = match value.dechiffrage.take() {
            Some(inner) => inner,
            None => Err(Error::Str("commande_rechiffrer_batch Information de dechiffrage absente"))?
        };
        todo!("Fix me - deconge en base64, pas en multibase");
        Ok(Self {
            contenu: multibase::decode(value.contenu_escaped)?.1,
            dechiffrage: (&dechiffrage).into(),
        })
    }
}

impl MessageReponseChiffree {
    pub fn new<M,S>(middleware: &M, contenu: S, certificat_demandeur: &EnveloppeCertificat)
        -> Result<Self, Error>
        where M: CleChiffrageHandler, S: Serialize
    {
        todo!("fix me")
        // let (data_chiffre, dechiffrage) = chiffrer_data(middleware, contenu)?;
        // Ok(Self { contenu: data_chiffre.data_chiffre, dechiffrage })
    }

    pub fn dechiffrer<M>(&self, middleware: &M)  -> Result<DataDechiffre, Error>
        where M: GenerateurMessages + CleChiffrageHandler
    {
        let enveloppe_privee = middleware.get_enveloppe_signature();
        let fingerprint_local = enveloppe_privee.fingerprint()?;
        let header = match self.dechiffrage.header.as_ref() {
            Some(inner) => inner.as_str(),
            None => Err(Error::Str("formatteur_messages.MessageReponseChiffree.dechiffrer Erreur format message, header absent"))?
        };

        let (header, cle_secrete) = match self.dechiffrage.cles.as_ref() {
            Some(inner) => match inner.get(fingerprint_local.as_str()) {
                Some(inner) => {
                    // Cle chiffree, on dechiffre
                    let cle_bytes = multibase::decode(inner)?;
                    let cle_secrete = dechiffrer_asymmetrique_ed25519(&cle_bytes.1[..], &enveloppe_privee.cle_privee)?;
                    (header, cle_secrete)
                },
                None => Err(Error::Str("formatteur_messages.MessageReponseChiffree.dechiffrer Erreur format message, dechiffrage absent"))?
            },
            None => Err(Error::Str("formatteur_messages.MessageReponseChiffree.dechiffrer Erreur format message, dechiffrage absent"))?
        };

        todo!("fix me")

        // // Dechiffrer le contenu
        // let data_chiffre = DataChiffre {
        //     ref_hachage_bytes: None,
        //     data_chiffre: self.contenu,
        //     format: FormatChiffrage::mgs4,
        //     header: Some(header.to_owned()),
        //     tag: None,
        // };
        // debug!("formatteur_messages.MessageReponseChiffree.dechiffrer Data chiffre contenu : {:?}", data_chiffre);
        //
        // let cle_dechiffre = CleDechiffree {
        //     cle: "m".to_string(),
        //     cle_secrete,
        //     domaine: "MaitreDesCles".to_string(),
        //     format: "mgs4".to_string(),
        //     hachage_bytes: "".to_string(),
        //     identificateurs_document: None,
        //     iv: None,
        //     tag: None,
        //     header: Some(header.to_owned()),
        //     // signature_identite: "".to_string(),
        // };
        //
        // debug!("formatteur_messages.MessageReponseChiffree.dechiffrer Dechiffrer data avec cle dechiffree");
        // let data_dechiffre = dechiffrer_data(cle_dechiffre, data_chiffre)?;
        // debug!("formatteur_messages.MessageReponseChiffree.dechiffrer.MessageReponseChiffree.dechiffrerfrer_batch Data dechiffre len {}", data_dechiffre.data_dechiffre.len());
        // // debug!("formatteur_messages.MessageReponseChiffree.dechiffrer Data dechiffre {:?}", String::from_utf8(data_dechiffre.data_dechiffre.clone()));
        //
        // Ok(data_dechiffre)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteClesNonDechiffrable {
    pub limite: Option<u64>,
    // pub page: Option<u64>,
    pub skip: Option<u64>,
    #[serde(default, skip_serializing_if="Option::is_none", with="optionepochseconds")]
    pub date_creation_min: Option<chrono::DateTime<Utc>>,
    pub exclude_hachage_bytes: Option<Vec<String>>
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