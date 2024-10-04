use millegrilles_common_rust::constantes::COMMANDE_CERT_MAITREDESCLES;

pub const DOMAINE_NOM: &str = "MaitreDesCles";
pub const NOM_COLLECTION_CONFIGURATION: &str = "MaitreDesCles/configuration";
pub const INDEX_CLES_HACHAGE_BYTES: &str = "index_hachage_bytes";
pub const INDEX_CLE_ID: &str = "index_cle_id";
//pub const INDEX_CLES_HACHAGE_BYTES_DOMAINES: &str = "index_hachage_bytes_domaines";
pub const INDEX_NON_DECHIFFRABLES: &str = "index_non_dechiffrables";
pub const NOM_Q_DECHIFFRAGE: &str = "MaitreDesCles/dechiffrage";
pub const REQUETE_SYNCHRONISER_CLES: &str = "synchroniserCles";
pub const REQUETE_DECHIFFRAGE: &str = "dechiffrage";
pub const REQUETE_DECHIFFRAGE_V2: &str = "dechiffrageV2";
pub const REQUETE_VERIFIER_PREUVE: &str = "verifierPreuve";
pub const REQUETE_TRANSFERT_CLES: &str = "transfertCles";
// pub const COMMANDE_SAUVEGARDER_CLE: &str = "sauvegarderCle";
pub const COMMANDE_CONFIRMER_CLES_SUR_CA: &str = "confirmerClesSurCa";
pub const COMMANDE_CLE_SYMMETRIQUE: &str = "cleSymmetrique";
pub const TRANSACTION_CLE: &str = "cle";
pub const TRANSACTION_CLE_V2: &str = "cleV2";
pub const CHAMP_CLE_SYMMETRIQUE: &str = "cle_symmetrique";
pub const CHAMP_NONCE_SYMMETRIQUE: &str = "nonce_symmetrique";
// pub const EVENEMENT_RESET_CLES_NON_DECHIFFRABLES: &str = "resetClesNonDechiffrables";
pub const EVENEMENT_CLES_MANQUANTES_PARTITION: &str = "clesManquantesPartition";
pub const EVENEMENT_CLE_RECUE_PARTITION: &str = "cleRecuePartition";
pub const EVENEMENT_DEMANDE_CLE_SYMMETRIQUE: &str = "demandeCleSymmetrique";
pub const COMMANDE_VERIFIER_CLE_SYMMETRIQUE: &str = "verifierCleSymmetrique";
pub const CHAMP_HACHAGE_BYTES: &str = "hachage_bytes";
pub const CHAMP_DOMAINE: &str = "domaine";
pub const CHAMP_LISTE_HACHAGE_BYTES: &str = "liste_hachage_bytes";
// pub const CHAMP_LISTE_FINGERPRINTS: &str = "liste_fingerprints";
pub const CHAMP_LISTE_CLE_REF: &str = "liste_cle_ref";
pub const CHAMP_LISTE_CLE_ID: &str = "liste_cle_id";
pub const CHAMP_NON_DECHIFFRABLE: &str = "non_dechiffrable";
pub const CHAMP_DERNIERE_PRESENCE: &str = "derniere_presence";
// pub const CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";
pub const CHAMP_CLE_ID: &str = "cle_id";
// pub const CHAMP_CLE_REF: &str = "cle_ref";
pub const CHAMP_CLES: &str = "cles";
pub const CHAMP_LISTE_CLES: &str = "liste_cles";
// pub const CHAMP_ACCES: &str = "acces";
pub const CHAMP_ACCES_REFUSE: &str = "0.refuse";
pub const CHAMP_ACCES_PERMIS: &str = "1.permis";
// pub const CHAMP_ACCES_ERREUR: &str = "2.erreur";
// pub const CHAMP_ACCES_CLE_INDECHIFFRABLE: &str = "3.indechiffrable";
pub const CHAMP_ACCES_CLE_INCONNUE: &str = "4.inconnue";

pub const REQUETE_CERTIFICAT_MAITREDESCLES: &str = COMMANDE_CERT_MAITREDESCLES;

pub const COMMANDE_RECHIFFRER_BATCH: &str = "rechiffrerBatch";

pub const INDEX_RECHIFFRAGE_PK: &str = "fingerprint_pk";
pub const INDEX_CONFIRMATION_CA: &str = "confirmation_ca";

pub const CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";
pub const CHAMP_CONFIRMATION_CA: &str = "confirmation_ca";


pub const NOM_Q_CA_TRANSACTIONS: &str = "MaitreDesCles/CA/transactions";
pub const NOM_Q_CA_VOLATILS: &str = "MaitreDesCles/CA/volatils";
pub const NOM_Q_CA_TRIGGERS: &str = "MaitreDesCles/CA/triggers";


pub const REQUETE_CLES_NON_DECHIFFRABLES: &str = "clesNonDechiffrables";
pub const REQUETE_CLES_NON_DECHIFFRABLES_V2: &str = "clesNonDechiffrablesV2";
pub const REQUETE_COMPTER_CLES_NON_DECHIFFRABLES: &str = "compterClesNonDechiffrables";
pub const COMMANDE_RESET_NON_DECHIFFRABLE: &str = "resetNonDechiffrable";
