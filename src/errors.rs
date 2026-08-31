use millegrilles_common_rust::error::Error;

#[derive(Debug)]
pub struct ErrorPermissionRefusee {
    pub code: usize,
    pub err: String,
}

pub enum ErreurPermissionRechiffrage { Refuse(ErrorPermissionRefusee), Error(Error) }

impl<E> From<E> for ErreurPermissionRechiffrage where E: std::error::Error {
    fn from(value: E) -> Self {
        let err = Error::String(format!("ErreurPermissionRechiffrage {:?}", value));
        Self::Error(err)
    }
}