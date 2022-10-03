use chrono::{DateTime, Timelike, Utc};

pub use self::crypto::KeyPair;
use self::{serialize::serialize_token, crypto::do_sign};

mod crypto;
mod serialize;

#[derive(Debug)]
pub struct AuthToken {
    pub user_id: u64,
    pub org_id: u64,
    pub session_id: Option<u64>,
    pub session_expires: Option<DateTime<Utc>>,
    pub metadata: TokenInfo,
}

#[derive(Debug)]
pub struct TokenInfo {
    pub version: u32,
    pub expires: DateTime<Utc>,
    pub issuer_id: u32,
    pub key_id: Option<i32>,
}

#[derive(Debug)]
pub struct SignedToken {
    version: u32,
    pub token: AuthToken,
    pub signature: String,
}

impl AuthToken {
    pub fn from(user_id: u64, org_id: u64, expires: DateTime<Utc>) -> Self {
        let expires_at = expires.with_nanosecond(0).unwrap();
        Self {
            user_id,
            org_id,
            session_id: None,
            session_expires: None,
            metadata: TokenInfo::from(expires_at),
        }
    }

    pub fn with_session(self, session_id: u64, session_expires: DateTime<Utc>) -> Self {
        Self {
            session_id: Some(session_id),
            session_expires: session_expires.with_nanosecond(0),
            ..self
        }
    }

    pub fn sign(mut self, key_pair: &KeyPair) -> SignedToken {
        self.metadata.key_id = Some(key_pair.id);
        let bytes = serialize_token(&self);
        let sign_bytes = do_sign(&bytes, key_pair);
        let signed = format!("{}.{}.{}", self.metadata.version, base64_url::encode(&bytes), base64_url::encode(&sign_bytes));
        SignedToken {
            version: self.metadata.version,
            token: self,
            signature: signed,
        }
    }
}

impl TokenInfo {
    const V1: u32 = 1;

    const ISSUER_SELF: u32 = 0;

    pub fn from(expires: DateTime<Utc>) -> Self {
        Self {
            version: TokenInfo::V1,
            issuer_id: TokenInfo::ISSUER_SELF,
            key_id: None,
            expires,
        }
    }
}
