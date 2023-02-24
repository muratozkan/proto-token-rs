pub mod crypto;
pub mod serialize;

use chrono::{DateTime, Timelike, Utc};

pub use self::crypto::KeyPair;
pub use self::crypto::do_sign;

#[derive(Debug)]
pub struct TokenClaims {
    pub user_id: u64,
    pub org_id: u64,
    pub session_id: u64
}

#[derive(Debug)]
pub struct RawToken {
    pub claims: TokenClaims,
    pub expires: DateTime<Utc>,
    pub issuer_id: i32
}

#[derive(Debug)]
pub(crate) struct ToSignToken {
    pub claims: TokenClaims,
    pub version: u32,
    pub expires: DateTime<Utc>,
    pub issuer_id: u32,
    pub key_id: i32
}

#[derive(Debug)]
pub struct SignedToken {
    pub claims: TokenClaims,
    pub version: u32,
    pub expires: DateTime<Utc>,
    pub issuer_id: u32,
    pub token: String
}

fn to_encoded_token(version: u32, bytes: Vec<u8>, sign_bytes: Vec<u8>) -> String {
        version.to_string().to_owned() +
        "." +
        &base64_url::encode(&bytes) + 
        "." +
        &base64_url::encode(&sign_bytes)
}

pub trait TokenSigner {
    fn sign(&self, raw_token: RawToken, key_pair: &KeyPair) -> SignedToken;
}

pub struct TokenV1Signer{}

impl TokenSigner for TokenV1Signer {
    fn sign(&self, raw_token: RawToken, key_pair: &KeyPair) -> SignedToken {
        let to_sign = ToSignToken {
            claims: raw_token.claims,
            version: 1,
            expires: raw_token.expires.with_nanosecond(0).unwrap(),
            issuer_id: 0,
            key_id: key_pair.id
        };
        let bytes = serialize::serialize_token(&to_sign);
        let sign_bytes = do_sign(&bytes, key_pair);
        let token = to_encoded_token(1, bytes, sign_bytes);
        SignedToken {
            token, 
            claims: to_sign.claims,
            version: to_sign.version,
            expires: to_sign.expires,
            issuer_id: to_sign.issuer_id
        }
    }
}