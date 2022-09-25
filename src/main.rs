use std::{time::SystemTime};

use chrono::{DateTime, Utc, Timelike, TimeZone};

use prost::Message;
use prost_types::Timestamp;

use token::{Identity, Payload, Session};
use token::Signature as TokenSignature;

pub mod token {
    include!(concat!(env!("OUT_DIR"), "/auth.token.rs"));
}

fn main() {
    // let now = Utc::now();
    // let expires = now + Duration::seconds(30);
    // let session_expires = now + Duration::minutes(15);

    let expires = Utc.timestamp(1664137640, 0);
    let session_expires = Utc.timestamp(1664148000, 0);
    let mut token = AuthToken::from(1234, 23, expires).with_session(12, session_expires);

    let signed = token.sign(2089961141, "MFECAQEwBQYDK2VwBCIEIMSgRczjQCsTWeWBbJ3epX6/3Lp06m79CdLKHyoC2m9rgSEAcV1F+dSUbwGWvFBF9af+DByvftCXcjkxsTHi1JrpWK4=");

    println!("Signed: {}", signed);
}

pub trait SignToken {
    fn sign(&mut self, key_id: u32, key: &str) -> String;
}

#[derive(Debug)]
pub struct AuthToken {
    pub user_id: u64,
    pub org_id: u64,
    pub session_id: Option<u64>,
    pub session_expires: Option<DateTime<Utc>>,
    pub metadata: TokenInfo,
}

impl AuthToken {
    fn from(user_id: u64, org_id: u64, expires: DateTime<Utc>) -> Self {
        let expires_at = expires.with_nanosecond(0).unwrap();
        Self {
            user_id,
            org_id,
            session_id: None,
            session_expires: None,
            metadata: TokenInfo::from(expires_at),
        }
    }

    fn with_session(self, session_id: u64, session_expires: DateTime<Utc>) -> Self {
        Self {
            session_id: Some(session_id),
            session_expires: session_expires.with_nanosecond(0),
            ..self
        }
    }
}

impl From<&mut AuthToken> for Payload {
    fn from(token: &mut AuthToken) -> Self {
        let mut payload = Payload::default();
        payload.session = token.session_id.map(|id| {
            let mut session = Session::default();
            session.id = id as i64;
            session.expires = token
                .session_expires
                .map(|expire| Timestamp::from(SystemTime::from(expire)));

            session
        });
        payload.identity = {
            let mut identity = Identity::default();
            identity.user_id = token.user_id as i64;
            identity.workspace_id = token.org_id as i64;
            Some(identity)
        };
        payload.expires = Some(Timestamp::from(SystemTime::from(token.metadata.expires)));
        payload.signature = {
            let mut sign = TokenSignature::default();
            sign.issuer = token.metadata.issuer_id as i32;
            sign.key_id = token.metadata.key_id.unwrap() as i32;
            sign.version = token.metadata.version as i32;

            Some(sign)
        };

        payload
    }
}

use ed25519_dalek::{ExpandedSecretKey, SecretKey, PublicKey, Signature};

// TODO: How to make different implementations for different encryption algs? 
impl SignToken for AuthToken {

    fn sign(&mut self, key_id: u32, key: &str) -> String {
        self.metadata.set_key_id(key_id);

        let version = self.metadata.version;
        let payload = Payload::from(self);
        let payload_bytes = payload.encode_to_vec();

        println!("PB: {:?}", payload);

        // TODO: This secret key is 32-bytes long and we can't use the extracted ones from java directly.
        // because, in java, they are stored with ASN.1 encoding :/
        // https://www.baeldung.com/java-keystore-convert-to-pem-format
        // Verify with openssl:
        //    openssl pkcs12 -in keypair.p12 -out keypair.pem
        //    openssl pkey -in keypair.pem -text  # list key pair bytes in hex
        //    openssl pkey -in keypair.pem -outform DER | tail -c +17 | openssl base64  # extract private key bytes
        //    openssl pkey -in keypair.pem -outform DER -pubout | tail -c +13 | openssl base64  # extract public key bytes
        // Maybe it's better to have openssl decode PEM with a create?
        let secret_key = {
            let key_bytes = base64::decode(key).expect("Can't read sign key");
            println!("Key len: {}", key_bytes.len());
            let secret = SecretKey::from_bytes(&key_bytes[..]).expect("Not a valid secret key");
            ExpandedSecretKey::from(&secret)
        };
        let public_key = {
            // TODO: BouncyCastle generates this somehow... It might not be the actual public key - although I'm not sure
            PublicKey::from_bytes(b"").expect("Can't read public key")
        };
        let signed = secret_key.sign(payload.encode_to_vec().as_ref(), &public_key);
        
        // Payload bytes are the same :)
        println!("Bytes: {}", base64::encode(&payload_bytes));

        // TODO: Sign an verify
        format!("{}.{}.{}", version, base64::encode(payload_bytes), base64::encode(signed.to_bytes()))
    }
}

#[derive(Debug)]
pub struct TokenInfo {
    pub version: u32,
    pub expires: DateTime<Utc>,
    pub issuer_id: u32,
    pub key_id: Option<u32>,
}

impl TokenInfo {
    const V1: u32 = 1;

    const ISSUER_SELF: u32 = 0;

    fn from(expires: DateTime<Utc>) -> Self {
        Self {
            version: TokenInfo::V1,
            issuer_id: TokenInfo::ISSUER_SELF,
            key_id: None,
            expires,
        }
    }

    fn set_key_id(&mut self, key_id: u32) {
        self.key_id = Some(key_id)
    }
}
