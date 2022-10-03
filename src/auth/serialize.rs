use std::time::SystemTime;

use prost::Message;
use token::Signature as TokenSignature;
use token::{Identity, Payload, Session};
use prost_types::Timestamp;

use super::AuthToken;

mod token {
    include!(concat!(env!("OUT_DIR"), "/auth.token.rs"));
}

impl From<&AuthToken> for Payload {
    fn from(token: &AuthToken) -> Self {
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

pub(crate) fn serialize_token(token: &AuthToken) -> Vec<u8> {
    Payload::from(token).encode_to_vec()
}
