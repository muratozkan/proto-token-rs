use std::time::SystemTime;

use prost::Message;
use token::Signature as TokenSignature;
use token::{Identity, Payload, Session};
use prost_types::Timestamp;

use super::ToSignToken;

mod token {
    include!(concat!(env!("OUT_DIR"), "/auth.token.rs"));
}

impl From<&ToSignToken> for Payload {
    fn from(token: &ToSignToken) -> Self {
        let mut payload = Payload::default();
        payload.session = {
            let mut session = Session::default();
            session.id = token.claims.session_id as i64;
            Some(session)
        };
        payload.identity = {
            let mut identity = Identity::default();
            identity.user_id = token.claims.user_id as i64;
            identity.workspace_id = token.claims.org_id as i64;
            Some(identity)
        };
        payload.expires = Some(Timestamp::from(SystemTime::from(token.expires)));
        payload.signature = {
            let mut sign = TokenSignature::default();
            sign.issuer = token.issuer_id as i32;
            sign.key_id = token.key_id as i32;
            sign.version = token.version as i32;

            Some(sign)
        };

        payload
    }
}

pub(crate) fn serialize_token(token: &ToSignToken) -> Vec<u8> {
    Payload::from(token).encode_to_vec()
}
