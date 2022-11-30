use chrono::{TimeZone, Utc};

mod auth;
use crate::auth::{TokenClaims, TokenSigner};

use self::auth::{RawToken, KeyPair, TokenV1Signer};

fn main() {
    // let now = Utc::now();
    // let expires = now + Duration::seconds(30);
    // let session_expires = now + Duration::minutes(15);

    // let store_bytes = include_bytes!("../keypair.p12");

    // let key_id = 2089961141;
    let key_pair = KeyPair::from_file("keypair.p12");
    let token = RawToken {
        claims: TokenClaims {
            user_id: 12345,
            org_id: 23,
            session_id: 3423425,
        },
        expires: Utc.timestamp(1664137640, 0),
        issuer_id: 0
    };
    let signer = TokenV1Signer { };
    let signed = signer.sign(token, &key_pair);

    println!("Signed: {}", signed.token);
}
