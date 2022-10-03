use auth::KeyPair;
use chrono::{TimeZone, Utc};

use crate::auth::AuthToken;

mod auth;

fn main() {
    // let now = Utc::now();
    // let expires = now + Duration::seconds(30);
    // let session_expires = now + Duration::minutes(15);

    // let store_bytes = include_bytes!("../keypair.p12");

    let expires = Utc.timestamp(1664137640, 0);
    let session_expires = Utc.timestamp(1664148000, 0);
    let mut token = AuthToken::from(1234, 23, expires).with_session(12, session_expires);

    // let key_id = 2089961141;
    let key_pair = KeyPair::from_file("../keypair.p12");

    let signed = token.sign(&key_pair);

    // println!("Signed: {}", signed);
}
