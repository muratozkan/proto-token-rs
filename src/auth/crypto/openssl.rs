use std::fs;

use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{Private, PKey};
use openssl::sign::Signer;

pub fn do_sign(bytes: &Vec<u8>, key_pair: &KeyPair) -> Vec<u8> {
    Signer::new(MessageDigest::null(), key_pair.pkey.as_ref())
            .unwrap()
            .sign_oneshot_to_vec(bytes.as_ref())
            .unwrap()
}

pub struct KeyPair {
    pub id: i32,
    pkey: PKey<Private>
}

impl KeyPair {

    pub fn from_file(name: &str) -> KeyPair {
        let store_bytes = fs::read(name)
            .expect(format!("Can't open file: {}", name).as_str());
        let parsed = Pkcs12::from_der(store_bytes.as_ref())
            .unwrap()
            .parse("default")
            .unwrap();
        KeyPair { id: 1234, pkey: parsed.pkey }
    }
}
