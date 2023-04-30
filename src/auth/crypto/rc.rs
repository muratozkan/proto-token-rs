use std::fs;

use jwt_compact::{
    alg::{Ed25519},
    Algorithm, jwk::JsonWebKey,
};

type SecretKey = <Ed25519 as Algorithm>::SigningKey;
type PublicKey = <Ed25519 as Algorithm>::VerifyingKey;

pub struct KeyPair {
    pub id: i32,
    sign_key: SecretKey,
    verify_key: PublicKey
}

impl KeyPair {
    pub fn from_jwk(name: &str) -> KeyPair {
        let jwk_str = fs::read_to_string(name)
            .expect(format!("Can't open file: {}", name).as_str());

        let jwk: JsonWebKey<'_> = serde_json::from_str(&jwk_str)
            .expect("jwk");

        println!("JWK: {:?}", &jwk);

        let verifying_key = PublicKey::try_from(&jwk)
            .expect("incompatible public key from jwk");

        let signing_key = SecretKey::try_from(&jwk)
            .expect("incompatible secret key from jwk");

        KeyPair { id: 2089961141, verify_key: verifying_key, sign_key: signing_key }
    }
}

pub fn do_sign(bytes: &Vec<u8>, key_pair: &KeyPair) -> Vec<u8> {
    let alg = Ed25519;

    let signed = alg.sign(&key_pair.sign_key, &bytes);

    signed.to_vec()
}
