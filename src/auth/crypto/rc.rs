use std::fs;

pub struct KeyPair {
    pub id: i32,
}

impl KeyPair {
    pub fn from_file(name: &str) -> KeyPair {
        let store_bytes = fs::read(name)
            .expect(format!("Can't open file: {}", name).as_str());

        let parsed = p12::PFX::parse(&store_bytes)
            .expect("Problem reading P12 store");

        println!("{:?}", parsed.key_bags("default"));

        KeyPair { id: 1 }
    }
}

pub fn do_sign(_bytes: &Vec<u8>, _key_pair: &KeyPair) -> Vec<u8> {
    vec![0]
}
