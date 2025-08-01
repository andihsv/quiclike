use x25519_dalek::{EphemeralSecret, PublicKey};

pub trait DH {
    fn generate_key_pair() -> (EphemeralSecret, PublicKey);
}