//! The DH mod is based on The Noise Protocol spec: https://noiseprotocol.org/noise.html#dh-functions

/// The default DH length for x25519 ecdh
pub const DHLEN: usize = 32;

pub mod ephemeral_key {
    use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
    pub fn generate_keypair() -> (EphemeralSecret, PublicKey) {
        let ephemeral_key = EphemeralSecret::random();
        let public_key = PublicKey::from(&ephemeral_key);
        (ephemeral_key, public_key)
    }

    // The ephemeral_key is the local 'e', and the public_key is the remote 're'
    pub fn dh(ephemeral_key: EphemeralSecret, public_key: PublicKey) -> SharedSecret {
        ephemeral_key.diffie_hellman(&public_key)
    }
}

// Used to generate 's'
pub mod static_key {
    use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
    pub fn generate_keypair() -> (StaticSecret, PublicKey) {
        let static_key = StaticSecret::random();
        let public_key = PublicKey::from(&static_key);
        (static_key, public_key)
    }
    // The static_key is local, and the public_key is from remote.
    pub fn dh(static_key: StaticSecret, public_key: PublicKey) -> SharedSecret {
        static_key.diffie_hellman(&public_key)
    }
}

// Suitable for The Noise Protocol.
pub mod reusable_key {
    use x25519_dalek::{PublicKey, ReusableSecret, SharedSecret};
    pub fn generate_keypair() -> (ReusableSecret, PublicKey) {
        let reusable_key = ReusableSecret::random();
        let public_key = PublicKey::from(&reusable_key);
        (reusable_key, public_key)
    }

    // The reusable_key is local, and the public_key is from remote.
    pub fn dh(reusable_key: ReusableSecret, public_key: PublicKey) -> SharedSecret {
        reusable_key.diffie_hellman(&public_key)
    }
}
