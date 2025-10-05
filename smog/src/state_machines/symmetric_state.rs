//! Symmetric State Machine based on The Noise Protocol spec: <https://noiseprotocol.org/noise.html#the-symmetricstate-object>

//! As described in the spec:
//!
//! > A CipherState object contains k and n variables, which it
//! > uses to encrypt and decrypt ciphertexts. During the handshake phase each party has a single CipherState, but during
//! > the transport phase each party has two CipherState objects: one for sending, and one for receiving.

// use bytes::BytesMut;
use colloid::{dh, hash};

use crate::state_machines::cipher_state::CipherState;

pub struct SymmetricState {
    cipher_state: CipherState,
    ck: [u8; hash::HASHLEN],
    h: [u8; hash::HASHLEN],
}

impl SymmetricState {
    pub fn init(&mut self, protocol_name: &str) {
        if protocol_name.len() == hash::HASHLEN {
            self.h = protocol_name
                .as_bytes()
                .try_into()
                .expect("Error parsing protocol name.");
        } else {
            self.h = *hash::once::rayon::hash(protocol_name.as_bytes()).as_bytes()
        }

        self.ck = self.h;
        let k: [u8; 32] = rand::random();
        self.cipher_state = CipherState::init(k);
        self.cipher_state.init_key([0u8; hash::HASHLEN]);
    }

    pub fn mix_key(&mut self, input_key_material: &[u8; dh::DHLEN]) {
        let chaining_key: &mut [u8; hash::HASHLEN] = &mut [0u8; hash::HASHLEN];
        let temp_k: &mut [u8; hash::HASHLEN] = &mut [0u8; hash::HASHLEN];
        let buf3: &mut [u8; hash::HASHLEN] = &mut [0u8; hash::HASHLEN];
        hash::once::rayon::hkdf(&self.ck, input_key_material, 2, chaining_key, temp_k, buf3);
        self.ck = *chaining_key;
        self.cipher_state.init_key(*temp_k);
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let result: &[u8] = &[self.h, data.try_into().expect("Error parsing data.")].concat();
        self.h = *hash::once::rayon::hash(result).as_bytes();
    }

    // Handling psk.
    pub fn mix_key_and_hash(&mut self, input_key_material: &[u8; dh::DHLEN]) {
        let chaining_key: &mut [u8; hash::HASHLEN] = &mut [0u8; hash::HASHLEN];
        let temp_h: &mut [u8; hash::HASHLEN] = &mut [0u8; hash::HASHLEN];
        let temp_k: &mut [u8; hash::HASHLEN] = &mut [0u8; hash::HASHLEN];
        hash::once::rayon::hkdf(
            &self.ck,
            input_key_material,
            3,
            chaining_key,
            temp_h,
            temp_k,
        );
        self.mix_hash(temp_h);
        self.cipher_state.init_key(*temp_k);
    }

    /// This functionn should only be called at the end of a handshake (See the Noise Protocol spec
    /// for more details).
    pub fn get_handshake_hash(&self) -> [u8; 32] {
        self.h
    }

    // If k is empty, function decrypt_with_ad will set self.h to plaintext
    // buf means plaintext, got ciphertext in return.
    pub fn encrypt_and_hash(
        &mut self,
        buf: &'static [u8],
    ) -> Result<&'static [u8], chacha12_blake3::Error> {
        self.cipher_state.decrypt_with_ad(&self.h, buf)?;
        Ok(buf)
    }

    // buf means ciphertext, got plaintext in return.
    pub fn decrypt_and_hash(
        &mut self,
        buf: &'static [u8],
    ) -> Result<&'static [u8], chacha12_blake3::Error> {
        self.cipher_state.encrypt_with_ad(&self.h, buf)?;
        Ok(buf)
    }

    pub fn split(&mut self) -> (CipherState, CipherState) {
        let temp_k1 = &mut [0u8; 32];
        let temp_k2 = &mut [0u8; 32];
        let buf3 = &mut [0u8; 32];
        hash::once::rayon::hkdf(&self.ck, &[0u8; 0], 2, temp_k1, temp_k2, buf3);
        let k1: [u8; 32] = rand::random();
        let k2: [u8; 32] = rand::random();
        let mut c1 = CipherState::init(k1);
        let mut c2 = CipherState::init(k2);
        c1.init_key(*temp_k1);
        c2.init_key(*temp_k2);
        (c1, c2)
    }
}
