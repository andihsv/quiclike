use std::io::Read;

use once_cell::sync::Lazy;

use super::cipher_state;
use crate::{crypto::{cipher, hash}, states::cipher_state::CipherState};

// static PROTOCOL_NAME: &str = "Noise_IKfallback+psk3_25519_ChaChaPoly_BLAKE2b";
static PROTOCOL_NAME: Lazy<anyctx::AnyCtx<&str>> = Lazy::new(|| {
    anyctx::AnyCtx::new("Noise_IKfallback+psk3_25519_ChaChaPoly_BLAKE2b")
});

/// [DOC]: https://noiseprotocol.org/noise.html#the-symmetricstate-object
pub struct SymmetricState<C: cipher::Cipher, H: hash::Hash> {
    cipher_state: cipher_state::CipherState<C>,
    hash: H,
    ck: [u8; 64],
    h: [u8; 64],
}

impl<C: cipher::Cipher, H: hash::Hash> SymmetricState<C, H> {
    pub fn new(cipher_state: CipherState<C>, hash: H) -> Self {
        SymmetricState { cipher_state, hash, ck: [0u8; 64], h: [0u8; 64] }
    }

    pub fn init(&mut self, cipher: C) {
        // let len = rand::rng().random_range(1..=32);
        let protocol_name = PROTOCOL_NAME.get(|ctx| {
            let mut protocol_name = ctx.init().as_bytes().to_vec();
            protocol_name.resize(64, 0);
            protocol_name
        });
        // let mut protocol_name = "Noise_XXfallback+psk3_25519_ChaChaPoly_BLAKE2b".as_bytes().to_vec();
        // protocol_name.resize(64, 0);
        self.h = self.hash.hash(protocol_name.as_slice());
        self.ck = self.h;
        self.cipher_state.init(cipher, [0u8; 32]);
    }

    pub fn mix_key(&mut self, input: &[u8], cipher: C) {
        if let (Some(ck), Some(temp_k), _) = self.hash.hkdf(self.ck, input, 2) {
            self.ck = ck;
            let mut temp = [0u8; 32];
            temp_k.take(32).read_exact(&mut temp).expect("Unable to truncate temp key.");
            self.cipher_state.init(cipher, temp);       
        }
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        self.h = self.hash.hash(&[self.h.as_slice(), data].concat())
    }

    // To handle psk.
    pub fn mix_keyhash(&mut self, input: &[u8], cipher: C) {
        if let (Some(ck), Some(temp_h), Some(temp_k)) = self.hash.hkdf(self.ck, input, 3) {
            self.ck = ck;
            self.mix_hash(temp_h.as_slice());    
            let mut temp = [0u8; 32];
            temp_k.take(32).read_exact(&mut temp).expect("Unable to truncate temp key.");
            self.cipher_state.init(cipher, temp);
        }; 
    }
}