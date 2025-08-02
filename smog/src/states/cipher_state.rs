use crate::crypto::cipher;

/// [DOC]: https://noiseprotocol.org/noise.html#the-cipherstate-object
pub struct CipherState<C: cipher::Cipher> {
    pub cipher: C, // Because Smog is a framework, not a implementation, we still don't know what cipher function to use.
    k: [u8; 32],
    n: u64,
}

impl<C: cipher::Cipher> CipherState<C> {
    pub fn new(cipher: C) -> Self {
        CipherState::<C> {
            cipher,
            k: [0u8; 32],
            n: 0,
        }
    }

    pub fn init(&self, cipher: C, k: [u8; 32]) -> Self {
        CipherState::<C> { cipher, k, n: 0 }
    }

    pub fn has_key(&self) -> bool {
        !self.k.is_empty()
    }

    pub fn set_nonce(&mut self, n: u64) {
        self.n = n;
    }

    pub fn encrypt_with_ad(&self, ad: &[u8], plain_text: &[u8]) -> Vec<u8> {
        // C::encrypt(self.k, self.n + 1, ad, plain_text)
        if !self.has_key() {
            plain_text.to_vec()
        } else {
            self.cipher.encrypt(self.k, self.n + 1, ad, plain_text)
        }
    }

    pub fn decrypt_with_ad(&self, ad: &[u8], cipher_text: &[u8]) -> Vec<u8> {
        // C::decrypt(self.k, self.n + 1, ad, cipher_text).expect("Decryption failed.")
        if !self.has_key() {
            cipher_text.to_vec()
        } else {
            self.cipher
                .decrypt(self.k, self.n, ad, cipher_text)
                .expect("Failed to decrypt.")
        }
    }

    pub fn rekey(&mut self) {
        self.k = self.cipher.rekey(self.k, self.n);
    }
}
