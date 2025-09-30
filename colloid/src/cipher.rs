use chacha12_blake3::ChaCha12Blake3;

pub struct Cipher {
    pub inner: ChaCha12Blake3,
}

impl Cipher {
    pub fn new(k: [u8; 32]) -> Self {
        Self { inner: ChaCha12Blake3::new(k) }
    }

    pub fn encrypt(&self, nonce: [u8; 32], ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        self.inner.encrypt(&nonce, plaintext, ad) 
    }

    pub fn decrypt(&self, nonce: [u8; 32], ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, chacha12_blake3::Error> {
        self.inner.decrypt(&nonce, ciphertext, ad)
    }

    pub fn rekey(&mut self, k: [u8; 32]) {
        self.inner = Cipher::new(k).inner;
    }
}
