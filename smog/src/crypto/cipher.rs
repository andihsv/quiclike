
/// [DOC]: https://noiseprotocol.org/noise.html#cipher-functions
pub trait Cipher {
    fn encrypt(&self, k: [u8; 32], n: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8>;
    fn decrypt(&self, k: [u8; 32], n: u64, ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>>;
    fn rekey(&self, k: [u8; 32], n: u64) -> [u8; 32];
}
