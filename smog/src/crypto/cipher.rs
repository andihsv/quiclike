
/// [DOC]: https://noiseprotocol.org/noise.html#cipher-functions
pub trait Cipher {
    fn encrypt(k: [u8; 32], n: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8>;
    fn decrypt(k: [u8; 32], n: u64, ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>>;
    fn rekey(k: [u8; 32], n: u64) -> Vec<u8>;
}
