
/// [DOC]: https://noiseprotocol.org/noise.html#hash-functions
pub trait Hash {
    type Triple; // (Option<[u8; 64]>, Option<[u8; 64]>, Option<[u8; 64]>)
    fn hash(&self, input: &[u8]) -> [u8; 64];
    fn hmac_hash(&self, k: [u8; 64], data: &[u8]) -> [u8; 64];
    fn hkdf(&self, ck: [u8; 64],input: &[u8], num: u8) -> (Option<[u8; 64]>, Option<[u8; 64]>, Option<[u8; 64]>);
}