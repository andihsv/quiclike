
/// [DOC]: https://noiseprotocol.org/noise.html#hash-functions
pub trait Hash {
    type Hash; // Usually [u8; 64] or type 'Hash'
    type HMAC; // usually [u8; 32]
    fn hash(input: &[u8]) -> Self::Hash;
    fn hmac_hash(k: Self::Hash, data: &[u8]) -> Self::HMAC;
    fn hkdf(ck: Self::HMAC,input: Self::Hash, num: u8) -> (Option<Self::HMAC>, Option<Self::HMAC>, Option<Self::HMAC>);
}