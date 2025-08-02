/// [DOC]: https://noiseprotocol.org/noise.html#dh-functions
pub trait DH {
    type Secret; // Type for Secret Key.
    type Public; // Type for Public Key.
    type Shared; // Type for Shared Key.
    fn generate_keypair() -> (Self::Secret, Self::Public);
    fn dh(keypair: Self::Secret, public_key: Self::Public) -> Self::Shared;
}
