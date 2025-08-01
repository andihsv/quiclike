// Handshake Pattern Derivation
pub mod hspn_der;
pub mod fallback;
pub mod crypto;
pub mod states;
/// QUIC Version Number: 0xf0f0f2f0
#[allow(dead_code)]
const QUIC_VERSION: u32 = 0xf0f0f2f0;

