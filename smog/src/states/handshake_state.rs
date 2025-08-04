use crate::{
    crypto::{cipher::Cipher, dh::DH, hash::Hash},
    hspn_der::Role,
};

use super::symmetric_state;

// /// [DOC]: https://noiseprotocol.org/noise.html#the-handshakestate-object
// pub struct HandshakeState<C: Cipher, H: Hash, D: DH> {
//     dh: D,
//     sym_state: symmetric_state::SymmetricState<C, H>,
//     role: Role,
//     message_pattern:
// }
