//! Handshake State Machine based on The Noise Protocol spec: <https://noiseprotocol.org/noise.html#the-handshakestate-object>

use crate::state_machines::symmetric_state::SymmetricState;

pub struct LocalKey {
    s: ,
    e: ,
}

pub struct RemoteKey {
    s: ,
    e: ,
}

pub struct Keys {
    local_key: LocalKey,
    remote_key: RemoteKey,
}

pub enum Tokens {
    E,
    S,
    Ee,
    Es,
    Se,
    Ss,
    Psk(u8),
}

pub struct Pattern(Vec<Tokens>);

pub struct HandshakeState {
    symmetric_state: SymmetricState,
    keys: Keys,
    initiator: bool,
    message_patterns: Pattern,
}
