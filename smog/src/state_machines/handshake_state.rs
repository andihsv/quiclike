//! Handshake State Machine based on The Noise Protocol spec: <https://noiseprotocol.org/noise.html#the-handshakestate-object>

use crate::state_machines::symmetric_state::SymmetricState;
use colloid::dh::{ephemeral_key, static_key};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

pub struct LocalKey {
    s: (StaticSecret, PublicKey),    // Local static keypair
    e: (EphemeralSecret, PublicKey), // Local ephemeral keypair
}

impl LocalKey {
    pub fn new() -> Self {
        let s = static_key::generate_keypair();
        let e = ephemeral_key::generate_keypair();
        Self { s, e }
    }

    pub fn set_s(&mut self, s: StaticSecret) {
        let pub_s = PublicKey::from(&s);
        self.s = (s, pub_s);
    }

    pub fn set_e(&mut self, e: EphemeralSecret) {
        let pub_e = PublicKey::from(&e);
        self.e = (e, pub_e);
    }
}

pub struct RemoteKey {
    s: (Option<StaticSecret>, Option<PublicKey>), // Remote static public key
    e: (Option<EphemeralSecret>, Option<PublicKey>), // Remote ephemeral public key
}

impl RemoteKey {
    pub fn new(s: Option<StaticSecret>, e: Option<EphemeralSecret>) -> Self {
        Self {
            s: (s, None),
            e: (e, None),
        }
    }

    pub fn set_s(&mut self, s: StaticSecret) {
        self.s.0 = Some(s);
    }

    pub fn set_e(&mut self, e: EphemeralSecret) {
        self.e.0 = Some(e);
    }

    pub fn has_s(&self) -> bool {
        self.s.0.is_some()
    }

    pub fn has_e(&self) -> bool {
        self.e.0.is_some()
    }
}

pub struct Keys {
    local_key: LocalKey,
    remote_key: RemoteKey,
}

impl Keys {
    pub fn new(
        locals: (StaticSecret, EphemeralSecret),
        remotes: (Option<StaticSecret>, Option<EphemeralSecret>),
    ) -> Self {
        let local_s_pub = PublicKey::from(&locals.0);
        let local_e_pub = PublicKey::from(&locals.1);
        Self {
            local_key: LocalKey {
                s: (locals.0, local_s_pub),
                e: (locals.1, local_e_pub),
            },
            remote_key: RemoteKey {
                s: (remotes.0, None),
                e: (remotes.1, None),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tokens {
    // SND/RCVD
    E, // Ephemeral Public Key
    S, // Static Public Key
    // DH Operations.
    Ee, // e & e.
    Es, // e & s.
    Se, // s & e.
    Ss, // s & s.
    // Pre-shared symmetric key.
    Psk(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagePattern(Vec<Tokens>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PubKey {
    Static,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreMessagePattern {
    pub responder_static: Option<PubKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakePattern {
    name: &'static str,
    pre: PreMessagePattern,
    messages: Vec<(bool, MessagePattern)>,
}

pub struct HandshakeState {
    symmetric_state: SymmetricState,
    keys: Keys,
    initiator: bool,
    message_pattern: MessagePattern,
}

impl HandshakeState {
    pub fn init(handshake_pattern: HandshakePattern, initiator: bool, prologue: &[u8], keys: Keys) {
    }
}
