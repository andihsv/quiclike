
use std::{error::Error, str::FromStr};
use regex::Regex;

use crate::hspn_der::Role;

/// For Intiator (Alice): ee → se → es → ss
const INITIATOR_STEPS: &[&str; 4] = &["ee", "se", "es", "ss"];
/// For Responder (Bob): ee → es → se → ss
const RESPONDER_STEPS: &[&str; 4] = &["ee", "es", "se", "ss"];

pub enum Steps {
    Ee, Es,
    Se, Ss,
}

impl FromStr for Steps {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ee" => Ok(Self::Ee),
            "es" => Ok(Self::Es),
            "se" => Ok(Self::Se),
            "ss" => Ok(Self::Ss),
            _ => Err("Not supported DH form!")
        }
    }
}

    // Possible Patterns (Recommended): 
    // N,
    // K,
    // X,
    // NN,
    // NK,
    // NX,
    // XN,
    // XK,
    // XX,
    // KN,
    // KK,
    // KX,
    // IN,
    // IK,
    // IX,
    // XXfallback,
    // pskN

#[derive(Debug, PartialEq, Eq)]
pub enum Tokens {
    X,
    K,
    N,
    I,
    Fallback,
    Psk(u8),
}

impl Tokens {
    pub fn new(patterns: &str) -> Result<Vec<Tokens>, Box<dyn Error>> {
        // 1) Get the prefix and sufix.
        let (prefix, suffix) = patterns.split_once('+').unwrap_or((patterns, ""));

        
        // 2) Regex: Match letter groups with X/K/N/I only.
        static RE: once_cell::sync::Lazy<Regex> =
            once_cell::sync::Lazy::new(|| Regex::new(r"^[IXKxkNn]+").unwrap());
        let body = RE
            .find(prefix)
            .ok_or("invalid pattern prefix")?
            .as_str()
            .to_uppercase();

        let mut out = Vec::new();
        for ch in body.chars() {
            match ch {
                'X' => out.push(Tokens::X),
                'K' => out.push(Tokens::K),
                'N' => out.push(Tokens::N),
                'I' => out.push(Tokens::I),
                _ => unreachable!(),
            }
        }

        // 3) fallback
        if prefix.to_lowercase().ends_with("fallback") {
            out.push(Tokens::Fallback);
        }

        // 4) psk
        if let Some(num_str) = suffix.strip_prefix("psk") {
            let n: u8 = num_str.parse().map_err(|_| "invalid psk number")?;
            out.push(Tokens::Psk(n));
        }

        Ok(out)
    }
}

impl FromStr for Tokens {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "X" => Ok(Self::X),
            "K" => Ok(Self::K),
            "N" => Ok(Self::N),
            "I" => Ok(Self::I),
            "fallback" => Ok(Self::Fallback),
            "+psk0" => Ok(Self::Psk(0)),
            "+psk1" => Ok(Self::Psk(1)),
            "+psk2" => Ok(Self::Psk(2)),
            "+psk3" => Ok(Self::Psk(3)),
            _ => Err("Unsupported Handshake pattern."),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct LocalKeys {
    ls: Vec<u8>, // Local Static. 
    le: Vec<u8>, // Local Ephemeral.
    has_ls: bool,
    has_le: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RemoteKeys {
    rs: Vec<u8>, // Remote Static.
    re: Vec<u8>, // Remote Ephemeral.
    has_rs: bool,
    has_re: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Keys {
    local_keys: LocalKeys,
    remote_keys: RemoteKeys,
}

impl Keys {
    pub fn new() -> Self {
        Keys::default()
    }

    // Setters.
    // Local Operations.
    #[inline]
    pub fn set_local_ephemeral(&mut self, le: Vec<u8>) {
        self.local_keys.le = le;
    } 

    #[inline]
    pub fn set_local_static(&mut self, ls: Vec<u8>) {
        self.local_keys.ls = ls;
    }

    // Remote Operations.
    #[inline]
    pub fn set_remote_ephemeral(&mut self, re: Vec<u8>) {
        self.remote_keys.re = re;
    }

    #[inline]
    pub fn set_remote_static(&mut self, rs: Vec<u8>) {
        self.remote_keys.rs = rs;
    }

    // Set Has-keys:
    // Local keys.
    #[inline]
    pub fn set_has_local_ephemeral(&mut self) {
        self.local_keys.has_le = true;
    }

    #[inline]
    pub fn set_has_local_static(&mut self) {
        self.local_keys.has_ls = true;
    }

    #[inline]
    pub fn set_has_remote_ephemeral(&mut self) {
        self.remote_keys.has_re = true;
    }

    #[inline]
    pub fn set_has_remote_static(&mut self) {
        self.remote_keys.has_rs = true;
    }

    // Get Has-keys:
    // Local keys.
    pub fn has_local_ephemeral(&self) -> bool {
        if !self.local_keys.has_le {
            false
        } else {
            true
        }
    }

    pub fn has_local_static(&self) -> bool {
        if !self.local_keys.has_ls {
            false
        } else {
            true
        }
    }

    // Remote keys.
    pub fn has_remote_ephemeral(&self) -> bool {
        if !self.remote_keys.has_re {
            false
        } else {
            true
        }
    }

    pub fn has_remote_static(&self) -> bool {
        if !self.remote_keys.has_rs {
            false
        } else {
            true
        }
    }
}

pub struct Session {
    pattern: Vec<Tokens>, // Tokens::new("XXfallback+psk3")?
    role: Role,
    keys: Keys,
}

impl Session {
    pub fn new(pattern: Vec<Tokens>, role: Role) -> Self {
        Session { pattern, role, keys: Keys::default() }
    }

    // Once we have a pair of key, we could take certain steps of dh operations.
    pub fn start(&self) {
        match self.role {
            Role::Initiator => {
                
            },
            Role::Responder => {

            }, 
        }
    }

    pub fn has_local_static(&self) -> bool {
        if self.keys.has_local_static() {
            true
        } else {
            false
        }
    }

    pub fn has_local_ephemeral(&self) -> bool {
        if self.keys.has_local_ephemeral() {
            true
        } else {
            false
        }
    }

    pub fn has_remote_static(&self) -> bool {
        if self.keys.has_remote_static() {
            true
        } else {
            false
        }
    }

    pub fn has_remote_ephemeral(&self) -> bool {
        if self.keys.has_remote_ephemeral() {
            true
        } else {
            false
        }
    }

    #[inline]
    pub fn set_local_static(&mut self, ls: Vec<u8>) {
        self.keys.local_keys.ls = ls;
    }

    #[inline]
    pub fn set_local_ephemeral(&mut self, le: Vec<u8>) {
        self.keys.local_keys.le = le;
    }

    #[inline]
    pub fn set_remote_static(&mut self, rs: Vec<u8>) {
        self.keys.remote_keys.rs = rs;
    }

    #[inline]
    pub fn set_remote_ephemeral(&mut self, re: Vec<u8>) {
        self.keys.remote_keys.re = re;
    }

    #[inline]
    pub fn get_local_static(&self) -> &[u8] {
        &self.keys.local_keys.ls
    }

    #[inline]
    pub fn get_local_ephemeral(&self) -> &[u8] {
        &self.keys.local_keys.le
    }

    #[inline]
    pub fn get_remote_static(&self) -> &[u8] {
        &self.keys.remote_keys.rs
    }

    #[inline]
    pub fn get_remote_ephemeral(&self) -> &[u8] {
        &self.keys.remote_keys.re
    }
}