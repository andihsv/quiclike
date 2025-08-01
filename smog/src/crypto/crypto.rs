// use blake2s_simd::{ blake2s, blake2sp::Params};
// use chacha20poly1305::{
//     aead::{Aead, Payload},
//     ChaCha20Poly1305, KeyInit, Nonce,
// };
// use x25519_dalek::{PublicKey, StaticSecret};

// use core::convert::TryInto;

// pub type SymKey   = [u8; 32];
// pub type Hash     = [u8; 32];  // BLAKE2s-256
// pub type PubKey   = [u8; 32];  // Curve25519
// pub type SharedSecret = [u8; 32];

// /// The set of all cryptographic primitives
// pub trait Crypto {
//     /// Random 32 bytes.
//     fn random_key(&mut self) -> SymKey;

//     /// HKDF(chaining_key, input) -> (new_ck, output_key)
//     fn hkdf(&mut self, ck: &SymKey, input: &[u8]) -> (SymKey, SymKey);

//     /// aead_encrypt(key, nonce, ad, plaintext) -> ciphertext
//     fn encrypt(&mut self, key: &SymKey, nonce: u64, ad: &[u8], pt: &[u8]) -> Vec<u8>;

//     /// aead_decrypt(...)
//     fn decrypt(&mut self, key: &SymKey, nonce: u64, ad: &[u8], ct: &[u8]) -> Option<Vec<u8>>;

//     /// HASH(data) -> 32 bytes
//     fn hash(&mut self, data: &[u8]) -> Hash;

//     /// h = HASH(h || data)
//     fn mix_hash(&mut self, h: &mut Hash, data: &[u8]) {
//         let mut buf = Vec::with_capacity(h.len() + data.len());
//         buf.extend_from_slice(h);
//         buf.extend_from_slice(data);
//         *h = self.hash(&buf);
//     }

//     /// ECDH Secret → PubKey
//     fn pubkey_from_secret(&mut self, sk: &SymKey) -> PubKey;

//     /// ECDH Shared Secret.
//     fn ecdh(&mut self, sk: &SymKey, pk: &PubKey) -> SharedSecret;
// }


// pub struct ChaChaBlake2s;

// impl Crypto for ChaChaBlake2s {
//     fn random_key(&mut self) -> SymKey {
//         let mut k = [0u8; 32];
//         getrandom::fill(&mut k).expect("Unable to fill random key buffer.");
//         k
//     }

//     fn hkdf(&mut self, ck: &SymKey, input: &[u8]) -> (SymKey, SymKey) {
//         let mut st = Params::new()
//             .hash_length(64)
//             .key(ck)
//             .to_state();
//         st.update(input);
//         let out = st.finalize();
//         let mut ck2 = [0u8; 32];
//         let mut k   = [0u8; 32];
//         ck2.copy_from_slice(&out.as_bytes()[..32]);
//         k.copy_from_slice(&out.as_bytes()[32..]);
//         (ck2, k)
//     }

//     fn encrypt(&mut self, key: &SymKey, nonce: u64, ad: &[u8], pt: &[u8]) -> Vec<u8> {
//         let cipher = ChaCha20Poly1305::new(key.into());
//         let mut n = [0u8; 12];
//         n[4..12].copy_from_slice(&nonce.to_le_bytes());
//         cipher
//             .encrypt(Nonce::from_slice(&n), Payload { msg: pt, aad: ad })
//             .unwrap()
//     }

//     fn decrypt(&mut self, key: &SymKey, nonce: u64, ad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
//         let cipher = ChaCha20Poly1305::new(key.into());
//         let mut n = [0u8; 12];
//         n[4..12].copy_from_slice(&nonce.to_le_bytes());
//         cipher
//             .decrypt(Nonce::from_slice(&n), Payload { msg: ct, aad: ad })
//             .ok()
//     }

//     fn hash(&mut self, data: &[u8]) -> Hash {
//         blake2s(data).as_bytes().try_into().unwrap()
//     }

//     fn pubkey_from_secret(&mut self, sk: &SymKey) -> PubKey {
//         let ss = StaticSecret::from(*sk);
//         PublicKey::from(&ss).to_bytes()
//     }

//     fn ecdh(&mut self, sk: &SymKey, pk: &PubKey) -> SharedSecret {
//         let ss = StaticSecret::from(*sk);
//         let pk = PublicKey::from(*pk);
//         ss.diffie_hellman(&pk).to_bytes()
//     }
// }

