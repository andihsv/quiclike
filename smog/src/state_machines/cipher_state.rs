//! Cipehr State Machine based on The Noise Protocol spec: <https://noiseprotocol.org/noise.html#the-cipherstate-object>

use bytes::BytesMut;
use colloid::cipher::non_detached::{in_place, non_in_place};

#[derive(Default, Debug)]
pub struct CipherState {
    k: [u8; 32],
    n: [u8; 12],
}

impl CipherState {
    pub fn init_key(&mut self, key: [u8; 32]) {
        self.k = key;
        self.n = [0u8; 12];
    }

    pub fn has_key(&self) -> bool {
        !self.k.is_empty()
    }

    pub fn set_nonce(&mut self, nonce: [u8; 12]) {
        self.n = nonce;
    }

    pub(crate) fn increment_nonce_le(&mut self) {
        let mut carry = 1u8;
        for b in self.n.iter_mut() {
            let (val, new_carry) = b.overflowing_add(carry);
            *b = val;
            carry = new_carry as u8;
            if carry == 0 {
                break;
            }
        }
    }

    pub(crate) fn decrement_nonce_le(&mut self) {
        let mut borrow = 1u8;
        for b in self.n.iter_mut() {
            let (val, under) = b.overflowing_sub(borrow);
            *b = val;
            borrow = under as u8; // 1 if we underflowed, 0 otherwise
            if borrow == 0 {
                break; // no further borrowing needed
            }
        }
    }

    pub fn encrypt_with_ad(
        &mut self,
        ad: &[u8],
        buf: BytesMut,
    ) -> std::result::Result<(), chacha20poly1305::Error> {
        if self.has_key() {
            self.increment_nonce_le();
            in_place::encrypt(&self.k, &self.n, ad, buf)?;
        }
        Ok(())
    }

    pub fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        buf: BytesMut,
    ) -> std::result::Result<(), chacha20poly1305::Error> {
        if self.has_key() {
            self.increment_nonce_le();
            let result = in_place::decrypt(&self.k, &self.n, ad, buf);
            match result {
                Ok(()) => return Ok(()),
                Err(_e) => {
                    self.decrement_nonce_le();
                    return Err(chacha20poly1305::Error);
                }
            }
        }
        Ok(())
    }

    pub fn rekey(&mut self) -> Result<(), chacha20poly1305::Error> {
        self.k = non_in_place::rekey(&self.k)?;
        Ok(())
    }
}
