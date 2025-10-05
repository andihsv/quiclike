//! Cipehr State Machine based on The Noise Protocol spec: <https://noiseprotocol.org/noise.html#the-cipherstate-object>

use chacha12_blake3::ChaCha12Blake3;
use colloid::cipher::Cipher;

pub struct CipherState {
    k: [u8; 32],
    n: [u8; 32],
    pub cipher_obj: Cipher,
}

impl CipherState {
    pub fn init(k: [u8; 32]) -> Self {
        Self {
            k,
            n: [0u8; 32],
            cipher_obj: Cipher {
                inner: ChaCha12Blake3::new(k),
            },
        }
    }

    pub fn init_key(&mut self, key: [u8; 32]) {
        self.k = key;
        self.n = [0u8; 32];
    }

    pub fn has_key(&self) -> bool {
        !self.k.is_empty()
    }

    pub fn set_nonce(&mut self, nonce: [u8; 32]) {
        self.n = nonce;
    }

    pub(crate) fn increase_nonce_le(&mut self) {
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

    // pub(crate) fn decrease_nonce_le(&mut self) {
    //     let mut borrow = 1u8;
    //     for b in self.n.iter_mut() {
    //         let (val, under) = b.overflowing_sub(borrow);
    //         *b = val;
    //         borrow = under as u8; // 1 if we underflowed, 0 otherwise
    //         if borrow == 0 {
    //             break; // no further borrowing needed
    //         }
    //     }
    // }

    pub fn encrypt_with_ad(
        &mut self,
        ad: &[u8],
        buf: &[u8],
    ) -> std::result::Result<(), chacha12_blake3::Error> {
        if self.has_key() {
            self.increase_nonce_le();
            self.cipher_obj.encrypt(self.n, ad, buf);
        }
        Ok(())
    }

    pub fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        buf: &[u8],
    ) -> std::result::Result<Vec<u8>, chacha12_blake3::Error> {
        if self.has_key() {
            self.increase_nonce_le();
            return self.cipher_obj.decrypt(self.n, ad, buf);
            // match result {
            //     Ok(v) => return Ok(v),
            //     Err(_e) => {
            //         self.decrement_nonce_le();
            //         return Err(chacha12_blake3::Error {});
            //     }
            // }
        } else {
            return Err(chacha12_blake3::Error {});
        }
    }

    pub fn rekey(&mut self) -> Result<(), chacha12_blake3::Error> {
        self.cipher_obj.rekey(self.k);
        Ok(())
    }
}
