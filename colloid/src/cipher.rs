/// Seperated cipher text and authenticated tag.
pub mod non_detached {

    pub mod in_place {

        use aead::bytes;
        use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, aead::AeadInPlace};

        /// Encryption will proceed in-place, which means you pass in the plain text buffer,
        /// and you will get a buffer full of cipher text.
        pub fn encrypt(
            key: &[u8; 32],
            nonce: &[u8; 12],
            ad: &[u8],
            buf: &mut bytes::BytesMut,
        ) -> std::result::Result<(), chacha20poly1305::Error> {
            let key = Key::from_slice(key);
            let nonce = Nonce::from_slice(nonce);
            let cipher = ChaCha20Poly1305::new(&key);
            cipher.encrypt_in_place(nonce, ad, buf)?;
            Ok(())
        }

        pub fn decrypt(
            key: &[u8; 32],
            nonce: &[u8; 12],
            ad: &[u8],
            buf: &mut bytes::BytesMut,
        ) -> std::result::Result<(), chacha20poly1305::Error> {
            let key = Key::from_slice(key);
            let nonce = Nonce::from_slice(nonce);
            let cipher = ChaCha20Poly1305::new(&key);
            cipher.decrypt_in_place(nonce, ad, buf)?;
            Ok(())
        }
    }

    pub mod non_in_place {

        use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead};

        pub fn encrypt(
            key: &[u8; 32],
            nonce: &[u8; 12],
            // ad: &[u8],
            plaintext: &[u8],
        ) -> std::result::Result<Vec<u8>, chacha20poly1305::Error> {
            let key = Key::from_slice(key);
            let nonce = Nonce::from_slice(nonce);
            let cipher = ChaCha20Poly1305::new(&key);
            let ciphertext = cipher.encrypt(nonce, plaintext)?;
            Ok(ciphertext)
        }
    }
}

/// Not seperated cipher text and authenticated tag.
pub mod detached {

    /// Encryption will proceed in-place, which means you pass in the plain text buffer,
    /// and you will get a buffer full of cipher text.
    pub fn encrypt(key: &[u8; 32], nonce: u8, ad: &[u8], buf: &[u8]) {}
}
