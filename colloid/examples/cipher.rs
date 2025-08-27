use aead::AeadCore;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::OsRng};
use colloid::cipher::non_detached::in_place;

fn main() -> std::result::Result<(), chacha20poly1305::Error> {
    let generated_key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let key: &[u8; 32] = generated_key.as_slice().try_into().unwrap();
    let generated_nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let nonce: &[u8; 12] = generated_nonce.as_slice().try_into().unwrap();
    let mut ciphertext = aead::bytes::BytesMut::from("We are cryptographic");
    in_place::encrypt(&key, &nonce, b"Hello", &mut ciphertext)?;
    println!("{:?}", str::from_utf8(&ciphertext));
    // in_place::decrypt(&key, &nonce, b"Hell0", &mut ciphertext)?;  <-- This will fail.
    in_place::decrypt(&key, &nonce, b"Hello", &mut ciphertext)?;
    println!("{:?}", ciphertext);
    println!("Decrypted: {:?}", str::from_utf8(&ciphertext));
    // Expected:
    //      Err(Utf8Error { valid_up_to: 0, error_len: Some(1) })
    //      b"We are cryptographic"
    //      Decrypted: Ok("We are cryptographic")
    Ok(())
}
