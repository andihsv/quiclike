use aead::AeadCore;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::OsRng};
use colloid::cipher::{
    detached,
    non_detached::{in_place, non_in_place},
};

fn main() -> std::result::Result<(), chacha20poly1305::Error> {
    let generated_key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let key: &[u8; 32] = generated_key.as_slice().try_into().unwrap();
    let generated_nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let nonce: &[u8; 12] = generated_nonce.as_slice().try_into().unwrap();
    let mut ciphertext = aead::bytes::BytesMut::from("We are cryptographic");
    // Option: in-place en/de.
    println!("Option: in-place en/de.");
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
    //
    // Option: non-in-place en/de.
    println!("Option: non-in-place en/de.");
    let encrypted = non_in_place::encrypt(&key, &nonce, &mut ciphertext)?;
    println!("Encryped: {:?}", str::from_utf8(&encrypted));
    let decryped = non_in_place::decrypt(&key, &nonce, &encrypted)?;
    println!("Decrypted: {:?}", str::from_utf8(&decryped));
    // Expected:
    //      Encryped: Err(Utf8Error { valid_up_to: 2, error_len: Some(1) })
    //      Decrypted: Ok("We are cryptographic")
    //
    // Option: in-place-detatached en/de.
    println!("Option: in-place-detatached en/de.");
    let tag = detached::encrypt(&key, &nonce, b"Crypto", &mut ciphertext)?;
    println!("Tag: {:?}", tag);
    println!("Encrypted: {:?}", ciphertext);
    detached::decrypt(&key, &nonce, b"Crypto", &mut ciphertext, &tag)?;
    println!("Decrypted: {:?}", ciphertext);
    // Expected:
    //      Tag: [235, 164, 205, 33, 178, 135, 236, 177, 86, 29, 18, 217, 169, 18, 111, 133]
    //      Encrypted: b"\x84\xad\xa7r\x81\xe6\x9ef\x07jN\x8c\x07\xc0\x9ajg\xbe\xa1\xd3"
    //      Decrypted: b"We are cryptographic"
    Ok(())
}
