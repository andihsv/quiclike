use colloid::{
    dh::DHLEN,
    hash::{HASHLEN, once},
};

fn main() {
    // Hashing data.
    let data = b"Hash algo Blake3.";
    let hash = once::rayon::hash(data);
    println!("Hash result: {}", hash);
    // Expected:
    //      Hash result: a3344e602b69188a1fb4ebb89e4897f297e9a2063bb54cea857bf2e2e7da92d2
    // HMAC (Keyd Hash).
    let key = &[0u8; HASHLEN]; // Example only.
    let hmac = once::rayon::hmac(key, data);
    println!("Hmac result: {}", hmac);
    // Expected:
    //      Hmac result: 5306de6f781feb39730ee7c1d7e62ce29e0d261c94ef2a379eab76fbc976500c
    let input_key_material = &[0u8; DHLEN];
    let buf1: &mut [u8; 32] = &mut [0u8; 32];
    let buf2: &mut [u8; 32] = &mut [0u8; 32];
    let buf3: &mut [u8; 32] = &mut [0u8; 32];
    once::rayon::hkdf(key, input_key_material, 2, buf1, buf2, buf3);
    println!("HKDF result 1: {:?}", buf1);
    println!("HKDF result 2: {:?}", buf2);
    println!("HKDF result 3: {:?}", buf3);
    once::rayon::hkdf(key, input_key_material, 3, buf1, buf2, buf3);
    println!("HKDF result 1: {:?}", buf1);
    println!("HKDF result 2: {:?}", buf2);
    println!("HKDF result 3: {:?}", buf3);
}
