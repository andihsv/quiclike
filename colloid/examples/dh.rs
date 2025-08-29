use colloid::dh::ephemeral_key;

fn main() {
    // Ephemeral key dh op.
    let (e_secret_1, e_public_1) = ephemeral_key::generate_keypair();
    let (e_secret_2, e_public_2) = ephemeral_key::generate_keypair();
    // Object 1.
    let shared_1 = ephemeral_key::dh(e_secret_1, e_public_2);
    println!("Shared key from Obj 1: {:?}", shared_1.to_bytes());
    // Object 2.
    let shared_2 = ephemeral_key::dh(e_secret_2, e_public_1);
    println!("Shared key from Obj 2: {:?}", shared_2.to_bytes());
    // Expected: They should be the same.
    // blabla...(Other mods.)
}
