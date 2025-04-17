use hashing::{
    generate_ecdsa_key_pair, generate_ed25519_key_pair, keccak256, mimc, poseidon, sha256,
    sign_message_ecdsa, sign_message_ed25519, to_hex, verify_signature_ecdsa,
    verify_signature_ed25519,
};

fn main() {
    let message = b"Hello World!";

    // Example with Keccak
    let keccak256_hash = keccak256(message);
    println!("Keccak hash: 0x{}", to_hex(keccak256_hash));

    // Example with SHA-256
    let sha256_hash = sha256(message);
    println!("SHA-256 hash: 0x{}", to_hex(sha256_hash));

    // Example with Poseidon
    let poseidon_hash = poseidon(message);
    println!("Poseidon hash: 0x{}", to_hex(poseidon_hash));

    // Example with MiMC
    let mimc_hash = mimc(message);
    println!("MiMC hash: 0x{}", to_hex(mimc_hash));

    // Example with ECDSA
    let (signing_key, verifying_key) = generate_ecdsa_key_pair();
    // Sign the message
    let signature = sign_message_ecdsa(&signing_key, message);
    println!("Ecdsa Message signed successfully");

    // Verify the signature
    let is_valid = verify_signature_ecdsa(&verifying_key, message, &signature);
    println!(
        "Ecdsa Signature verification: {}",
        if is_valid { "successful" } else { "failed" }
    );

    // Example with EDDSA
    let (signing_key, verifying_key) = generate_ed25519_key_pair();

    // Sign the message
    let signature = sign_message_ed25519(&signing_key, message);
    println!("Eddsa Message signed successfully");

    // Verify the signature
    let is_valid = verify_signature_ed25519(&verifying_key, message, &signature);
    println!(
        "Eddsa Signature verification: {}",
        if is_valid { "successful" } else { "failed" }
    );
}
