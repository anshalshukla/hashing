use ark_bn254::Fr;
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use mimc_rs::Mimc7;
use p256::ecdsa::{
    SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

/// Generate a new ECDSA key pair
pub fn generate_ecdsa_key_pair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    (signing_key, verifying_key)
}

/// Sign a message using ECDSA
pub fn sign_message_ecdsa(signing_key: &SigningKey, message: &[u8]) -> p256::ecdsa::Signature {
    signing_key.sign(message)
}

/// Verify an ECDSA signature
pub fn verify_signature_ecdsa(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &p256::ecdsa::Signature,
) -> bool {
    verifying_key.verify(message, signature).is_ok()
}

/// Generate a new EdDSA key pair
pub fn generate_ed25519_key_pair() -> (Ed25519SigningKey, Ed25519VerifyingKey) {
    let mut secret_key = [0u8; 32];
    OsRng.fill_bytes(&mut secret_key);
    let signing_key = Ed25519SigningKey::from_bytes(&secret_key);
    let verifying_key = Ed25519VerifyingKey::from(&signing_key);
    (signing_key, verifying_key)
}

/// Sign a message using EdDSA
pub fn sign_message_ed25519(
    signing_key: &Ed25519SigningKey,
    message: &[u8],
) -> ed25519_dalek::Signature {
    signing_key.sign(message)
}

/// Verify an EdDSA signature
pub fn verify_signature_ed25519(
    verifying_key: &Ed25519VerifyingKey,
    message: &[u8],
    signature: &ed25519_dalek::Signature,
) -> bool {
    verifying_key.verify(message, signature).is_ok()
}

/// Hash a message using keccak256
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(&input);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

/// Hash a message using SHA-256
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Hash a message using Poseidon
pub fn poseidon(input: &[u8]) -> [u8; 32] {
    let mut poseidon = Poseidon::<Fr>::new_circom(1).unwrap();
    let hash = poseidon.hash_bytes_be(&[input]).unwrap();
    hash
}

/// Hash a message using MiMC
pub fn mimc(input: &[u8]) -> [u8; 32] {
    let mimc7 = Mimc7::new();
    let hash = mimc7.hash_bytes(input.to_vec()).unwrap();
    let (_, result) = hash.to_bytes_be();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result[..32]);
    output
}

/// Convert hashes to Hex String
pub fn to_hex(hash: [u8; 32]) -> String {
    let hash: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    hash
}
