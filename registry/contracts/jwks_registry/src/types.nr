use aztec::protocol::traits::{Deserialize, Packable, Serialize};
use std::meta::derive;

// SHA-256 hash commitment of the RSA-2048 modulus (base64url-encoded string).
// Stored as 2 Fields (128 bits each) instead of the full 37-Field limb representation.
// At bind time, the user provides the raw modulus string as a private witness,
// hashes it, and verifies against this stored commitment.
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct StoredJwk {
    pub modulus_hash: [Field; 2], // SHA-256 of base64url modulus, packed [high_128, low_128]
    pub is_valid: bool,
}

impl StoredJwk {
    pub fn empty() -> Self {
        StoredJwk {
            modulus_hash: [0; 2],
            is_valid: false,
        }
    }
}

/// Pack a 32-byte SHA-256 hash into 2 Field elements (128 bits each).
/// hash[0..16] -> high, hash[16..32] -> low
pub fn sha256_to_fields(hash: [u8; 32]) -> [Field; 2] {
    let mut high: Field = 0;
    let mut low: Field = 0;
    for i in 0..16 {
        high = high * 256 + hash[i] as Field;
    }
    for i in 16..32 {
        low = low * 256 + hash[i] as Field;
    }
    [high, low]
}
