use aztec::protocol::traits::{Deserialize, Packable, Serialize};
use std::meta::derive;

// RSA-2048 key stored as 18 limbs of 120 bits each (matches noir-jwt format)
// plus Barrett reduction parameters for noir_rsa
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct StoredJwk {
    pub modulus_limbs: [Field; 18],
    pub redc_params_limbs: [Field; 18],
    pub is_valid: bool,
}

impl StoredJwk {
    pub fn empty() -> Self {
        StoredJwk {
            modulus_limbs: [0; 18],
            redc_params_limbs: [0; 18],
            is_valid: false,
        }
    }
}
