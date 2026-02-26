mod types;

use aztec::macros::aztec;

/// JWKS Registry Contract
///
/// Stores RSA-2048 public keys from Google and Apple JWKS endpoints.
/// Keys can be updated via two paths:
///   1. Admin-controlled: `admin_set_jwk()` for bootstrapping/testing
///   2. Permissionless: `update_jwk()` backed by Primus zkTLS attestations
#[aztec]
pub contract JwksRegistry {
    use crate::types::StoredJwk;
    use att_verifier_lib::{verify_attestation_hashing, MAX_CONTENT_LEN, MAX_URL_LEN};
    use aztec::{
        macros::{functions::{external, initializer, only_self, view}, storage::storage},
        protocol::address::AztecAddress,
        state_vars::{Map, PublicImmutable, PublicMutable},
    };

    global MAX_ATTESTORS: u32 = 5;

    #[storage]
    struct Storage<Context> {
        admin: PublicImmutable<AztecAddress, Context>,

        // (provider_id, kid_hash) -> StoredJwk
        // provider_id: 1=Google, 2=Apple
        // kid_hash: pedersen_hash(kid_bytes)
        jwks: Map<Field, Map<Field, PublicMutable<StoredJwk, Context>, Context>, Context>,

        // Primus attestor secp256k1 public keys, indexed by attestor_index
        attestor_keys_x: Map<Field, PublicMutable<Field, Context>, Context>,
        attestor_keys_y: Map<Field, PublicMutable<Field, Context>, Context>,
        attestor_count: PublicMutable<Field, Context>,

        // Poseidon2 hashes of whitelisted JWKS endpoint URLs
        allowed_url_hash_0: PublicMutable<Field, Context>,
        allowed_url_hash_1: PublicMutable<Field, Context>,
        allowed_url_hash_2: PublicMutable<Field, Context>,
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    #[initializer]
    #[external("public")]
    fn constructor(admin: AztecAddress, url_hash_0: Field, url_hash_1: Field, url_hash_2: Field) {
        assert(!admin.is_zero(), "invalid admin");
        self.storage.admin.initialize(admin);
        self.storage.allowed_url_hash_0.write(url_hash_0);
        self.storage.allowed_url_hash_1.write(url_hash_1);
        self.storage.allowed_url_hash_2.write(url_hash_2);
        self.storage.attestor_count.write(0);
    }

    // ========================================================================
    // Admin functions
    // ========================================================================

    /// Register a Primus attestor secp256k1 public key.
    #[external("public")]
    fn set_attestor_key(index: Field, pub_key_x: Field, pub_key_y: Field) {
        let admin = self.storage.admin.read();
        assert(self.msg_sender() == admin, "caller is not admin");

        self.storage.attestor_keys_x.at(index).write(pub_key_x);
        self.storage.attestor_keys_y.at(index).write(pub_key_y);

        let count = self.storage.attestor_count.read();
        if index as u64 >= count as u64 {
            self.storage.attestor_count.write(index + 1);
        }
    }

    /// Admin-only: directly set a JWK entry (for bootstrapping/testing).
    #[external("public")]
    fn admin_set_jwk(
        provider_id: Field,
        kid_hash: Field,
        modulus_limbs: [Field; 18],
        redc_params_limbs: [Field; 18],
    ) {
        let admin = self.storage.admin.read();
        assert(self.msg_sender() == admin, "caller is not admin");
        assert(
            (provider_id == 1) | (provider_id == 2),
            "invalid provider_id",
        );

        let jwk = StoredJwk {
            modulus_limbs,
            redc_params_limbs,
            is_valid: true,
        };
        self.storage.jwks.at(provider_id).at(kid_hash).write(jwk);
    }

    /// Admin-only: revoke a JWK entry.
    #[external("public")]
    fn revoke_jwk(provider_id: Field, kid_hash: Field) {
        let admin = self.storage.admin.read();
        assert(self.msg_sender() == admin, "caller is not admin");

        let mut jwk = self.storage.jwks.at(provider_id).at(kid_hash).read();
        jwk.is_valid = false;
        self.storage.jwks.at(provider_id).at(kid_hash).write(jwk);
    }

    // ========================================================================
    // Permissionless path (Primus zkTLS attestation)
    // ========================================================================

    /// Permissionless JWK update backed by a Primus zkTLS attestation.
    ///
    /// Private function: the attestation data stays as private witnesses.
    /// After verification, enqueues a public call to store the JWK.
    #[external("private")]
    fn update_jwk(
        // Primus attestation data (private witnesses)
        attestor_pub_key_x: [u8; 32],
        attestor_pub_key_y: [u8; 32],
        attestation_hash: [u8; 32],
        attestation_signature: [u8; 64],
        request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
        allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
        data_hashes: [[u8; 32]; 2],
        plain_json_response: [BoundedVec<u8, MAX_CONTENT_LEN>; 2],
        // Extracted JWK data
        provider_id: Field,
        kid_hash: Field,
        modulus_limbs: [Field; 18],
        redc_params_limbs: [Field; 18],
    ) {
        // 1. Verify the Primus attestation (ECDSA signature + URL match + SHA-256 hash)
        let url_hashes: [Field; 2] = verify_attestation_hashing(
            attestor_pub_key_x,
            attestor_pub_key_y,
            attestation_hash,
            attestation_signature,
            request_urls,
            allowed_urls,
            data_hashes,
            plain_json_response,
        );

        // 2. Pack attestor public key coordinates into Fields for the public function
        let mut attestor_x_field: Field = 0;
        let mut attestor_y_field: Field = 0;
        for i in 0..32 {
            attestor_x_field = attestor_x_field * 256 + attestor_pub_key_x[i] as Field;
            attestor_y_field = attestor_y_field * 256 + attestor_pub_key_y[i] as Field;
        }

        // 3. Enqueue public function to validate and store
        self.enqueue_self.store_jwk(
            provider_id,
            kid_hash,
            modulus_limbs,
            redc_params_limbs,
            url_hashes,
            attestor_x_field,
            attestor_y_field,
        );
    }

    /// Internal: validate attestation metadata against on-chain state and store JWK.
    /// Only callable from within this contract (via enqueue from update_jwk).
    #[external("public")]
    #[only_self]
    fn store_jwk(
        provider_id: Field,
        kid_hash: Field,
        modulus_limbs: [Field; 18],
        redc_params_limbs: [Field; 18],
        url_hashes: [Field; 2],
        attestor_x: Field,
        attestor_y: Field,
    ) {
        // 1. Verify URL hashes match on-chain allowed list
        let allowed_hashes = [
            self.storage.allowed_url_hash_0.read(),
            self.storage.allowed_url_hash_1.read(),
            self.storage.allowed_url_hash_2.read(),
        ];
        for i in 0..2 {
            let url_hash = url_hashes[i];
            let mut found = false;
            for j in 0..3 {
                if allowed_hashes[j] == url_hash {
                    found = true;
                }
            }
            assert(found, "URL hash not in allowed list");
        }

        // 2. Verify attestor public key matches a registered attestor
        let attestor_count = self.storage.attestor_count.read();
        let mut attestor_found = false;
        for i in 0..MAX_ATTESTORS {
            if (i as u64) < (attestor_count as u64) {
                let stored_x = self.storage.attestor_keys_x.at(i as Field).read();
                let stored_y = self.storage.attestor_keys_y.at(i as Field).read();
                if (stored_x == attestor_x) & (stored_y == attestor_y) {
                    attestor_found = true;
                }
            }
        }
        assert(attestor_found, "attestor key not registered");

        // 3. Validate provider_id
        assert(
            (provider_id == 1) | (provider_id == 2),
            "invalid provider_id",
        );

        // 4. Store the JWK
        let jwk = StoredJwk {
            modulus_limbs,
            redc_params_limbs,
            is_valid: true,
        };
        self.storage.jwks.at(provider_id).at(kid_hash).write(jwk);
    }

    // ========================================================================
    // View functions
    // ========================================================================

    /// Read a JWK entry (public, callable cross-contract).
    #[external("public")]
    #[view]
    fn get_jwk(provider_id: Field, kid_hash: Field) -> StoredJwk {
        self.storage.jwks.at(provider_id).at(kid_hash).read()
    }

    /// Read a JWK entry (off-chain utility).
    #[external("utility")]
    unconstrained fn get_jwk_unconstrained(
        provider_id: Field,
        kid_hash: Field,
    ) -> pub StoredJwk {
        self.storage.jwks.at(provider_id).at(kid_hash).read()
    }

    /// Check if a JWK is valid (off-chain utility).
    #[external("utility")]
    unconstrained fn is_jwk_valid(provider_id: Field, kid_hash: Field) -> pub bool {
        self.storage.jwks.at(provider_id).at(kid_hash).read().is_valid
    }
}
