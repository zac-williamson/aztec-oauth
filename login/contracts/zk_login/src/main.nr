mod types;

use aztec::macros::aztec;

/// ZkLogin Contract
///
/// Implements privacy-preserving identity binding on Aztec.
/// Users prove ownership of a Google or Apple account via ZK-verified JWTs,
/// binding their identity to an AztecAddress with sybil resistance.
///
/// Fully private: for mature keys (past the registry's delay), the entire
/// bind_account flow stays in private context with no on-chain data leakage.
/// For brand-new keys, a public fallback verifies the key against the
/// instant store, leaking only key metadata (not identity or address).
///
/// Sybil resistance is enforced via two nullifiers:
///   - Identity nullifier: same identity (sub claim) cannot bind twice
///   - Address nullifier: same address cannot bind twice, enables is_address_bound
#[aztec]
pub contract ZkLogin {
    use crate::types::{
        MAX_JWT_DATA_LENGTH, MAX_MODULUS_B64_LEN, MAX_MODULUS_DECODED_LEN,
        MAX_NONCE_LENGTH, MAX_SUB_LENGTH, PROVIDER_APPLE, PROVIDER_GOOGLE,
        bytes_to_limbs, field_to_hex_bytes, hash_bytes_to_field, sha256_to_fields,
    };
    use aztec::{
        macros::{functions::{external, initializer, only_self, view}, storage::storage},
        protocol::{address::AztecAddress, traits::ToField},
        state_vars::PublicImmutable,
    };
    use base64::BASE64_URL_DECODER;
    use jwt::JWT;
    use jwks_registry::JwksRegistry;
    use sha256::sha256_var;
    use std::hash::pedersen_hash;

    #[storage]
    struct Storage<Context> {
        // Address of the JwksRegistry contract
        registry: PublicImmutable<AztecAddress, Context>,
    }

    #[initializer]
    #[external("public")]
    fn constructor(registry_address: AztecAddress) {
        assert(!registry_address.is_zero(), "invalid registry address");
        self.storage.registry.initialize(registry_address);
    }

    /// Bind an OAuth identity to the caller's Aztec address.
    ///
    /// Private function - the JWT and all personal data remain as private witnesses
    /// and never leave the user's PXE.
    ///
    /// The caller provides the base64url-encoded RSA modulus string. The circuit:
    /// 1. SHA-256 hashes it and verifies against the registry's stored commitment
    /// 2. Base64url decodes it to raw bytes and converts to limbs for RSA verification
    ///
    /// `redc_params_limbs` remains a free witness (Barrett reduction params can't
    /// be efficiently derived in-circuit from the modulus).
    #[external("private")]
    fn bind_account(
        // JWT data (private witnesses)
        jwt_data: BoundedVec<u8, MAX_JWT_DATA_LENGTH>,
        base64_decode_offset: u32,
        pubkey_modulus_b64url: BoundedVec<u8, MAX_MODULUS_B64_LEN>,
        redc_params_limbs: [u128; 18],
        signature_limbs: [u128; 18],
        // Public inputs
        provider_id: Field,
        kid_hash: Field,
        // Nonce binding (private)
        nonce_randomness: Field,
        // Path selection
        use_public_fallback: bool,
    ) {
        // 1. Hash the base64url modulus string and derive the hash commitment
        let modulus_sha = sha256_var(
            pubkey_modulus_b64url.storage(),
            pubkey_modulus_b64url.len(),
        );
        let modulus_hash = sha256_to_fields(modulus_sha);

        // 2. Base64url decode the modulus string to raw bytes, then convert to limbs
        let decoded: BoundedVec<u8, MAX_MODULUS_DECODED_LEN> =
            BASE64_URL_DECODER::decode_var(pubkey_modulus_b64url);
        let pubkey_modulus_limbs: [u128; 18] = bytes_to_limbs(decoded);

        // 3. Verify JWT RS256 signature using the derived limbs
        let mut jwt: JWT<MAX_JWT_DATA_LENGTH> = JWT::init(
            jwt_data,
            base64_decode_offset,
            pubkey_modulus_limbs,
            redc_params_limbs,
            signature_limbs,
        );
        jwt.verify();

        // 4. Verify issuer matches provider
        if provider_id == PROVIDER_GOOGLE {
            let expected_iss: BoundedVec<u8, 27> = BoundedVec::from_array(
                "https://accounts.google.com".as_bytes(),
            );
            jwt.assert_claim_string::<3, 27>("iss".as_bytes(), expected_iss);
        } else if provider_id == PROVIDER_APPLE {
            let expected_iss: BoundedVec<u8, 25> = BoundedVec::from_array(
                "https://appleid.apple.com".as_bytes(),
            );
            jwt.assert_claim_string::<3, 25>("iss".as_bytes(), expected_iss);
        } else {
            assert(false, "unsupported provider");
        }

        // 5. Extract sub claim (unique stable user identifier)
        let sub: BoundedVec<u8, MAX_SUB_LENGTH> = jwt.get_claim_string("sub".as_bytes());

        // 6. Verify nonce binds to caller (anti-front-running)
        let sender: AztecAddress = self.msg_sender();
        let expected_nonce_hash = pedersen_hash([sender.to_field(), nonce_randomness]);

        // Extract nonce from JWT and verify it matches
        let jwt_nonce: BoundedVec<u8, MAX_NONCE_LENGTH> =
            jwt.get_claim_string("nonce".as_bytes());

        // Convert expected_nonce_hash to hex string and compare
        let expected_nonce_bytes = field_to_hex_bytes(expected_nonce_hash);
        for i in 0..MAX_NONCE_LENGTH {
            if i < jwt_nonce.len() {
                assert(
                    jwt_nonce.get(i) == expected_nonce_bytes[i],
                    "nonce mismatch: JWT nonce does not bind to caller",
                );
            }
        }

        // 7. Compute identity nullifier
        let sub_hash = hash_bytes_to_field(sub);
        let identity_nullifier = pedersen_hash([sub_hash, provider_id]);

        // 8. Push identity nullifier (sybil resistance - same identity can't bind twice)
        self.context.push_nullifier(identity_nullifier);

        // 9. Push address nullifier (same address can't bind twice + enables is_address_bound)
        let address_nullifier = pedersen_hash([sender.to_field()]);
        self.context.push_nullifier(address_nullifier);

        // 10. Verify the key hash commitment against the JWKS registry
        let registry_address = self.storage.registry.read();

        if use_public_fallback {
            // PUBLIC FALLBACK: key is new (not yet in delayed store).
            // Enqueue public function to verify against instant store.
            // Trade-off: provider_id, kid_hash, and modulus_hash (4 Fields) are visible on-chain,
            // but identity nullifier and bound address remain private.
            self.enqueue_self.verify_key_public(
                provider_id,
                kid_hash,
                modulus_hash,
            );
        } else {
            // PRIVATE PATH: key is mature (past delay).
            // Cross-contract private read - no data leakage.
            let stored_jwk = self.view(
                JwksRegistry::at(registry_address).get_jwk_private(provider_id, kid_hash),
            );
            assert(stored_jwk.is_valid, "JWK is not valid or not found");
            assert(
                stored_jwk.modulus_hash[0] == modulus_hash[0],
                "modulus hash mismatch with registry (high)",
            );
            assert(
                stored_jwk.modulus_hash[1] == modulus_hash[1],
                "modulus hash mismatch with registry (low)",
            );
        }
    }

    /// Verify a key hash commitment against the registry's instant (public) store.
    /// Only callable from within this contract (via enqueue from bind_account).
    #[external("public")]
    #[only_self]
    fn verify_key_public(
        provider_id: Field,
        kid_hash: Field,
        modulus_hash: [Field; 2],
    ) {
        let registry_address = self.storage.registry.read();
        let stored_jwk = self.view(
            JwksRegistry::at(registry_address).get_jwk(provider_id, kid_hash),
        );
        assert(stored_jwk.is_valid, "JWK is not valid or not found");
        assert(
            stored_jwk.modulus_hash[0] == modulus_hash[0],
            "modulus hash mismatch with registry (high)",
        );
        assert(
            stored_jwk.modulus_hash[1] == modulus_hash[1],
            "modulus hash mismatch with registry (low)",
        );
    }

    // ========================================================================
    // View functions
    // ========================================================================

    /// Check if an address has been bound to an identity.
    /// Queries the nullifier tree for the address nullifier.
    #[external("public")]
    #[view]
    fn is_address_bound(address: AztecAddress) -> pub bool {
        let address_nullifier = pedersen_hash([address.to_field()]);
        self.context.nullifier_exists_unsafe(address_nullifier, self.context.this_address())
    }
}
