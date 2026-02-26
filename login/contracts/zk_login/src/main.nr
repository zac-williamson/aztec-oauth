mod types;

use aztec::macros::aztec;

/// ZkLogin Contract
///
/// Implements privacy-preserving identity binding on Aztec.
/// Users prove ownership of a Google or Apple account via ZK-verified JWTs,
/// binding their identity to an AztecAddress with sybil resistance.
///
/// Same identity (sub claim) cannot bind to two different addresses.
/// The JWT and all personal data stay private - only the nullifier,
/// provider_id, and kid_hash are visible on-chain.
#[aztec]
pub contract ZkLogin {
    use crate::types::{
        MAX_JWT_DATA_LENGTH, MAX_NONCE_LENGTH, MAX_SUB_LENGTH, PROVIDER_APPLE, PROVIDER_GOOGLE,
        field_to_hex_bytes, hash_bytes_to_field,
    };
    use aztec::{
        macros::{functions::{external, initializer, only_self, view}, storage::storage},
        protocol::{address::AztecAddress, traits::ToField},
        state_vars::{Map, PublicImmutable, PublicMutable},
    };
    use jwt::JWT;
    use jwks_registry::JwksRegistry;
    use std::hash::pedersen_hash;

    #[storage]
    struct Storage<Context> {
        // Address of the JwksRegistry contract
        registry: PublicImmutable<AztecAddress, Context>,

        // identity_nullifier -> bound AztecAddress
        bindings: Map<Field, PublicMutable<AztecAddress, Context>, Context>,

        // AztecAddress -> is_bound (convenience lookup)
        bound_addresses: Map<AztecAddress, PublicMutable<bool, Context>, Context>,
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
    #[external("private")]
    fn bind_account(
        // JWT data (private witnesses)
        jwt_data: BoundedVec<u8, MAX_JWT_DATA_LENGTH>,
        base64_decode_offset: u32,
        pubkey_modulus_limbs: [u128; 18],
        redc_params_limbs: [u128; 18],
        signature_limbs: [u128; 18],
        // Public inputs
        provider_id: Field,
        kid_hash: Field,
        // Nonce binding (private)
        nonce_randomness: Field,
    ) {
        // 1. Verify JWT RS256 signature
        let mut jwt: JWT<MAX_JWT_DATA_LENGTH> = JWT::init(
            jwt_data,
            base64_decode_offset,
            pubkey_modulus_limbs,
            redc_params_limbs,
            signature_limbs,
        );
        jwt.verify();

        // 2. Verify issuer matches provider
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

        // 3. Extract sub claim (unique stable user identifier)
        let sub: BoundedVec<u8, MAX_SUB_LENGTH> = jwt.get_claim_string("sub".as_bytes());

        // 4. Verify nonce binds to caller (anti-front-running)
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

        // 5. Compute identity nullifier
        let sub_hash = hash_bytes_to_field(sub);
        let identity_nullifier = pedersen_hash([sub_hash, provider_id]);

        // 6. Push nullifier (protocol-level sybil resistance)
        self.context.push_nullifier(identity_nullifier);

        // 7. Convert limbs from u128 to Field for public function
        let mut modulus_fields: [Field; 18] = [0; 18];
        let mut redc_fields: [Field; 18] = [0; 18];
        for i in 0..18 {
            modulus_fields[i] = pubkey_modulus_limbs[i] as Field;
            redc_fields[i] = redc_params_limbs[i] as Field;
        }

        // 8. Enqueue public binding storage
        self.enqueue_self.store_binding(
            identity_nullifier,
            sender,
            provider_id,
            kid_hash,
            modulus_fields,
            redc_fields,
        );
    }

    /// Validate RSA key against the JWKS registry and record the binding.
    /// Only callable from within this contract.
    #[external("public")]
    #[only_self]
    fn store_binding(
        identity_nullifier: Field,
        bound_address: AztecAddress,
        provider_id: Field,
        kid_hash: Field,
        modulus_limbs: [Field; 18],
        redc_params_limbs: [Field; 18],
    ) {
        // 1. Read JWK from registry via cross-contract call
        let registry_address = self.storage.registry.read();
        let stored_jwk = self.view(
            JwksRegistry::at(registry_address).get_jwk(provider_id, kid_hash),
        );

        // 2. Verify the JWK is valid
        assert(stored_jwk.is_valid, "JWK is not valid or not found");

        // 3. Verify the modulus matches what was used in private JWT verification
        for i in 0..18 {
            assert(
                stored_jwk.modulus_limbs[i] == modulus_limbs[i],
                "modulus mismatch with registry",
            );
            assert(
                stored_jwk.redc_params_limbs[i] == redc_params_limbs[i],
                "redc_params mismatch with registry",
            );
        }

        // 4. Secondary binding check (primary is nullifier tree)
        let existing: AztecAddress = self.storage.bindings.at(identity_nullifier).read();
        assert(existing.is_zero(), "identity already bound");

        // 5. Record the binding
        self.storage.bindings.at(identity_nullifier).write(bound_address);
        self.storage.bound_addresses.at(bound_address).write(true);
    }

    // ========================================================================
    // View functions
    // ========================================================================

    /// Check if an address has been bound to an identity.
    #[external("public")]
    #[view]
    fn is_address_bound(address: AztecAddress) -> pub bool {
        self.storage.bound_addresses.at(address).read()
    }

    /// Get the address bound to a specific identity nullifier.
    #[external("public")]
    #[view]
    fn get_bound_address(identity_nullifier: Field) -> pub AztecAddress {
        self.storage.bindings.at(identity_nullifier).read()
    }
}
