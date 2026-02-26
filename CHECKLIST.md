# Implementation Checklist — zkLogin Sybil Protection on Aztec

**Target**: aztec-packages `v4.0.0-devnet.2-patch.1` (Noir 1.0.0-beta.18)
**Rule**: Each phase is complete ONLY when code compiles AND tests pass.

---

## Phase 0: Environment & Toolchain Setup

### 0.1 Install Aztec Sandbox
- [ ] Install `aztec-up` and pin to `v4.0.0-devnet.2-patch.1`
- [ ] Run `aztec start --sandbox` and verify it boots without error
- [ ] Verify `nargo --version` reports Noir 1.0.0-beta.18

### 0.2 Verify Nargo resolves deps
- [ ] Create a minimal hello-world Aztec contract with `aztec` dep at tag `v4.0.0-devnet.2-patch.1`
- [ ] Run `nargo compile` — must succeed
- [ ] **TEST**: `nargo compile` exits 0

---

## Phase 1: Port `att_verifier_lib` (Pure Noir Library)

### 1.1 Fix Nargo.toml dependency versions
- [ ] sha256: `v0.2.1` → **`v0.3.0`** (must match aztec-nr)
- [ ] poseidon: `v0.1.1` → **`v0.2.3`** (must match aztec-nr)
- [ ] string_search: `v0.3.3` (keep — no conflict)
- [ ] Set `compiler_version = ">=0.25.0"`

### 1.2 Fix `dep::` prefix in imports
- [ ] `use dep::poseidon::poseidon2::Poseidon2` → `use poseidon::poseidon2::Poseidon2`
- [ ] Verify no other `dep::` prefixes remain

### 1.3 Fix sha256 v0.3.0 API change
- [ ] `sha256_var` second arg changed from `u64` to `u32`
- [ ] Line ~87: `plain_json_response_contents[i].len() as u64` → remove cast (`.len()` already returns `u32`)

### 1.4 Compile check
- [ ] `cd lib/att_verifier_lib && nargo compile` exits 0
- [ ] No warnings about deprecated `dep::` prefix

### 1.5 Test
- [ ] Write a Noir test circuit (`#[test]`) that calls `verify_attestation_hashing` with synthetic data
- [ ] Write a Noir test for `verify_attestation_comm` with synthetic data
- [ ] `nargo test` exits 0 with all tests passing

---

## Phase 2: Fork noir-jwt for Aztec v4 Compatibility

### 2.1 Fork noir-jwt v0.5.1
- [ ] Fork https://github.com/zkemail/noir-jwt to your own repo
- [ ] Checkout tag `v0.5.1`

### 2.2 Update Nargo.toml dependencies
- [ ] `rsa`: `v0.9.1` → **`v0.10.0`** (uses sha256 v0.3.0)
- [ ] `sha256`: `v0.2.1` → **`v0.3.0`**
- [ ] `bignum`: `v0.8.0` → **`v0.9.1`** (uses poseidon v0.2.4, close enough)
- [ ] `nodash`: `v0.42.0` → **`v0.43.3`** (uses sha256 v0.3.0, poseidon v0.2.3)
- [ ] `base64`: `v0.4.2` (keep)
- [ ] `string_search`: `v0.3.3` (keep)

### 2.3 Fix sha256_var API call in lib.nr
- [ ] Line ~106: `sha256_var(self.data.storage(), self.data.len() as u64)` → `sha256_var(self.data.storage(), self.data.len())`

### 2.4 Fix any `dep::` prefixes
- [ ] Search all `.nr` files for `dep::` and remove prefix

### 2.5 Compile check
- [ ] `nargo compile` in forked noir-jwt exits 0

### 2.6 Test
- [ ] `nargo test` in forked noir-jwt — all existing tests pass
- [ ] Verify JWT signature verification works with a known test vector

---

## Phase 3: JwksRegistry Contract

### 3.1 Fix Nargo.toml
- [ ] aztec dep tag: `v0.87.0` → **`v4.0.0-devnet.2-patch.1`**, directory = `noir-projects/aztec-nr/aztec`
- [ ] att_verifier_lib: path = `../../../lib/att_verifier_lib`
- [ ] `compiler_version = ">=0.25.0"`
- [ ] `type = "contract"`

### 3.2 Fix imports (drop `dep::` prefix)
- [ ] `use dep::aztec::macros::aztec` → `use aztec::macros::aztec`
- [ ] All `dep::aztec::` → `aztec::`
- [ ] Import macros correctly:
  ```noir
  use aztec::macros::{
      functions::{external, initializer, only_self, view},
      storage::storage,
  };
  ```

### 3.3 Fix function annotations
- [ ] Constructor: `#[external("public")] #[initializer]` ✓ (was correct)
- [ ] Public functions: `#[external("public")]` ✓ (was correct)
- [ ] Private functions: `#[external("private")]` ✓ (was correct)
- [ ] Internal-only public functions: `#[internal]` → **`#[external("public")] #[only_self]`**
- [ ] View functions: add **`#[view]`** attribute

### 3.4 Fix storage access pattern
- [ ] ALL `storage.X.read()` → **`self.storage.X.read()`**
- [ ] ALL `storage.X.write(v)` → **`self.storage.X.write(v)`**
- [ ] ALL `storage.X.at(k)` → **`self.storage.X.at(k)`**
- [ ] ALL `storage.X.initialize(v)` → **`self.storage.X.initialize(v)`**

### 3.5 Fix msg_sender
- [ ] ALL `context.msg_sender()` → **`self.msg_sender()`** (no `.unwrap()`)

### 3.6 Fix private→public enqueue pattern
- [ ] `JwksRegistry::at(context.this_address()).store_jwk(...).enqueue(&mut context)` →
      **`self.enqueue_self.store_jwk(...)`**
- [ ] `store_jwk` function needs `#[external("public")] #[only_self]` (not `#[internal]`)

### 3.7 Fix `context.this_address()` → `self.address`

### 3.8 Fix types.nr Serialize/Deserialize
- [ ] Verify `Serialize` and `Deserialize` trait paths: `use aztec::protocol::traits::{Serialize, Deserialize}`
- [ ] Verify StoredJwk default value works with PublicMutable (may need a `Default` impl or zero-check)

### 3.9 Compile check
- [ ] `nargo compile` exits 0
- [ ] No warnings

### 3.10 Tests
- [ ] Write Noir unit test: deploy registry, call `admin_set_jwk`, read back via `get_jwk`, assert match
- [ ] Write Noir unit test: `revoke_jwk` sets `is_valid = false`
- [ ] Write Noir unit test: non-admin cannot call `admin_set_jwk` (assert failure)
- [ ] Write TypeScript integration test: deploy to sandbox, set key, verify on-chain
- [ ] `nargo test` exits 0
- [ ] TypeScript tests pass

---

## Phase 4: ZkLogin Contract

### 4.1 Fix Nargo.toml
- [ ] aztec dep tag: **`v4.0.0-devnet.2-patch.1`**
- [ ] jwt dep: point to **forked noir-jwt** (Phase 2)
- [ ] jwks_registry dep: path-based dependency for cross-contract interface
- [ ] `compiler_version = ">=0.25.0"`
- [ ] `type = "contract"`

### 4.2 Fix imports
- [ ] Drop all `dep::` prefixes
- [ ] `use jwt::JWT` (not `dep::jwt::JWT`)
- [ ] `use std::hash::pedersen_hash`
- [ ] Import aztec macros correctly (same pattern as Phase 3)

### 4.3 Fix function annotations
- [ ] `bind_account`: `#[external("private")]` ✓
- [ ] `store_binding`: `#[internal]` → **`#[external("public")] #[only_self]`**
- [ ] View functions: add `#[view]`

### 4.4 Fix storage access
- [ ] ALL `storage.X` → **`self.storage.X`**

### 4.5 Fix context access
- [ ] `context.msg_sender()` → **`self.msg_sender()`**
- [ ] `context.push_nullifier(x)` → **`self.context.push_nullifier(x)`**
- [ ] `context.this_address()` → **`self.address`**

### 4.6 Fix private→public enqueue
- [ ] `ZkLogin::at(context.this_address()).store_binding(...).enqueue(&mut context)` →
      **`self.enqueue_self.store_binding(...)`**

### 4.7 Fix cross-contract call to JwksRegistry
- [ ] In `store_binding` (public function):
  ```noir
  // Wrong:
  let stored_jwk = jwks_registry::JwksRegistry::at(registry_address)
      .get_jwk(provider_id, kid_hash).call(&mut context);
  // Correct:
  let stored_jwk = self.call(
      jwks_registry::JwksRegistry::at(registry_address).get_jwk(provider_id, kid_hash)
  );
  ```

### 4.8 Fix noir-jwt usage
- [ ] `JWT::init()` takes `[u128; 18]` for limbs — verify function signature matches
- [ ] `jwt.verify()` takes `mut self` — verify called correctly
- [ ] `jwt.assert_claim_string("iss".as_bytes(), BoundedVec::from_array("https://accounts.google.com".as_bytes()))` — verify exact syntax
- [ ] `jwt.get_claim_string::<3, MAX_SUB_LENGTH>("sub".as_bytes())` — verify turbofish syntax for MAX_VALUE_LENGTH
- [ ] `BoundedVec::from_array(...)` is a real method ✓

### 4.9 Fix `field_to_hex_bytes` helper
- [ ] `value.to_be_bytes()` — verify this works for Field→[u8; 32] in Noir 1.0.0-beta.18
- [ ] May need `value.to_be_bytes::<32>()` with explicit generic
- [ ] Verify hex encoding logic produces correct output

### 4.10 Fix `hash_bytes_to_field` helper
- [ ] `pedersen_hash(fields)` where `fields: [Field; 9]` — verify `std::hash::pedersen_hash` accepts fixed-size arrays

### 4.11 Compile check
- [ ] `nargo compile` exits 0
- [ ] No warnings

### 4.12 Tests
- [ ] Noir unit test: construct JWT with test RSA key, call `bind_account`, verify nullifier is pushed
- [ ] Noir unit test: wrong nonce → assertion failure
- [ ] Noir unit test: wrong issuer → assertion failure
- [ ] Noir unit test: `hash_bytes_to_field` is deterministic for same input
- [ ] Noir unit test: `field_to_hex_bytes` round-trips correctly
- [ ] `nargo test` exits 0

---

## Phase 5: TypeScript Registry Scripts

### 5.1 Fix package.json
- [ ] All `@aztec/*` packages at **`4.0.0-devnet.2-patch.1`** (NOT `0.87.0`)
- [ ] `npm install` succeeds

### 5.2 jwk-transform.ts
- [ ] `base64UrlDecode` — use `Buffer.from(str, 'base64url')` (Node.js native, not `atob`)
- [ ] `computeKidHash` — implement with actual `@aztec/bb.js` Pedersen hash (not placeholder)
- [ ] Verify `splitBigIntToLimbs` produces same output as noir-jwt JS SDK's `splitBigIntToChunks`
- [ ] Verify `computeRedcParams` matches noir-jwt JS SDK's formula: `(1n << (2n * 2048n + 4n)) / modulus`

### 5.3 update-registry.ts
- [ ] Use `@aztec/aztec.js` v4 API (`createPXEClient`, etc.)
- [ ] Verify contract artifact import path matches compiled output

### 5.4 Tests
- [ ] `base64UrlDecode` test: decode known JWK modulus, compare with expected BigInt
- [ ] `splitBigIntToLimbs` test: split, reconstruct, assert equal
- [ ] `computeRedcParams` test: verify `redc * modulus <= 2^4100 < redc * modulus + modulus`
- [ ] Fetch real Google JWKS, process all keys, verify no errors
- [ ] Fetch real Apple JWKS, process all keys, verify no errors
- [ ] `npm test` / `vitest run` exits 0

---

## Phase 6: Web App

### 6.1 Fix package.json
- [ ] `@aztec/aztec.js` at **`4.0.0-devnet.2-patch.1`**
- [ ] `npm install` succeeds

### 6.2 nonce.ts
- [ ] Implement with real `@aztec/bb.js` Pedersen hash
- [ ] `computeNonce` returns deterministic hex string for same inputs
- [ ] localStorage round-trip works (store, retrieve, clear)

### 6.3 providers.ts
- [ ] `buildAuthUrl` produces valid Google OAuth URL with all required params
- [ ] `buildAuthUrl` produces valid Apple OAuth URL
- [ ] `extractIdToken` parses `#id_token=xxx&state=yyy` correctly
- [ ] `decodeJwt` correctly decodes a Base64URL JWT

### 6.4 jwt-inputs.ts
- [ ] Integrate real `noir-jwt` JS SDK (`generateInputs`)
- [ ] Verify output format matches contract's `bind_account` parameters

### 6.5 BindAccount.tsx
- [ ] Uses `@aztec/aztec.js` v4 API for wallet connection
- [ ] Constructs correct contract method call matching `bind_account` signature

### 6.6 Tests
- [ ] Unit test: `computeNonce` is deterministic
- [ ] Unit test: `extractIdToken` parses fragment correctly
- [ ] Unit test: `decodeJwt` decodes known JWT
- [ ] `npm run build` (TypeScript + Vite) exits 0 with no errors

---

## Phase 7: End-to-End Integration Tests

### 7.1 Test infrastructure
- [ ] Aztec sandbox running at `http://localhost:8080`
- [ ] 3 test wallets created (admin, userA, userB)
- [ ] Test RSA-2048 key pair generated via `crypto.generateKeyPairSync`

### 7.2 Contract deployment tests
- [ ] Deploy JwksRegistry with admin wallet → succeeds, address non-zero
- [ ] Deploy ZkLogin with registry address → succeeds, address non-zero

### 7.3 Registry population tests
- [ ] `admin_set_jwk(GOOGLE, kidHash, modulus, redc)` → succeeds
- [ ] `get_jwk(GOOGLE, kidHash)` returns matching modulus and `is_valid == true`
- [ ] Non-admin calling `admin_set_jwk` → reverts

### 7.4 Bind account tests
- [ ] **Happy path**: mock JWT (iss=google, sub="user-12345", nonce bound to userA)
      → `bind_account()` succeeds
      → `is_address_bound(userA)` returns `true`
- [ ] **Sybil resistance**: same sub="user-12345", nonce bound to userB
      → `bind_account()` fails (nullifier collision)
- [ ] **Different identity**: sub="user-67890", nonce bound to userB
      → `bind_account()` succeeds
- [ ] **Multi-provider**: sub="user-12345" with provider_id=APPLE, nonce bound to userA
      → succeeds (different nullifier because different provider_id)

### 7.5 Nonce binding tests
- [ ] JWT with nonce NOT matching caller's address → `bind_account()` fails
- [ ] JWT with correct nonce but submitted by different address → fails

### 7.6 Key validation tests
- [ ] `bind_account()` with RSA key not in registry → `store_binding` reverts
- [ ] `bind_account()` with revoked JWK → `store_binding` reverts

### 7.7 All tests pass
- [ ] `vitest run` exits 0
- [ ] All 10+ integration test cases green

---

## Phase 8: Permissionless Registry Updates (Primus zkTLS)

### 8.1 Primus attestation integration
- [ ] `set_attestor_key` stores a Primus secp256k1 public key
- [ ] `update_jwk` with valid attestation → stores JWK
- [ ] `update_jwk` with invalid signature → reverts
- [ ] `update_jwk` with URL not in allowed list → reverts
- [ ] `update_jwk` with unregistered attestor key → reverts

### 8.2 Update script with real attestations
- [ ] Script fetches Google JWKS with Primus attestation
- [ ] Script submits `update_jwk` transaction
- [ ] Key appears in registry via `get_jwk`

### 8.3 Tests
- [ ] TypeScript test with mock Primus attestation → `update_jwk` succeeds
- [ ] TypeScript test with tampered attestation → reverts
- [ ] All tests pass

---

## Quick Reference: Correct Aztec v4.0.0-devnet.2-patch.1 Patterns

```noir
use aztec::macros::aztec;  // NO dep:: prefix

#[aztec]
pub contract MyContract {
    use aztec::macros::{
        functions::{external, initializer, only_self, view},
        storage::storage,
    };
    use aztec::protocol::address::AztecAddress;
    use aztec::state_vars::{Map, PublicImmutable, PublicMutable};

    #[storage]
    struct Storage<Context> {
        admin: PublicImmutable<AztecAddress, Context>,
        data: Map<Field, PublicMutable<Field, Context>, Context>,
    }

    #[external("public")]
    #[initializer]
    fn constructor(admin: AztecAddress) {
        self.storage.admin.initialize(admin);     // self.storage, not storage
    }

    #[external("public")]
    fn set_data(key: Field, value: Field) {
        let caller = self.msg_sender();           // self.msg_sender(), no .unwrap()
        let admin = self.storage.admin.read();
        assert(caller == admin, "not admin");
        self.storage.data.at(key).write(value);
    }

    #[external("private")]
    fn do_private_thing(x: Field) {
        self.context.push_nullifier(x);           // self.context.push_nullifier()
        self.enqueue_self.public_callback(x);     // self.enqueue_self for own public fn
    }

    #[external("public")]
    #[only_self]
    fn public_callback(x: Field) {
        self.storage.data.at(0).write(x);
    }

    #[external("public")]
    #[view]
    fn get_data(key: Field) -> Field {
        self.storage.data.at(key).read()
    }

    // Cross-contract call from public function:
    // self.call(OtherContract::at(addr).some_func(args))

    // Cross-contract call from private function:
    // self.enqueue(OtherContract::at(addr).some_public_func(args))
}
```
