 Specification: zkLogin-Style Sybil Protection on Aztec

 Context

 The goal is to implement a privacy-preserving identity binding system on Aztec where users prove ownership of a Google or Apple account via
 ZK-verified JWTs, and bind that identity to an AztecAddress with sybil resistance (same identity cannot bind to two different addresses). This
  consists of two subprojects: a permissionless JWKS key registry backed by Primus Labs zkTLS attestations, and a login contract + web app for
 the actual identity binding.

 Key discovery from research: Both Apple and Google sign JWTs with RS256 (RSA-SHA256, 2048-bit keys). Apple
 JWKS endpoint (https://appleid.apple.com/auth/keys) returns 4 RS256 keys; Google (https://www.googleapis.com/oauth2/v3/certs) returns 2. This
 means a single RSA verification path handles both providers.

 zkTLS provider: Primus Labs ZKTLS Verification Noir — an existing library (built by HashCloak) that verifies Primus zkTLS attestations inside
 Aztec contracts. Currently targets Aztec v3; needs porting to v4.

 ---
 Project Structure

 aztec-sybil-protection/
   Report.md                           # (existing) Research report
   registry/
     contracts/jwks_registry/
       Nargo.toml                      # Depends on aztec-nr v4 + att_verifier_lib (Primus)
       src/
         main.nr                       # JwksRegistry Aztec contract
         types.nr                      # StoredJwk, provider constants
     scripts/
       package.json
       src/
         update-registry.ts            # Node.js script: fetch JWKS + submit with Primus attestation
         jwk-transform.ts             # JWK Base64URL modulus -> 18 BigNum limbs conversion
       test/
         registry.test.ts              # Registry integration tests
   login/
     contracts/zk_login/
       Nargo.toml                      # Depends on aztec-nr v4 + noir-jwt v0.5.1+
       src/
         main.nr                       # ZkLogin contract (bind_account)
         types.nr                      # Shared types, MAX constants
     webapp/
       package.json
       src/
         App.tsx
         lib/
           nonce.ts                    # Nonce = hex(pedersen(address, randomness))
           jwt-inputs.ts               # noir-jwt SDK wrapper (generateInputs)
           providers.ts                # Google/Apple OAuth configuration
         components/
           BindAccount.tsx             # Main UI component
     test/
       integration.test.ts            # End-to-end test
   lib/
     att_verifier_lib/                 # Forked + ported from primus-labs/zktls-verification-noir
       Nargo.toml                      # Pure Noir library (no Aztec dependency)
       src/lib.nr                      # verify_attestation_comm(), verify_attestation_hashing()

 ---
 Primus Labs zkTLS: How It Works

 Primus is a zkTLS oracle service that fetches data from web APIs over TLS, then creates cryptographic attestations proving the response
 content is authentic. The existing Noir library (att_verifier_lib) verifies these attestations inside Aztec contracts.

 Attestation Format

 A Primus attestation contains:
 - recipient: Ethereum-style address (the requester)
 - request: URL, headers, method, body of the HTTPS request
 - responseResolves: Key names, parse types, and parse paths for extracting data from the response
 - data: Either Pedersen commitments (Grumpkin curve) or SHA-256 hashes of response content
 - timestamp: When the attestation was created
 - signature: 65-byte ECDSA secp256k1 signature (r|s|v)

 Signed Message Construction

 The signed message is keccak256(encodePacked(...)) where encodePacked concatenates:
 1. recipient address bytes
 2. keccak256(url + header + method + body) — request hash
 3. keccak256(keyName + parseType + parsePath) — response resolve hash
 4. Raw data string bytes
 5. Raw attConditions string bytes
 6. timestamp as big-endian uint64
 7. Raw additionParams string bytes

 Two Verification Modes

 Hash-based (simpler, recommended for JWKS registry):
 - The data field contains SHA-256 hashes of plaintext JSON response segments
 - Circuit verifies: sha256(provided_plaintext) == hash_in_attestation
 - The plaintext JWKS JSON is available as a private witness

 Commitment-based (stronger privacy):
 - The data field contains Pedersen commitments on the Grumpkin curve: C = m*G + r*H
 - Circuit verifies: m*G + r*H == C for each commitment
 - Uses std::embedded_curve_ops for Grumpkin arithmetic

 Verification in Noir (from att_verifier_lib)

 // Hash-based verification signature
 pub fn verify_attestation_hashing(
     public_key_x: [u8; 32],
     public_key_y: [u8; 32],
     hash: [u8; 32],                    // keccak256 of packed attestation
     signature: [u8; 64],               // ECDSA secp256k1 signature (r|s)
     request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
     allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
     data_hashes: [[u8; 32]; 2],        // SHA-256 hashes from attestation
     plain_json_response_contents: [BoundedVec<u8, MAX_RESPONSE_LEN>; 2],
 ) -> [Field; 2]                        // Poseidon2 hashes of matched allowed URLs

 Internally:
 1. std::ecdsa_secp256k1::verify_signature(pub_key_x, pub_key_y, signature, hash) — verifies attestor signed this data
 2. URL prefix matching via string_search::substring_match — ensures request URL matches an allowed URL
 3. sha256_var(plaintext) == data_hash — ensures plaintext matches the attested hash
 4. Returns Poseidon2(allowed_url) hashes for public-side validation against on-chain whitelist

 Aztec v3→v4 Porting Required

 The Primus library (att_verifier_lib) is pure Noir with no Aztec dependency — it should work with updated Noir stdlib versions. The contract
 templates target Aztec v3.0.0-devnet.6-patch.1 and need these changes for v4:

 ┌─────────────────────────────────────────────────────────────────────┬───────────────────────────────────────────────────────────┐
 │                             v3 Pattern                              │                       v4 Equivalent                       │
 ├─────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
 │ use dep::aztec::...                                                 │ use aztec::... (drop dep:: prefix)                        │
 ├─────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
 │ #[external("private")] / #[external("public")]                      │ #[private] / #[public]                                    │
 ├─────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
 │ self.msg_sender().unwrap()                                          │ context.msg_sender()                                      │
 ├─────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
 │ self.context / self.storage / self.address                          │ &mut context / storage / direct access                    │
 ├─────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
 │ .enqueue(self.context)                                              │ .enqueue(&mut context)                                    │
 ├─────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
 │ self.emit(event)                                                    │ context.emit(event)                                       │
 ├─────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
 │ PublicMutable::initialize()                                         │ Check v4 API                                              │
 ├─────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
 │ Library deps (string_search v0.3.3, poseidon v0.1.1, sha256 v0.2.1) │ Bump to versions compatible with Noir bundled in Aztec v4 │
 └─────────────────────────────────────────────────────────────────────┴───────────────────────────────────────────────────────────┘

 The att_verifier_lib library uses string_search, poseidon, and sha256 — all official Noir-lang crates that should have v4-compatible versions.

 ---
 Registry Subproject

 JwksRegistry Contract

 Storage:
 #[storage]
 struct Storage<Context> {
     admin: PublicImmutable<AztecAddress, Context>,

     // (provider_id, kid_hash) -> StoredJwk
     // provider_id: 1=Google, 2=Apple. kid_hash: pedersen_hash(kid_bytes)
     jwks: Map<Field, Map<Field, PublicMutable<StoredJwk, Context>, Context>, Context>,

     // Primus attestor public keys (secp256k1), indexed by attestor_index
     attestor_keys_x: Map<Field, PublicMutable<[u8; 32], Context>, Context>,
     attestor_keys_y: Map<Field, PublicMutable<[u8; 32], Context>, Context>,
     attestor_count: PublicMutable<Field, Context>,

     // Allowed URL hashes (Poseidon2 hashes of whitelisted JWKS endpoint URLs)
     allowed_url_hashes: PublicMutable<[Field; 3], Context>,
 }

 Where StoredJwk is:
 struct StoredJwk {
     modulus_limbs: [Field; 18],      // RSA-2048 modulus as 18x120-bit limbs (matches noir-jwt format)
     redc_params_limbs: [Field; 18],  // Barrett reduction params for noir_rsa
     is_valid: bool,
 }

 Functions:

 ┌────────────────────────────────────────────────────┬────────────────┬──────────────────────────────────────────────────────────────────┐
 │                      Function                      │   Visibility   │                             Purpose                              │
 ├────────────────────────────────────────────────────┼────────────────┼──────────────────────────────────────────────────────────────────┤
 │ constructor(admin, allowed_url_hashes)             │ public,        │ Sets admin, stores Poseidon2 hashes of allowed JWKS URLs         │
 │                                                    │ initializer    │                                                                  │
 ├────────────────────────────────────────────────────┼────────────────┼──────────────────────────────────────────────────────────────────┤
 │ set_attestor_key(index, pub_key_x, pub_key_y)      │ public         │ Admin-only: register Primus attestor secp256k1 public keys       │
 ├────────────────────────────────────────────────────┼────────────────┼──────────────────────────────────────────────────────────────────┤
 │ update_jwk(primus_attestation_fields...,           │                │ Permissionless: verify Primus ECDSA attestation via              │
 │ provider_id, kid_hash, modulus_limbs,              │ private        │ att_verifier_lib::verify_attestation_hashing(), extract JWKS     │
 │ redc_params_limbs)                                 │                │ data, enqueue storage update                                     │
 ├────────────────────────────────────────────────────┼────────────────┼──────────────────────────────────────────────────────────────────┤
 │ _store_jwk(provider_id, kid_hash, modulus_limbs,   │ public,        │ Verify URL hashes match on-chain allowed list, store JWK         │
 │ redc_params_limbs, url_hashes)                     │ only_self      │                                                                  │
 ├────────────────────────────────────────────────────┼────────────────┼──────────────────────────────────────────────────────────────────┤
 │ _admin_set_jwk(provider_id, kid_hash,              │ public         │ Admin-only: directly set a JWK (for bootstrapping/testing)       │
 │ modulus_limbs, redc_params_limbs)                  │                │                                                                  │
 ├────────────────────────────────────────────────────┼────────────────┼──────────────────────────────────────────────────────────────────┤
 │ get_jwk(provider_id, kid_hash) -> StoredJwk        │ unconstrained  │ Read a JWK entry                                                 │
 │                                                    │ view           │                                                                  │
 └────────────────────────────────────────────────────┴────────────────┴──────────────────────────────────────────────────────────────────┘

 update_jwk Private Function — Detail

 This function is the permissionless path. It takes the full Primus attestation as private inputs:

 #[private]
 fn update_jwk(
     // Primus attestation data (private witnesses)
     attestor_pub_key_x: [u8; 32],
     attestor_pub_key_y: [u8; 32],
     attestation_hash: [u8; 32],         // keccak256 of packed attestation fields
     attestation_signature: [u8; 64],    // ECDSA secp256k1 (r|s)
     request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
     allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
     data_hashes: [[u8; 32]; 2],
     plain_json_response: [BoundedVec<u8, MAX_RESPONSE_LEN>; 2],

     // Extracted JWK data (caller pre-parses from plaintext response)
     provider_id: Field,
     kid_hash: Field,
     modulus_limbs: [Field; 18],
     redc_params_limbs: [Field; 18],
 )

 Logic:
 1. Call att_verifier_lib::verify_attestation_hashing(...) — verifies ECDSA signature, URL match, and SHA-256 hash of plaintext
 2. The returned url_hashes: [Field; 2] (Poseidon2 of matched URLs) are passed to the public function
 3. The plain_json_response contains the raw JWKS JSON — the circuit can optionally verify that modulus_limbs were correctly extracted from it
 (via noir_json_parser or string matching)
 4. Enqueue _store_jwk(provider_id, kid_hash, modulus_limbs, redc_params_limbs, url_hashes)

 _store_jwk Public Function:
 1. Verify url_hashes from the private function match storage.allowed_url_hashes.read() — ensures the attestation was for a whitelisted JWKS
 endpoint
 2. Verify attestor public key matches one of the stored attestor_keys_x/y entries
 3. Write storage.jwks.at(provider_id).at(kid_hash).write(StoredJwk { modulus_limbs, redc_params_limbs, is_valid: true })

 Phased approach: The _admin_set_jwk function provides a simpler admin-controlled path for initial development and testing. The update_jwk
 function with full Primus verification is built in parallel. Both paths coexist — the admin path for bootstrapping, the permissionless path
 for production.

 Registry Update Script (Node.js)

 update-registry.ts flow:
 1. Fetch JWKS JSON from Apple and Google endpoints
 2. For each key: convert Base64URL modulus n to 18 BigNum limbs (120 bits each), compute Barrett reduction params (floor(2^(2*2048+4) /
 modulus)), compute kid_hash = pedersen_hash(kid_bytes)
 3. Generate Primus zkTLS attestation for the HTTPS fetch (via Primus SDK / att_verifier_parsing from the Primus repo)
 4. Parse the attestation file to extract PublicData (signature, attestation fields) and PrivateData (plaintext response)
 5. For each key: construct and submit Aztec transaction calling update_jwk() (or _admin_set_jwk() for bootstrapping)
 6. Verify by calling get_jwk() view function

 jwk-transform.ts: Converts JWK modulus from Base64URL string to [Field; 18] limb format. Each limb = 120 bits.
 splitBigIntToChunks(modulusBigInt, 120n, 18).

 Primus attestation parsing: The Primus repo includes att_verifier_parsing/ — a TypeScript package that converts JSON attestation files into
 the exact argument format expected by the Noir verification functions. This should be reused directly.

 ---
 Login Subproject

 ZkLogin Contract

 Storage:
 #[storage]
 struct Storage<Context> {
     registry: PublicImmutable<AztecAddress, Context>,
     bindings: Map<Field, PublicMutable<AztecAddress, Context>, Context>,        // nullifier -> address
     bound_addresses: Map<AztecAddress, PublicMutable<bool, Context>, Context>,  // address -> is_bound
 }

 Core function: bind_account (private):

 #[private]
 fn bind_account(
     // JWT data (private witnesses — never leave PXE)
     jwt_data: BoundedVec<u8, 1024>,
     base64_decode_offset: u32,
     pubkey_modulus_limbs: [Field; 18],
     redc_params_limbs: [Field; 18],
     signature_limbs: [Field; 18],

     // Public inputs
     provider_id: pub Field,         // 1=Google, 2=Apple
     kid_hash: pub Field,            // pedersen_hash(JWT header kid)

     // Nonce binding (private)
     expected_nonce: BoundedVec<u8, 64>,
     nonce_randomness: Field,
 )

 Logic sequence:

 1. Verify JWT RS256 signature via noir-jwt: JWT::init(...).verify()
 2. Verify issuer: jwt.assert_claim_string("iss", "https://accounts.google.com") or "https://appleid.apple.com" based on provider_id
 3. Extract sub claim: jwt.get_claim_string("sub") — this is the unique, stable user identifier
 4. Verify nonce binds to caller: Nonce in JWT = hex(pedersen_hash([msg_sender, randomness])). Circuit recomputes this from msg_sender() and
 nonce_randomness, then asserts it matches the JWT's nonce claim. This prevents front-running.
 5. Compute identity nullifier: pedersen_hash([pedersen_hash_bytes(sub), provider_id]). Same identity always produces same nullifier. Different
  providers produce different nullifiers.
 6. Push nullifier: context.push_nullifier(identity_nullifier) — Aztec protocol rejects if nullifier already exists in the tree (protocol-level
  sybil resistance, atomic, permanent, no race conditions)
 7. Enqueue public binding: passes (identity_nullifier, msg_sender, provider_id, kid_hash, pubkey_modulus_limbs, redc_params_limbs) to
 _store_binding

 _store_binding (public, only_self):
 1. Read JwksRegistry via cross-contract call: JwksRegistry::at(registry_address).get_jwk(provider_id, kid_hash).call(&mut context)
 2. Assert stored modulus/redc match what was used in private JWT verification (18 field comparisons each)
 3. Assert stored JWK is_valid == true
 4. Assert bindings.at(nullifier).read() == AztecAddress::zero() (secondary check; nullifier tree is primary)
 5. Write bindings.at(nullifier) = bound_address and bound_addresses.at(bound_address) = true

 Why this private→public split: Private functions cannot read public state (the registry). So the private function verifies the JWT against
 user-supplied key material, and the public function retroactively validates that key material against the registry. If the keys don't match,
 the public function reverts, failing the entire transaction.

 Circuit cost estimate: ~70,000-100,000 constraints total (RSA-2048 ~7,131 gates + SHA-256 ~50-80k + Base64 decoding ~5-10k + claim extraction
 ~2-5k + Pedersen hashes ~1k). Proving time: ~3-8 seconds depending on device.

 Web App

 OAuth flow:
 1. User connects Aztec wallet → gets AztecAddress
 2. App generates nonce = hex(pedersen_hash([aztec_address, Fr.random()])), stores randomness locally
 3. App redirects to Google/Apple OAuth with nonce in authorization request, scope=openid, response_type=id_token
 4. User authenticates with provider → redirected back with JWT (id_token)
 5. App fetches current JWKS from provider, finds signing key by matching kid from JWT header
 6. App calls generateInputs() from noir-jwt JS SDK to prepare circuit inputs
 7. App submits bind_account() transaction via @aztec/aztec.js — PXE generates proof locally
 8. Transaction confirmed — identity bound

 What leaves the user's device: Only the ZK proof, nullifier, provider_id, kid_hash, and key material. The JWT, sub claim, email, and all
 private data stay on-device.

 What is visible on-chain: Nullifier (opaque hash), bound AztecAddress, provider_id (Google vs Apple), kid_hash. An observer sees "some Google
 user bound to address X" but cannot determine which Google user.

 ---
 Integration Test

 Test sequence (in login/test/integration.test.ts):

 1. Setup: Start aztec start --dev, create 3 test wallets (admin, userA, userB), generate a test RSA-2048 key pair
 2. Deploy registry: JwksRegistryContract.deploy(wallet, adminAddress, allowedUrlHashes)
 3. Populate registry: Call _admin_set_jwk() with test RSA key (bypasses Primus for testing)
 4. Deploy zkLogin: ZkLoginContract.deploy(wallet, registryAddress)
 5. Successful bind: Create mock JWT (iss=google, sub="user-12345", nonce bound to userA), sign with test RSA key, call bind_account() → assert
  success, verify is_address_bound(userA) == true
 6. Reject duplicate: Create another JWT with same sub="user-12345" but nonce bound to userB, call bind_account() → assert failure (nullifier
 collision)
 7. Different identity succeeds: JWT with sub="user-67890" bound to userB → assert success
 8. Multi-provider: userA binds to Apple (sub="apple-abc", provider_id=2) → assert success (different nullifier than Google binding)

 Mock JWT signing uses Node.js crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 }) + standard JWT construction
 with jsonwebtoken library.

 ---
 Security Model

 ┌────────────────────────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │         Attack         │                                                   Prevention                                                   │
 ├────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Sybil (same identity,  │ nullifier = pedersen_hash(sub_hash, provider_id) — protocol nullifier tree rejects duplicates                  │
 │ two addresses)         │                                                                                                                │
 ├────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Front-running (steal   │ JWT nonce = pedersen_hash(aztec_address, randomness) — circuit checks msg_sender() matches committed address   │
 │ JWT)                   │                                                                                                                │
 ├────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Fake RSA key           │ Public _store_binding validates key against JwksRegistry via cross-contract call                               │
 ├────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Replay (reuse JWT)     │ Nullifier already in tree — second tx fails at protocol level                                                  │
 ├────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Provider               │ Google/Apple know sub and could compute pedersen_hash(sub_hash, provider_id) to check on-chain nullifiers.     │
 │ deanonymization        │ Privacy tradeoff accepted for "loose sybil resistance". Future: add user-chosen salt (but must be              │
 │                        │ deterministic per identity to prevent sybil bypass)                                                            │
 ├────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Registry poisoning     │ Primus attestation ECDSA secp256k1 signature verified against stored attestor keys; Poseidon2 URL hash         │
 │                        │ validation ensures attestation was for a whitelisted JWKS endpoint                                             │
 └────────────────────────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

 Open Issues

 1. Primus v3→v4 porting: The att_verifier_lib and contract templates target Aztec v3. Need to update import paths (dep:: → bare), function
 annotations, context/storage patterns, and bump library dependency versions. The core library is pure Noir so the main risk is stdlib API
 changes.
 2. noir-jwt limb type: noir-jwt may use [u128; 18] internally while Aztec storage uses [Field; 18]. Explicit casts needed.
 3. JWT size: MAX_JWT_DATA_LENGTH=1024 covers standard Google/Apple JWTs. noir-jwt's partial hash optimization handles larger tokens if needed.
 4. Binding permanence: No recovery if user loses wallet access. Future work: time-locked rebinding or social recovery.
 5. JWKS JSON parsing in-circuit: The update_jwk private function receives the raw JWKS JSON as a private witness. Verifying that modulus_limbs
  were correctly extracted from this JSON requires either noir_json_parser (adds constraints) or trusting the caller (the public function still
  validates against the registry, so a bad parse just fails the tx). Recommended: trust the caller for extraction, rely on the attestation for
 authenticity.
 6. Primus attestation hash construction: The keccak256 of the packed attestation fields (~55k constraints) must be computed either in-circuit
 or passed as a pre-computed witness with the attestor signature verification proving its correctness. The existing att_verifier_lib takes the
 hash as input — the hash is computed off-chain in TypeScript and the ECDSA signature verification binds it to the attestor's authority.
 7. Circuit size for registry updates: Primus verification circuits are ~700k-800k gates (from Primus repo benchmarks). This is large but
 within Aztec's proving capacity. Registry updates are infrequent operations so proving time is less critical here.

 Implementation Sequence

 ┌───────┬───────────────────────────────────────────────────────────┬───────────────────────────────────┐
 │ Phase │                           Work                            │            Depends On             │
 ├───────┼───────────────────────────────────────────────────────────┼───────────────────────────────────┤
 │ 1     │ Port att_verifier_lib from Aztec v3 to v4 Noir            │ Primus repo, Aztec v4 Noir stdlib │
 ├───────┼───────────────────────────────────────────────────────────┼───────────────────────────────────┤
 │ 2     │ ZkLogin contract (bind_account with noir-jwt)             │ noir-jwt v0.5.1+, Aztec sandbox   │
 ├───────┼───────────────────────────────────────────────────────────┼───────────────────────────────────┤
 │ 3     │ JwksRegistry contract (admin-set keys for MVP)            │ Aztec sandbox                     │
 ├───────┼───────────────────────────────────────────────────────────┼───────────────────────────────────┤
 │ 4     │ Integration tests with mock JWTs + test RSA keys          │ Phase 2 + 3                       │
 ├───────┼───────────────────────────────────────────────────────────┼───────────────────────────────────┤
 │ 5     │ Web app (OAuth flow, nonce gen, tx submission)            │ Phase 2 + 3                       │
 ├───────┼───────────────────────────────────────────────────────────┼───────────────────────────────────┤
 │ 6     │ JwksRegistry permissionless path (update_jwk with Primus) │ Phase 1 + 3                       │
 ├───────┼───────────────────────────────────────────────────────────┼───────────────────────────────────┤
 │ 7     │ Registry update script with Primus attestations           │ Phase 6 + Primus SDK              │
 ├───────┼───────────────────────────────────────────────────────────┼───────────────────────────────────┤
 │ 8     │ E2E test with real Google/Apple JWTs on devnet            │ Phase 4 + 5                       │
 └───────┴───────────────────────────────────────────────────────────┴───────────────────────────────────┘

 Phase 1 (porting att_verifier_lib) and Phase 2 (ZkLogin contract) can proceed in parallel — they have no dependency on each other. Phase 2 is
 highest risk as it validates that noir-jwt works within an Aztec contract context.