# Sybil Protection on Aztec via Zero-Knowledge Proofs

## Comprehensive Report: Linking Aztec Accounts to Real-World Identity

---

## Executive Summary

Aztec's privacy-first architecture makes traditional sybil detection (on-chain activity analysis, address clustering) impossible by design. However, Aztec's powerful ZK proving capabilities — Noir language, UltraHonk proof system, native P-256 ECDSA support, RSA libraries, and recursive proof verification — make it uniquely well-suited for **ZK-based identity verification**. An Aztec smart contract can verify that a user controls a real-world identity (social media account, government ID, hardware device) without learning *which* identity, by verifying cryptographic signatures inside ZK circuits.

This report evaluates **10 auth pathways** across a trust spectrum from fully trustless (government passport PKI verification in ZK) to semi-trusted (zkTLS with attestor committees). The most immediately implementable pathways for Aztec are:

1. **ZKPassport** — Already built in Noir, strongest sybil resistance, trustless
2. **zkEmail** — Native Noir library (`zkemail.nr`), audited, proves social media ownership
3. **OAuth/zkLogin-style** — Verify Apple/Google JWTs in ZK using existing Noir libraries
4. **Device Attestation** — Verify Android hardware attestation chains in ZK

---

## Table of Contents

1. [Aztec's ZK Capabilities](#1-aztecs-zk-capabilities)
2. [Auth Pathway 1: Government Passport (ZKPassport / OpenPassport)](#2-auth-pathway-1-government-passport)
3. [Auth Pathway 2: zkEmail (Proof of Social Media / Email)](#3-auth-pathway-2-zkemail)
4. [Auth Pathway 3: OAuth2 / OpenID Connect (zkLogin-style)](#4-auth-pathway-3-oauth2--openid-connect)
5. [Auth Pathway 4: Passkeys / WebAuthn](#5-auth-pathway-4-passkeys--webauthn)
6. [Auth Pathway 5: Device Attestation (Android TEE / Apple App Attest)](#6-auth-pathway-5-device-attestation)
7. [Auth Pathway 6: World ID (Iris Biometrics)](#7-auth-pathway-6-world-id)
8. [Auth Pathway 7: zkTLS (TLSNotary / Reclaim / Opacity)](#8-auth-pathway-7-zktls)
9. [Auth Pathway 8: Anon Aadhaar (Indian Government ID)](#9-auth-pathway-8-anon-aadhaar)
10. [Auth Pathway 9: Semaphore-style Group Membership](#10-auth-pathway-9-semaphore-style-group-membership)
11. [Auth Pathway 10: Verifiable Credentials (Privado ID)](#11-auth-pathway-10-verifiable-credentials)
12. [Comparison Matrix](#12-comparison-matrix)
13. [Recommended Architecture](#13-recommended-architecture)

---

## 1. Aztec's ZK Capabilities

### Proof System

Aztec uses **Barretenberg**, a C++ cryptographic backend implementing several proof systems:

- **UltraHonk**: Primary proving system for private execution. PLONK-style arithmetization with custom gates and lookup tables.
- **MegaHonk**: Extended UltraHonk with databus support for the AVM (public execution).
- **ClientIVC**: Recursive proof composition on the client side via Goblin Plonk.
- **ProtoGalaxy**: Folding scheme for optimized recursive verification.

### Smart Contract Language: Noir

All Aztec smart contracts are written in **Noir**, a Rust-like DSL that compiles to ACIR (Abstract Circuit Intermediate Representation). Noir provides:

| Primitive | Status | Notes |
|---|---|---|
| **ECDSA secp256k1** | Standard library (blackbox) | Ethereum-compatible signatures |
| **ECDSA secp256r1** | Standard library (blackbox) | Passkey/WebAuthn P-256 signatures. ~2s proving, <3s in browser |
| **Schnorr** | Standard library (blackbox) | Over Grumpkin (embedded curve of BN254) |
| **EdDSA** | Standard library | Over Baby JubJub with Poseidon hash |
| **RSA** | Official library (`noir_rsa`) | PKCS#1 v1.5, up to 2048-bit. ~345ms proving |
| **SHA-256** | Standard library | Compression function built-in |
| **Keccak-256** | Library | ~55k constraints per hash |
| **Poseidon/Poseidon2** | Library | Most ZK-efficient hash |
| **Pedersen** | Standard library | ZK-native, returns Field element |
| **Blake2s/Blake3** | Standard library | Good performance/security tradeoff |
| **BLS12-381** | Community library | Pairing and signature verification (~2.4hr compile) |
| **JWT verification** | Library (`noir-jwt`) | RS256/ES256 JWT token verification |
| **DKIM email** | Library (`zkemail.nr`) | Email signature verification, audited by Consensys |
| **WebAuthn** | Library | WebAuthn credential signature verification |
| **Recursive proofs** | Standard library | `verify_proof()` blackbox for proof composition |

### Account Model

Aztec has **native protocol-level account abstraction** — every account is a smart contract. Built-in account types include Schnorr (default), ECDSA secp256k1, and ECDSA secp256r1 (passkey-compatible). Custom account contracts can implement arbitrary authentication logic.

The **PXE (Private Execution Environment)** runs locally on the user's device. Private functions execute entirely client-side, generating ZK proofs. Only proofs and encrypted outputs leave the device. **Oracles** (`#[oracle]` decorator) allow injecting off-chain data (JWTs, emails, attestations) into the proving process as private inputs.

### Key Insight for Sybil Resistance

The combination of:
1. Client-side proof generation (sensitive identity data never leaves the device)
2. Rich cryptographic primitives (RSA, ECDSA P-256, SHA-256)
3. Oracle system (inject external credentials as private witnesses)
4. Native account abstraction (bind identity proofs to account creation)

...means Aztec can verify real-world identity credentials entirely within ZK circuits, making it one of the most capable platforms for privacy-preserving sybil resistance.

---

## 2. Auth Pathway 1: Government Passport

### Overview

Users scan the NFC chip in their passport with a smartphone. The chip contains biographic data signed by the issuing country's Document Signing authority. A ZK circuit verifies this signature and produces a proof of passport validity without revealing any personal information.

### Trust Model: **Trustless** (government PKI only)

- Trust the issuing government's PKI (Country Signing Certificate Authority / CSCA)
- No attestor, no third-party service, no special hardware beyond an NFC-capable phone
- The CSCA root certificates are public and can be hardcoded or stored on-chain
- Proof generation is entirely local

### Implementations

**ZKPassport** — Built natively in **Noir** using **UltraHonk** (Barretenberg backend). Already used for sybil resistance on the Aztec testnet. RSA passport verification requires <1GB RAM, runnable on mobile devices.

**OpenPassport (now Self)** — Built in Circom/Groth16. Supports RSA, ECDSA, EdDSA, and DSA signature algorithms, covering ~50% of world passports (95%+ with CSCA-based architecture).

### Sybil Resistance Strength: **Very Strong**

- One passport per person (government-enforced uniqueness)
- Passport number or a derived identifier can serve as a nullifier
- Covers ~150 countries with NFC-enabled passports

### Implementation on Aztec

```
Architecture:
  1. User scans passport NFC chip via mobile app
  2. App extracts signed data (DG1/DG2 data groups)
  3. PXE oracle injects passport data as private witness
  4. Noir circuit verifies document signer's RSA/ECDSA signature
  5. Circuit computes nullifier = Poseidon(passport_identifier, app_scope)
  6. Public outputs: nullifier, validity flag, optional attributes (nationality, age > 18)
  7. Aztec contract checks nullifier uniqueness in public state
```

**Noir compatibility**: ZKPassport is already native Noir. This is the most immediately deployable pathway.

**Circuit cost**: RSA signature verification (~7,131 gates for 2048-bit) + SHA-256 hashing + Poseidon nullifier. Total proving time estimated at ~2-5 seconds on mobile.

### User Stories

**Phone (iPhone/Android):**
1. User opens the Aztec dApp in a mobile browser or native app
2. App prompts: "Scan your passport to verify your identity"
3. User holds their passport against the phone's NFC reader
4. Phone reads the signed data from the passport chip (takes 2-5 seconds)
5. The PXE generates a ZK proof locally on the phone (~5-10 seconds)
6. User sees: "Identity verified! Your account is now sybil-protected"
7. The proof and nullifier are submitted to the Aztec network
8. No personal data leaves the phone — only the proof

**Laptop (MacBook/PC):**
1. User opens the Aztec dApp in a browser
2. App shows a QR code or deep link: "Scan with your phone to verify"
3. User opens a companion mobile app, scans the QR code
4. Phone performs NFC passport scan and proof generation
5. Proof is relayed back to the browser session (via WebSocket or similar)
6. Browser submits the proof to the Aztec network

**Limitations:**
- Requires physical passport (not a digital copy)
- Requires NFC-capable phone (most modern smartphones)
- Not all passports have NFC chips (older passports, some countries)
- Laptop users need a phone as a secondary device for NFC scanning

---

## 3. Auth Pathway 2: zkEmail

### Overview

Users trigger an email from a social media platform (e.g., Twitter password reset email) and prove in ZK that they received a DKIM-signed email containing their username. DKIM (DomainKeys Identified Mail) is a standard protocol where mail servers sign outgoing emails with RSA, and the public key is published in DNS.

### Trust Model: **Mostly Trustless**

- Trust the sending mail server's DKIM signing (e.g., Google signs all Gmail, Twitter signs all notification emails)
- DKIM public keys are published in DNS (publicly verifiable)
- A registry (`registry.prove.email`) maintains 1M+ DKIM public keys
- No attestor or special hardware needed
- Proof generation is 100% client-side

The only trust assumption is that the mail provider's DKIM key is authentic (a DNS hijack could forge keys, but this is detectable and extremely rare for major providers).

### Sybil Resistance Strength: **Moderate to Strong**

- One proof per email address / social media account
- Strength depends on the underlying platform's sybil resistance (Twitter requires phone verification, making it moderately strong; Gmail accounts are easier to create)
- Can combine multiple email proofs (Twitter + GitHub + work email) for higher confidence

### Supported Identity Sources

Any service that sends DKIM-signed emails containing account identifiers:
- **Twitter/X** — "Forgot your password" emails contain `@username`
- **GitHub** — Notification emails contain username
- **Google** — Account security emails
- **Coinbase** — KYC-verified platform
- **Airbnb** — Identity-verified platform
- **Any corporate email** — Proves employment at a specific domain

### Implementation on Aztec

The `zkemail.nr` library is a **native Noir implementation**, audited by Consensys Diligence (December 2024). It uses `noir_rsa` for RSA signature verification.

```
Architecture:
  1. User triggers an email from the target service (e.g., Twitter password reset)
  2. User downloads the raw email (.eml file) or the app fetches it via IMAP
  3. PXE oracle injects the raw email as a private witness
  4. Noir circuit:
     a. Parses email headers to extract DKIM signature and signed fields
     b. Computes SHA-256 hash of the canonicalized headers/body
     c. Verifies RSA DKIM signature against the provider's public key
     d. Uses regex matching to extract the username/account ID from the email body
     e. Computes nullifier = Poseidon(account_id, provider_domain, app_scope)
  5. Public outputs: nullifier, provider domain, validity flag
  6. Aztec contract checks nullifier uniqueness
```

**Noir compatibility**: **Native**. `zkemail.nr` is production-ready.

**Circuit cost**: RSA-2048 verification (~7,131 gates) + SHA-256 hashing (dominant cost, ~66% of circuit) + regex matching. Total proving time estimated at ~3-8 seconds.

### User Stories

**Phone (iPhone/Android):**
1. User opens the Aztec dApp
2. App prompts: "Prove your Twitter account" and shows a button "Send verification email"
3. User taps the button — the app opens Twitter's password reset page in a browser
4. User enters their Twitter email and receives a reset email
5. The app accesses the email (via OAuth to Gmail/email provider, or user pastes raw email)
6. PXE generates ZK proof locally (~5-10 seconds)
7. User sees: "Twitter account @username verified!" (username is NOT sent to the network)
8. Only the nullifier and proof are submitted

**Laptop (MacBook/PC):**
1. User opens the Aztec dApp in browser
2. App prompts: "Prove your Twitter account"
3. User triggers a password reset email from Twitter
4. User downloads the raw .eml file from their email client (or the app connects to their email via IMAP/OAuth)
5. The browser-based PXE generates the ZK proof (WebAssembly, ~5-15 seconds)
6. Proof is submitted to the Aztec network

**Limitations:**
- Requires user to trigger an email from the target service (minor friction)
- Email content format may change (regex patterns need updating)
- Some email providers modify DKIM signatures when forwarding
- DKIM key rotation means the on-chain key registry needs periodic updates

---

## 4. Auth Pathway 3: OAuth2 / OpenID Connect

### Overview

Users authenticate with an OAuth provider (Google, Apple, Facebook, etc.) and receive a JWT identity token. A ZK circuit verifies the JWT signature and extracts the user's unique identifier (`sub` claim) without revealing it. This is the approach pioneered by Sui's zkLogin.

### Trust Model: **Semi-Trustless** (trust OAuth provider)

- Trust the OAuth provider (Google, Apple, etc.) to issue honest JWTs with correct `sub` claims
- Trust that the provider's signing keys (published at their JWKS endpoint) are authentic
- Provider signing keys rotate periodically — need an on-chain registry or oracle for current keys
- No trusted setup needed if using Noir/UltraHonk (unlike Sui's Groth16 which requires a ceremony)

### Sybil Resistance Strength: **Moderate**

- One identity per OAuth account (e.g., one per Google Account)
- Strength depends on provider's account creation barriers:
  - **Apple ID**: Relatively strong (phone number required, device binding)
  - **Google**: Moderate (phone verification required but can be bypassed)
  - **Facebook**: Moderate (phone/ID verification for new accounts)
  - **GitHub**: Weak (easy to create multiple accounts)
- A determined attacker can create multiple OAuth accounts, so this is best combined with other signals

### Signing Algorithms by Provider

| Provider | Algorithm | Key Type | ZK Cost |
|---|---|---|---|
| **Apple** | ES256 (ECDSA P-256) | Elliptic curve | Noir blackbox, ~2s proving |
| **Google** | RS256 (RSA-SHA256, 2048-bit) | RSA | `noir_rsa`, ~350ms + SHA-256 |
| **Facebook** | RS256 | RSA | Same as Google |
| **Microsoft** | RS256 | RSA | Same as Google |
| **Twitch** | RS256 | RSA | Same as Google |
| **Slack** | RS256 | RSA | Same as Google |

### Implementation on Aztec

Existing Noir libraries: `noir-jwt` (JWT verification) + `noir_rsa` (RSA signatures) + `std::ecdsa_secp256r1` (Apple ES256).

```
Architecture:
  1. User clicks "Sign in with Google/Apple" in the dApp
  2. Standard OAuth2 flow: user authenticates, dApp receives JWT
  3. dApp embeds a commitment to an ephemeral Aztec key in the OAuth nonce
     (nonce = Poseidon(ephemeral_pk, max_block, randomness))
  4. PXE oracle injects the JWT as a private witness
  5. Noir circuit:
     a. Parses JWT header to extract `kid` (key identifier)
     b. Verifies JWT signature (RSA or ECDSA) against provider's public key
     c. Extracts `sub` (unique user ID), `iss` (issuer), `aud` (app ID)
     d. Verifies nonce commitment binds to the ephemeral key
     e. Computes nullifier = Poseidon(sub, iss, salt, app_scope)
     f. Computes identity_commitment = Poseidon(sub, iss, aud, salt)
  6. Public outputs: nullifier, identity_commitment, ephemeral_pk, max_block
  7. Aztec contract checks nullifier uniqueness and ephemeral key validity

Key Management:
  - The `salt` is a user secret that prevents linking the on-chain identity
    to the OAuth account. Without the salt, no one (including the OAuth provider)
    can determine which account is behind the nullifier.
  - Provider JWK public keys must be maintained on-chain or in a trusted oracle.
    Options: (a) governance-updated registry, (b) periodic proof of DNS lookup,
    (c) multi-party oracle committee.
```

### User Stories

**Phone (iPhone/Android):**
1. User opens the Aztec dApp
2. Taps "Sign in with Apple" (or Google)
3. Native OAuth sheet appears (Face ID / fingerprint for Apple, Google sign-in page)
4. User authenticates — takes 2-3 seconds
5. App receives JWT, generates ZK proof locally (~3-5 seconds)
6. User sees: "Account verified via Apple ID"
7. Proof submitted to Aztec — the network never learns the Apple ID

**Laptop (MacBook/PC):**
1. User opens the Aztec dApp in browser
2. Clicks "Sign in with Google"
3. Google OAuth popup appears, user selects their account
4. Browser receives JWT, PXE generates ZK proof (~5-10 seconds in WebAssembly)
5. Proof submitted to Aztec

**Key Rotation Challenge:**
OAuth providers rotate their signing keys every few weeks. The Aztec contract needs a mechanism to track current valid keys:
- **Option A**: On-chain JWK registry updated by a multisig or governance
- **Option B**: Include a merkle proof of the JWK in the ZK circuit, with root updated by an oracle
- **Option C**: Accept proofs signed by any key that was valid within a recent time window

**Limitations:**
- Requires an internet-connected OAuth flow (cannot be done offline)
- JWT tokens expire (typically 1 hour) — proof must be generated promptly
- Provider key rotation requires on-chain infrastructure
- Provider could theoretically issue fraudulent JWTs (nation-state threat model)

---

## 5. Auth Pathway 4: Passkeys / WebAuthn

### Overview

Users authenticate using a passkey (FIDO2/WebAuthn credential) stored on their device. The passkey signs a challenge using ECDSA P-256, and a ZK circuit verifies this signature. This does NOT inherently provide sybil resistance (anyone can create multiple passkeys) — it must be combined with device attestation or another identity binding.

### Trust Model: **Varies**

- The passkey signature itself is **trustless** (standard ECDSA P-256)
- Sybil resistance requires an additional trust layer:
  - Device attestation (trust hardware manufacturer — Apple, Google, Yubico)
  - OR binding to an OAuth identity (trust OAuth provider)
  - OR using FIDO Metadata Service to verify authenticator model (trust FIDO Alliance)

### Sybil Resistance Strength: **Weak alone, Strong when combined**

- Passkeys alone: no sybil resistance (anyone can create unlimited passkeys)
- Passkey + device attestation: moderate (one per device, but people own multiple devices)
- Passkey + OAuth binding: moderate (one per OAuth account)

### Passkey Cryptographic Details

```
Signature computation:
  message = authenticatorData || SHA-256(clientDataJSON)
  signature = ECDSA_P256_Sign(privateKey, message)

authenticatorData contains:
  - rpIdHash (32 bytes): SHA-256 of relying party ID
  - flags (1 byte): user presence, user verification bits
  - signCount (4 bytes): monotonic counter

clientDataJSON contains:
  - type: "webauthn.get"
  - challenge: server-provided challenge (Base64URL)
  - origin: relying party origin
```

### Implementation on Aztec

Noir has native P-256 ECDSA verification via `std::ecdsa_secp256r1::verify_signature` (blackbox function). Aztec already ships a built-in `ecdsasecp256r1` account type.

```
Architecture (Passkey-as-Account):
  1. User creates a passkey for the Aztec dApp via WebAuthn API
  2. The passkey's P-256 public key becomes the account's authentication key
  3. For each transaction, the dApp calls navigator.credentials.get()
  4. The passkey signs the transaction hash
  5. The Aztec account contract verifies the P-256 signature in its entrypoint

  This gives UX parity with Apple Pay / biometric auth, but NO sybil resistance.

Architecture (Passkey + Sybil Layer):
  Combine the passkey account with one of the other auth pathways in this report.
  The passkey provides seamless authentication; the identity proof provides sybil resistance.
```

### User Stories

**Phone (iPhone):**
1. User opens the Aztec dApp
2. Taps "Create Account with Passkey"
3. iPhone Face ID / Touch ID prompt appears
4. User authenticates — passkey created in the Secure Enclave
5. Account contract deployed with the passkey's P-256 public key
6. For future transactions: tap "Confirm" → Face ID → signed → submitted
7. UX feels like Apple Pay — no seed phrases, no MetaMask popups

**Laptop (MacBook):**
1. User opens the Aztec dApp in Safari/Chrome
2. Clicks "Create Account with Passkey"
3. Touch ID prompt on MacBook (or phone prompt if using cross-device passkey)
4. Passkey created, account deployed
5. Future transactions: Touch ID → done

**Phone (Android):**
1. Same flow but using fingerprint/face unlock
2. Passkey stored in Google Password Manager or hardware security key
3. Android provides hardware attestation (see Pathway 5) for sybil resistance

**Limitations:**
- No sybil resistance without an additional identity layer
- Passkeys sync across devices (iCloud Keychain, Google Password Manager) — the "one device = one identity" assumption does not hold for synced passkeys
- Platform passkeys (Apple, Google) have no meaningful attestation for consumer use

---

## 6. Auth Pathway 5: Device Attestation

### Overview

Prove that a cryptographic key was generated inside genuine hardware (Apple Secure Enclave, Android TEE/StrongBox) by verifying the manufacturer's attestation certificate chain in a ZK circuit. This provides "proof of device" — harder to fake than software accounts.

### Trust Model: **Trust Hardware Manufacturer**

- **Android**: Trust Google's Hardware Attestation Root CA. The certificate chain proves the key lives in a TEE or StrongBox. Google maintains a revocation list.
- **Apple**: Trust Apple's App Attest Root CA. Proves the app runs on genuine Apple hardware, but does NOT attest individual passkeys. Apple consumer passkeys provide **zero attestation** (all-zero AAGUID, empty `attStmt`).
- Both require trusting that the hardware manufacturer's signing keys are not compromised

### Sybil Resistance Strength: **Moderate**

- One attestation per physical device
- A person with 3 phones gets 3 identities
- More resistant to bulk sybil attacks than OAuth (buying 100 phones is harder than creating 100 email accounts)
- Does not stop device farms, but raises the cost significantly

### Android Key Attestation (Strongest Path)

Android provides rich hardware attestation that is directly verifiable in ZK:

```
Certificate chain (3-4 levels):
  Leaf cert → Intermediate CA → Google Hardware Attestation Root

Leaf certificate contains attestation extension (OID 1.3.6.1.4.1.11129.2.1.17):
  KeyDescription {
    attestationSecurityLevel: TrustedEnvironment(1) | StrongBox(2)
    attestationChallenge: <app-provided challenge>
    hardwareEnforced: {
      origin: Generated (not imported)
      rootOfTrust: {
        verifiedBootKey, deviceLocked, verifiedBootState
      }
    }
  }
```

**ZK Circuit Design:**
```
  1. App generates a challenge, requests Android Key Attestation
  2. Android returns certificate chain with attestation extension
  3. PXE oracle injects the certificate chain as private witness
  4. Noir circuit:
     a. Verify each signature in the certificate chain (RSA or ECDSA)
     b. Check that the root certificate matches Google's known root
     c. Parse ASN.1 attestation extension
     d. Assert attestationSecurityLevel >= 1 (TrustedEnvironment)
     e. Assert key origin = Generated (not imported)
     f. Compute device_nullifier = Poseidon(attested_public_key, app_scope)
  5. Public outputs: device_nullifier, security_level, validity flag
  6. Aztec contract checks device_nullifier uniqueness
```

**Circuit cost**: 3x RSA-2048 verification (~21k gates) + ASN.1 parsing + SHA-256 hashing. Estimated 5-15 seconds proving time.

### Apple App Attest

Apple consumer passkeys provide **no attestation**. However, Apple App Attest can be used as a separate attestation pathway:

```
  1. Native iOS app calls DCAppAttestService.generateKey()
  2. Key pair generated in Secure Enclave
  3. App calls attestKey(_:clientDataHash:) with a challenge
  4. Apple returns CBOR-encoded attestation with x5c certificate chain:
     - Index 0: Credential certificate (contains public key)
     - Index 1: Apple intermediate CA
     - Chains to Apple App Attest Root CA
  5. ZK circuit verifies the certificate chain and extracts the public key
  6. Computes device_nullifier = Poseidon(attested_public_key, app_scope)
```

**Critical limitation**: App Attest requires a **native iOS/macOS app** — it cannot be used from a web browser. This means the Aztec dApp would need a native companion app for Apple device attestation.

### User Stories

**Phone (Android):**
1. User opens the Aztec dApp (native app or browser with companion app)
2. App prompts: "Verify your device to create an account"
3. App requests Android Key Attestation in the background
4. Android generates a TEE-backed key and returns the attestation chain
5. PXE generates ZK proof (~10-15 seconds on phone)
6. User sees: "Device verified — genuine Android hardware confirmed"
7. Proof submitted; the network knows "one real device" but not which

**Phone (iPhone):**
1. User opens the native Aztec companion app
2. App generates an App Attest key in the Secure Enclave
3. App calls Apple's attestation API with a challenge
4. PXE generates ZK proof (~5-10 seconds)
5. Result relayed to the dApp (if web-based, via QR code or deep link)

**Laptop (MacBook):**
1. No direct attestation path from a web browser on macOS
2. Must use either: (a) a native macOS app with App Attest, or (b) scan QR code with iPhone
3. After attestation on phone, proof can be used in the browser session

**Laptop (PC/Linux):**
1. No Apple/Google device attestation available
2. Alternative: use a hardware security key (YubiKey) with FIDO2 attestation
3. YubiKey provides packed attestation with a known AAGUID, verifiable against the FIDO Metadata Service

**Limitations:**
- Apple: requires native app (not browser-only), no attestation for synced passkeys
- Android: strongest path, but root certificate is rotating to ECDSA P-384 in 2026
- People own multiple devices — doesn't prevent multi-device sybils
- Emulators and rooted devices may bypass some attestation checks (though StrongBox attestation is robust)
- Certificate chain verification in ZK is expensive (multiple signature verifications)

---

## 7. Auth Pathway 6: World ID (Iris Biometrics)

### Overview

Worldcoin's World ID uses iris scanning at physical "Orb" devices to create a biometrically-unique identity. Users prove membership in the set of verified humans using a Semaphore-based ZK proof (Groth16 zkSNARK).

### Trust Model: **Trust Orb Hardware + AMPC System**

- Trust the Orb hardware integrity (tamper-resistant, two burned-in cryptographic keys)
- Trust the Anonymized Multi-Party Computation (AMPC) deduplication system
- Trust the Semaphore Groth16 trusted setup ceremony (400+ participants, July 2024)
- AMPC system is being transferred to independent custodians (UC Berkeley, University of Erlangen-Nuremberg)
- Iris images are NOT stored — only irreversible iris hashes

### Sybil Resistance Strength: **Very Strong**

- Biometric uniqueness — one iris per person
- Strongest possible sybil resistance (short of DNA)
- Cannot be faked without physical access to the Orb
- Per-scope nullifiers prevent double-registration

### Integration with Aztec

World ID proofs are **Groth16 zkSNARKs**. Verifying Groth16 inside a Noir/UltraHonk circuit is theoretically possible but prohibitively expensive (~20M constraints for pairing operations). Practical approaches:

**Option A: Independent Verification**
```
  1. User generates a World ID proof (Groth16) off-chain
  2. User also generates an Aztec circuit proof (UltraHonk) separately
  3. Both proofs share a common nullifier or commitment as a public input
  4. The Aztec contract verifies the linkage between the two proofs
  5. World ID Groth16 proof is verified by a separate on-chain verifier
     (if Aztec supports an L1 bridge or Groth16 verifier contract)
```

**Option B: Reimplementation in Noir**
```
  Reimplement Semaphore's core logic (Merkle membership + nullifier derivation)
  natively in Noir. This avoids Groth16 entirely:
  1. Maintain a Poseidon Merkle tree of identity commitments on Aztec
  2. User proves Merkle membership in Noir using native Poseidon hashing
  3. Nullifier = Poseidon(identity_secret, scope)

  Challenge: How do identity commitments get into the tree?
  Need a bridge from World ID's Ethereum state, or an independent enrollment process.
```

**Option C: Recursive Proof Wrapping**
```
  Use Noir's recursive proof verification to wrap the Groth16 proof.
  The outer Noir circuit verifies the inner Groth16 proof's public inputs
  without re-verifying the full proof. This requires a Groth16 verifier
  expressed as a Noir circuit — currently not implemented but architecturally possible.
```

### User Stories

**Phone (Any):**
1. User must first visit a physical World ID Orb location
2. Orb scans iris, generates identity commitment, inserts into Merkle tree
3. User downloads World App, which stores their identity secret
4. When accessing the Aztec dApp, user taps "Verify with World ID"
5. World App generates a Semaphore ZK proof (~2-5 seconds)
6. Proof is relayed to the Aztec dApp
7. dApp verifies or wraps the proof and submits to the Aztec network

**Laptop (Any):**
1. Same prerequisite: prior Orb enrollment
2. Browser-based dApp shows "Verify with World ID" button
3. QR code or deep link opens World App on phone
4. Phone generates proof, relays to browser

**Limitations:**
- Requires physical visit to an Orb device (limited global coverage)
- Groth16 proofs don't natively compose with Noir/UltraHonk
- Heavy infrastructure dependency on Worldcoin's network
- Controversial: biometric collection concerns, centralized hardware

---

## 8. Auth Pathway 7: zkTLS (TLSNotary / Reclaim / Opacity)

### Overview

zkTLS protocols allow a user to prove they received specific data from a web server over HTTPS, without the server's cooperation. A third-party "notary" or "attestor" participates in a multi-party computation (MPC) during the TLS handshake, enabling the user to prove the authenticity of the server's response.

### Trust Model: **Semi-Trusted** (requires attestor/notary)

All zkTLS approaches require a semi-trusted third party:

| Protocol | Trust Model | Decentralization |
|---|---|---|
| **TLSNotary** | Single Notary (MPC participant) | Notary cannot see plaintext, but must be trusted not to collude with Prover |
| **Reclaim Protocol** | Attestor nodes on EigenLayer AVS | Economic staking + slashing. 2,500+ data sources |
| **Opacity Network** | Committee of MPC nodes | Random sampling, on-chain logs, whistleblowing |
| **zkPass** | Three-Party TLS (3P-TLS) | Third-party TLS participant |

### Sybil Resistance Strength: **Varies by Data Source**

- Proves account ownership on any HTTPS website
- Strength depends entirely on the underlying service:
  - Bank account: very strong (KYC-verified)
  - LinkedIn: moderate (identity-verified for some users)
  - Twitter: moderate (phone verification)
  - Random website: weak

### Integration with Aztec

The zkTLS protocols produce **signed attestations** as their output. These attestations use standard signature schemes (ECDSA, EdDSA) that can be verified in Noir.

```
Architecture:
  1. User initiates a TLS session with the target service (e.g., twitter.com)
  2. An attestor participates in the MPC-TLS handshake
  3. Attestor signs an attestation: "User owns @username on twitter.com"
  4. PXE oracle injects the attestation as a private witness
  5. Noir circuit:
     a. Verifies the attestor's signature (ECDSA or EdDSA)
     b. Checks the attestor's public key against a known set of trusted attestors
     c. Extracts the identity claim from the attestation
     d. Computes nullifier = Poseidon(identity_claim, service, app_scope)
  6. Public outputs: nullifier, service identifier, validity flag
```

### User Stories

**Phone (Any):**
1. User opens the Aztec dApp
2. Taps "Prove your Twitter account via Reclaim"
3. App opens an in-app browser to twitter.com (routed through Reclaim's attestor network)
4. User logs into Twitter normally
5. Attestor verifies the TLS response showing the user's profile
6. Attestation signed and returned to the app
7. PXE generates ZK proof wrapping the attestation (~3-5 seconds)
8. Proof submitted to Aztec

**Laptop (Any):**
1. Similar flow in browser
2. Browser extension or popup initiates the attested TLS session
3. User logs into the target service
4. Attestation generated, proof created, submitted

**Limitations:**
- Requires an active attestor network (not self-sovereign)
- Attestor collusion could produce fraudulent attestations
- Adding new data sources requires attestor protocol updates
- TLS session is interactive (user must actively log in)
- Not fully trustless — the attestor is a trust assumption

---

## 9. Auth Pathway 8: Anon Aadhaar (Indian Government ID)

### Overview

Allows holders of Indian Aadhaar IDs (~1.4 billion people) to prove identity attributes via ZK proofs. The Aadhaar system issues QR codes signed by UIDAI (Indian government agency) using RSA-SHA256.

### Trust Model: **Trustless** (government PKI only)

- Trust UIDAI (Indian government) as the credential issuer
- RSA public key is hardcoded in the circuit
- No attestor, no hardware, no third-party service
- Proof generation is entirely local

### Sybil Resistance Strength: **Very Strong** (for Indian citizens)

- One Aadhaar per person (biometric deduplication at enrollment)
- Covers 1.4 billion people
- Government-enforced uniqueness

### Implementation on Aztec

The core operations (SHA-256 + RSA signature verification) have direct Noir library support.

```
Architecture:
  1. User opens Aadhaar QR code (from mAadhaar app or e-Aadhaar PDF)
  2. App scans the QR code
  3. PXE oracle injects QR data as private witness
  4. Noir circuit:
     a. Parses the signed data from the QR code
     b. Computes SHA-256 hash
     c. Verifies RSA-2048 signature against UIDAI's known public key
     d. Optionally reveals: age > 18, gender, state, zip code
     e. Computes nullifier = Poseidon(aadhaar_hash, app_scope)
  5. Public outputs: nullifier, selected attributes, validity flag
```

**Noir compatibility**: Directly portable. `noir_rsa` handles RSA verification, SHA-256 is built-in.

### User Stories

**Phone (Any):**
1. User opens the Aztec dApp
2. Taps "Verify with Aadhaar"
3. App opens camera to scan the Aadhaar QR code (printed or from mAadhaar app)
4. QR data extracted, ZK proof generated locally (~3-5 seconds)
5. User sees: "Aadhaar verified — age > 18 confirmed"

**Laptop (Any):**
1. User uploads their e-Aadhaar PDF or scans QR code via webcam
2. Browser PXE generates proof
3. Proof submitted

**Limitations:**
- Only works for Indian citizens with Aadhaar
- QR code format changes require circuit updates
- Trust in Indian government's identity system

---

## 10. Auth Pathway 9: Semaphore-style Group Membership

### Overview

A generic framework for anonymous group membership proofs. Users receive an identity commitment that is added to a Merkle tree. They can then prove membership without revealing which leaf they are, using ZK Merkle inclusion proofs with per-scope nullifiers.

### Trust Model: **Trustless** (if group is trustworthy)

- The ZK proof system itself is trustless
- The trust lies in **who manages the group** and **how members are admitted**
- If membership is gated by another sybil-resistant mechanism (passport, biometrics), the group inherits that mechanism's strength

### Sybil Resistance Strength: **Inherited from enrollment mechanism**

Semaphore itself is a framework, not a sybil solution. Its strength comes from whatever is used to gate group enrollment.

### Implementation on Aztec

Semaphore's core pattern (Poseidon Merkle tree + nullifier derivation) is extremely efficient in Noir:

```
Architecture:
  1. Identity: user generates identity_secret = random Field
  2. Commitment: identity_commitment = Poseidon(identity_secret)
  3. Enrollment: identity_commitment inserted into Poseidon Merkle tree (on-chain or via bridge)
  4. Proving: user generates Noir proof:
     a. Merkle inclusion proof (O(log n) Poseidon hashes for n members)
     b. Nullifier = Poseidon(identity_secret, external_nullifier)
     c. Signal = arbitrary data (vote, message, action)
  5. Verification: contract checks Merkle root + nullifier uniqueness

  Cost: For a tree of depth 20 (~1M members):
  - 20 Poseidon hashes for Merkle proof (~minimal, Poseidon is ZK-native)
  - 1 Poseidon hash for nullifier
  - 1 Poseidon hash for identity commitment verification
  - Total: ~22 Poseidon hashes — extremely fast, <1 second proving
```

### User Stories

This pathway is transparent to the user — it's an infrastructure layer. The user experience depends on the enrollment mechanism (passport scan, OAuth, etc.). After enrollment, Semaphore-style proofs are generated automatically by the PXE when the user takes any action.

**Limitations:**
- No sybil resistance on its own — only as strong as the enrollment gate
- Requires a Merkle tree state management mechanism on Aztec

---

## 11. Auth Pathway 10: Verifiable Credentials (Privado ID)

### Overview

Privado ID (formerly Polygon ID) implements W3C Verifiable Credentials with ZK proofs. Credential issuers sign credentials with EdDSA on Baby JubJub, and users prove credential attributes without revealing the full credential.

### Trust Model: **Trust Credential Issuer**

- Trust the entity issuing the credential (KYC provider, employer, university)
- The ZK proofs themselves are trustless
- Issuer signs with EdDSA on Baby JubJub — a curve native to BN254, highly efficient in Noir

### Sybil Resistance Strength: **Varies by Issuer**

- Government-issued VC: very strong
- KYC provider VC: strong
- Self-issued VC: none

### Implementation on Aztec

EdDSA on Baby JubJub is supported in Noir's standard library via `std::eddsa::eddsa_poseidon_verify`.

```
Architecture:
  1. User obtains a verifiable credential from an issuer (e.g., KYC provider)
  2. Credential contains: subject_id, attributes, issuer_signature (EdDSA)
  3. Issuer's identity commitment is stored in a Sparse Merkle Tree
  4. PXE oracle injects the credential as private witness
  5. Noir circuit:
     a. Verifies issuer's EdDSA signature on Baby JubJub
     b. Verifies issuer's identity commitment in the SMT
     c. Proves selected attributes (age, country, etc.)
     d. Computes nullifier = Poseidon(subject_id, app_scope)
  6. Public outputs: nullifier, attribute flags, issuer commitment root
```

### User Stories

**Phone/Laptop (Any):**
1. User first obtains a VC from a trusted issuer (one-time setup):
   - Visits a KYC provider (online or in-person)
   - Provider issues a signed VC stored in the user's digital wallet
2. When accessing the Aztec dApp:
   - App prompts "Prove your identity credential"
   - User selects the VC from their wallet
   - ZK proof generated locally (~1-2 seconds, EdDSA is fast)
   - Proof submitted

**Limitations:**
- Requires a separate credential issuance step
- Issuer must use Baby JubJub EdDSA (not all VC issuers do)
- Sparse Merkle Tree state must be bridged or maintained on Aztec

---

## 12. Comparison Matrix

| Pathway | Trust Model | Sybil Strength | Noir Ready? | Proving Time | Requires 3rd Party? | Coverage |
|---|---|---|---|---|---|---|
| **1. Passport (ZKPassport)** | Govt PKI | Very Strong | **Native Noir** | ~2-5s mobile | No | ~150 countries |
| **2. zkEmail** | DKIM (mail server) | Moderate-Strong | **Native Noir** | ~3-8s | No | Any email service |
| **3. OAuth/zkLogin** | OAuth provider | Moderate | Libraries exist | ~3-5s | OAuth provider | Google, Apple, etc. |
| **4. Passkeys** | None (alone) | None alone | **Native Noir** | ~2s | No | Universal |
| **5. Device Attestation** | HW manufacturer | Moderate | Feasible | ~5-15s | No | Android (strong), Apple (limited) |
| **6. World ID** | Orb HW + AMPC | Very Strong | Indirect | ~2-5s | Worldcoin infra | Limited Orb locations |
| **7. zkTLS** | Attestor network | Varies | Indirect | ~3-5s | **Yes** (attestor) | Any HTTPS site |
| **8. Anon Aadhaar** | Indian govt | Very Strong | Feasible | ~3-5s | No | India only |
| **9. Semaphore** | Enrollment gate | Inherited | Very efficient | <1s | No | N/A (framework) |
| **10. Verifiable Creds** | Credential issuer | Varies | Native (EdDSA) | ~1-2s | Issuer | Varies |

### Trustless vs. Semi-Trusted Summary

**Fully Trustless (no 3rd party service at verification time):**
- Government Passport (ZKPassport/OpenPassport)
- Anon Aadhaar
- zkEmail (trust only the mail server's existing DKIM infrastructure)
- Passkeys (for auth, not sybil)
- Semaphore (framework)

**Trust Hardware Manufacturer:**
- Device Attestation (Apple, Google)

**Trust Identity Provider:**
- OAuth/zkLogin (Google, Apple, Facebook)
- Verifiable Credentials (trust the issuer)

**Trust Active Third-Party Network:**
- World ID (Orb network, AMPC)
- zkTLS (attestor/notary network)

---

## 13. Recommended Architecture

### Tier 1: Deploy Now (Native Noir, Production-Ready)

**ZKPassport** for maximum sybil resistance:
- Already built in Noir, tested on Aztec testnet
- Strongest identity guarantee (government-issued, one per person)
- Best for high-stakes applications (governance, large airdrops)

**zkEmail** for social media identity binding:
- `zkemail.nr` is audited and production-ready
- Can prove Twitter, GitHub, Google, and other account ownership
- Good for community-based sybil resistance (prove membership in existing communities)

### Tier 2: Build Next (Libraries Exist, Assembly Required)

**OAuth/zkLogin** for frictionless onboarding:
- `noir-jwt` + `noir_rsa` / `std::ecdsa_secp256r1` provide the building blocks
- Most familiar UX (Sign in with Google/Apple)
- Requires JWK key management infrastructure on Aztec

**Passkey-based accounts** for UX:
- Aztec already supports `ecdsasecp256r1` accounts
- Combine with any of the above for sybil resistance + great UX

### Tier 3: Future Integration (Requires More Infrastructure)

**Device Attestation** for hardware-bound identity:
- Android path is strong; Apple path requires native app
- Certificate chain verification in ZK is expensive but feasible

**World ID** for biometric uniqueness:
- Requires Groth16-to-UltraHonk bridging or Semaphore reimplementation in Noir
- Strongest biometric guarantee

### Suggested Combined Architecture

```
                    ┌─────────────────────────────────────┐
                    │        Aztec Sybil Registry          │
                    │    (Public contract on Aztec L2)     │
                    │                                       │
                    │  Stores: nullifier → identity_tier    │
                    │  Checks: nullifier uniqueness         │
                    │  Emits: identity_verified events      │
                    └───────────┬───────────────────────────┘
                                │
                    ┌───────────┴───────────────────────────┐
                    │      Identity Verification Layer       │
                    │   (Noir circuits, runs in user PXE)   │
                    │                                       │
                    │   ┌──────────┐  ┌──────────┐         │
                    │   │ Passport │  │  zkEmail  │         │
                    │   │ (Tier 1) │  │ (Tier 1)  │         │
                    │   └──────────┘  └──────────┘         │
                    │   ┌──────────┐  ┌──────────┐         │
                    │   │  OAuth   │  │ Device   │         │
                    │   │ (Tier 2) │  │ (Tier 3) │         │
                    │   └──────────┘  └──────────┘         │
                    └───────────────────────────────────────┘
                                │
                    ┌───────────┴───────────────────────────┐
                    │         Aztec Account Layer            │
                    │                                       │
                    │   Account contract with passkey auth   │
                    │   (ecdsasecp256r1 for seamless UX)    │
                    │   + identity nullifier binding         │
                    └───────────────────────────────────────┘
```

**Scoring**: Applications can assign a sybil resistance score based on which pathways a user has completed:
- Passport proof: +100 points (strong uniqueness)
- zkEmail (Twitter): +30 points (moderate uniqueness)
- OAuth (Apple ID): +20 points (some barriers to multi-account)
- Device attestation: +15 points (proves genuine hardware)
- Threshold: applications set their own minimum score

This tiered approach allows users to choose their preferred verification method while giving applications flexibility in how much sybil resistance they require.

---

## Sources

### Aztec / Noir
- [Aztec Documentation](https://docs.aztec.network/)
- [Noir Language Documentation](https://noir-lang.org/docs/)
- [awesome-noir (GitHub)](https://github.com/noir-lang/awesome-noir)
- [Aztec Account Abstraction](https://docs.aztec.network/how-aztec-works/accounts)
- [Noir ECDSA Verification](https://noir-lang.org/docs/noir/standard_library/cryptographic_primitives/ecdsa_sig_verification)
- [noir_rsa (GitHub)](https://github.com/noir-lang/noir_rsa)
- [Aztec PXE Documentation](https://docs.aztec.network/aztec/concepts/pxe)
- [Client-side Proof Generation (Aztec Blog)](https://aztec.network/blog/client-side-proof-generation)

### Identity Protocols
- [ZKPassport Case Study (Aztec Blog)](https://aztec.network/blog/zkpassport-case-study-a-look-into-online-identity-verification)
- [ZKPassport Circuits (GitHub)](https://github.com/zkpassport/circuits)
- [zkemail.nr (GitHub)](https://github.com/zkemail/zkemail.nr)
- [zkEmail Noir Audit (Consensys Diligence)](https://diligence.security/audits/2024/12/zk-email-noir/)
- [noir-jwt (GitHub)](https://github.com/zkemail/noir-jwt)
- [OpenPassport / Self (GitHub)](https://github.com/zk-passport/openpassport)
- [Anon Aadhaar](https://documentation.anon-aadhaar.pse.dev/)

### OAuth / JWT
- [Sui zkLogin Documentation](https://docs.sui.io/concepts/cryptography/zklogin)
- [zkLogin Paper (ACM CCS 2024)](https://dl.acm.org/doi/10.1145/3658644.3690356)
- [Sign in with Apple](https://developer.apple.com/documentation/signinwithapple)
- [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)

### Device Attestation / Passkeys
- [WebAuthn Guide](https://webauthn.guide/)
- [Android Key Attestation (AOSP)](https://source.android.com/docs/security/features/keystore/attestation)
- [Apple App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
- [Cloudflare zkAttest](https://blog.cloudflare.com/introducing-zero-knowledge-proofs-for-private-web-attestation-with-cross-multi-vendor-hardware/)
- [Base - Benchmarking ZKP Systems](https://blog.base.dev/benchmarking-zkp-systems)

### Sybil Resistance Protocols
- [World ID Technical Implementation](https://whitepaper.worldcoin.org/technical-implementation)
- [Semaphore Protocol](https://docs.semaphore.pse.dev/)
- [TLSNotary](https://tlsnotary.org/docs/intro/)
- [Reclaim Protocol](https://blog.reclaimprotocol.org/posts/zk-in-zktls)
- [Privado ID](https://docs.privado.id/)
- [Gitcoin / Human Passport](https://passport.human.tech/)
- [Automata Proof of Machinehood](https://docs.ata.network/understanding-automata/what-is-automata/proof-of-machinehood)
