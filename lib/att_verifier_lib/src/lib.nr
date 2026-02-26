// Primus Labs zkTLS Attestation Verifier Library
// Ported from https://github.com/primus-labs/zktls-verification-noir/
// Pure Noir library - no Aztec dependency
//
// Verifies Primus zkTLS attestations inside ZK circuits.
// Two modes: commitment-based (Grumpkin Pedersen) and hash-based (SHA-256).

use poseidon::poseidon2::Poseidon2;
use sha256::sha256_var;
use std::embedded_curve_ops::{
    embedded_curve_add, EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul,
    multi_scalar_mul,
};
use string_search::{StringBody, StringBody1024, SubString, SubString1024};

pub global MAX_URL_LEN: u32 = 1024;
pub global MAX_CONTENT_LEN: u32 = 1000;

/// Verify a commitment-based Primus attestation.
///
/// 1. Verifies the ECDSA secp256k1 signature over the attestation hash.
/// 2. Checks that each request URL starts with one of the allowed URLs.
/// 3. Verifies Pedersen commitments: C == m*G + r*H for each commitment.
///
/// Returns Poseidon2 hashes of the matched allowed URLs (for on-chain validation).
pub fn verify_attestation_comm<let MAX_COMMS: u32>(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    coms: BoundedVec<EmbeddedCurvePoint, MAX_COMMS>,
    rnds: BoundedVec<Field, MAX_COMMS>,
    msgs_chunks: BoundedVec<Field, MAX_COMMS>,
    H: EmbeddedCurvePoint,
) -> [Field; 2] {
    // 1. Verify ECDSA secp256k1 signature
    assert(std::ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, signature, hash));

    // 2. Verify request URLs match allowed URL prefixes
    let allowed_url_matches = verify_url_prefixes(request_urls, allowed_urls);

    // 3. Verify Pedersen commitments: C == m*G + r*H
    for i in 0..MAX_COMMS {
        if i < coms.len() {
            assert(
                embedded_curve_add(
                    fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(msgs_chunks.get(i))),
                    multi_scalar_mul([H], [EmbeddedCurveScalar::from_field(rnds.get(i))]),
                )
                    == coms.get(i),
            );
        }
    }

    allowed_url_matches
}

/// Verify a hash-based Primus attestation.
///
/// 1. Verifies the ECDSA secp256k1 signature over the attestation hash.
/// 2. Checks that each request URL starts with one of the allowed URLs.
/// 3. Verifies SHA-256: sha256(plaintext) == data_hash for each response.
///
/// Returns Poseidon2 hashes of the matched allowed URLs (for on-chain validation).
pub fn verify_attestation_hashing(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    data_hashes: [[u8; 32]; 2],
    plain_json_response_contents: [BoundedVec<u8, MAX_CONTENT_LEN>; 2],
) -> [Field; 2] {
    // 1. Verify ECDSA secp256k1 signature
    assert(std::ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, signature, hash));

    // 2. Verify request URLs match allowed URL prefixes
    let allowed_url_matches = verify_url_prefixes(request_urls, allowed_urls);

    // 3. Verify SHA-256 hashes of plaintext responses
    for i in 0..2 {
        let computed_hash = sha256_var(
            plain_json_response_contents[i].storage(),
            plain_json_response_contents[i].len(),
        );
        assert(computed_hash == data_hashes[i]);
    }

    allowed_url_matches
}

/// Internal: verify that each request URL starts with one of the allowed URLs.
/// Returns Poseidon2 hashes of the matched allowed URLs.
fn verify_url_prefixes(
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
) -> [Field; 2] {
    let mut allowed_url_matches: [Field; 2] = [0; 2];
    for i in 0..2 {
        // Safety: find matching allowed URL index in unconstrained mode, then verify
        let (found, url_index) = unsafe { get_allowed_url_index(request_urls[i], allowed_urls) };
        assert(found == true, "No allowed URL matches the request URL");

        let request_url_haystack: StringBody1024 =
            StringBody::new(request_urls[i].storage(), request_urls[i].len());
        let allowed_url = allowed_urls[url_index];
        let needle: SubString1024 = SubString::new(allowed_url.storage(), allowed_url.len());

        let (result, match_position): (bool, u32) = request_url_haystack.substring_match(needle);
        assert(result & (match_position == 0), "URL check failed");

        // Hash the allowed URL for on-chain comparison
        let mut hash_input: [Field; 1024] = [0; 1024];
        for j in 0..1024 {
            if j < allowed_url.len() {
                hash_input[j] = allowed_url.storage()[j] as Field;
            }
        }
        allowed_url_matches[i] = Poseidon2::hash(hash_input, 1024);
    }
    allowed_url_matches
}

unconstrained fn search(
    haystack: BoundedVec<u8, MAX_URL_LEN>,
    needle: BoundedVec<u8, MAX_URL_LEN>,
) -> (bool, u32) {
    let haystack_length: u32 = haystack.len();
    let needle_length: u32 = needle.len();
    assert(needle_length > 0, "needle length of size 0 not supported");
    assert(haystack_length > 0, "haystack length of size 0 not supported");
    let mut found = false;
    let mut found_index: u32 = 0;
    for i in 0..haystack_length - needle_length + 1 {
        if found == true {
            break;
        }
        for j in 0..needle_length {
            if haystack.get(i + j) != needle.get(j) {
                break;
            } else if j == needle_length - 1 {
                found = true;
            }
            if found == true {
                found_index = i;
                break;
            }
        }
    }
    (found, found_index)
}

unconstrained fn get_allowed_url_index(
    request_url: BoundedVec<u8, MAX_URL_LEN>,
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
) -> (bool, u32) {
    let mut found = false;
    let mut index: u32 = 3050913689; // sentinel value
    for i in 0..allowed_urls.len() {
        let allowed_url = allowed_urls[i];
        if allowed_url.len() <= request_url.len() {
            let (result, match_position) = search(request_url, allowed_url);
            if result & (match_position == 0) & !found {
                found = true;
                index = i;
            }
        }
    }
    (found, index)
}
