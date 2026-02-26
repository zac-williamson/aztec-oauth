use std::hash::pedersen_hash;

// Maximum length of JWT data (base64-encoded header.payload)
// 1024 bytes covers standard Google/Apple JWTs
pub global MAX_JWT_DATA_LENGTH: u32 = 1024;

// Maximum length of the nonce claim value (hex-encoded Pedersen hash: "0x" + 64 hex chars)
pub global MAX_NONCE_LENGTH: u32 = 66;

// Maximum length of the sub claim value
pub global MAX_SUB_LENGTH: u32 = 255;

// Provider ID constants (must match registry)
pub global PROVIDER_GOOGLE: Field = 1;
pub global PROVIDER_APPLE: Field = 2;

/// Convert a Field to a hex-encoded byte array with "0x" prefix.
pub fn field_to_hex_bytes(value: Field) -> [u8; MAX_NONCE_LENGTH] {
    let bytes: [u8; 32] = value.to_be_bytes();
    let hex_chars: [u8; 16] = [
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102,
    ]; // "0123456789abcdef"
    let mut result: [u8; MAX_NONCE_LENGTH] = [0; MAX_NONCE_LENGTH];
    // "0x" prefix
    result[0] = 48; // '0'
    result[1] = 120; // 'x'
    for i in 0..32 {
        let byte = bytes[i];
        let high = (byte >> 4) & 0x0f;
        let low = byte & 0x0f;
        result[2 + i * 2] = hex_chars[high as u32];
        result[2 + i * 2 + 1] = hex_chars[low as u32];
    }
    result
}

/// Hash a BoundedVec of bytes into a single Field via Pedersen.
/// Packs bytes into Field elements (31 bytes per Field) then hashes.
pub fn hash_bytes_to_field(bytes: BoundedVec<u8, MAX_SUB_LENGTH>) -> Field {
    // Pack bytes into fields (31 bytes per field element to stay within field modulus)
    let mut fields: [Field; 9] = [0; 9]; // ceil(255/31) = 9
    for i in 0..MAX_SUB_LENGTH {
        if i < bytes.len() {
            let field_idx = i / 31;
            fields[field_idx] = fields[field_idx] * 256 + bytes.get(i) as Field;
        }
    }
    // Include the length to prevent collisions between different-length inputs
    fields[8] = bytes.len() as Field;
    pedersen_hash(fields)
}

// ========================================================================
// Tests
// ========================================================================

#[test]
fn test_field_to_hex_bytes_zero() {
    let result = field_to_hex_bytes(0);
    // Should start with "0x"
    assert(result[0] == 48, "first byte should be '0'"); // '0'
    assert(result[1] == 120, "second byte should be 'x'"); // 'x'
    // Field 0 as 32 bytes big-endian is all zeros -> hex is all '0'
    for i in 2..66 {
        assert(result[i] == 48, "zero field should produce all '0' hex chars");
    }
}

#[test]
fn test_field_to_hex_bytes_one() {
    let result = field_to_hex_bytes(1);
    assert(result[0] == 48, "first byte should be '0'"); // '0'
    assert(result[1] == 120, "second byte should be 'x'"); // 'x'
    // Field 1 as 32-byte big-endian: 00...01
    // Last hex char pair should be "01"
    assert(result[64] == 48, "second-to-last should be '0'"); // '0'
    assert(result[65] == 49, "last byte should be '1'"); // '1'
}

#[test]
fn test_field_to_hex_bytes_deterministic() {
    let value: Field = 0x1234abcd;
    let result1 = field_to_hex_bytes(value);
    let result2 = field_to_hex_bytes(value);
    for i in 0..MAX_NONCE_LENGTH {
        assert(result1[i] == result2[i], "field_to_hex_bytes should be deterministic");
    }
}

#[test]
fn test_hash_bytes_to_field_deterministic() {
    let mut bytes: BoundedVec<u8, MAX_SUB_LENGTH> = BoundedVec::new();
    bytes.push(104); // 'h'
    bytes.push(101); // 'e'
    bytes.push(108); // 'l'
    bytes.push(108); // 'l'
    bytes.push(111); // 'o'

    let hash1 = hash_bytes_to_field(bytes);
    let hash2 = hash_bytes_to_field(bytes);
    assert(hash1 == hash2, "hash_bytes_to_field should be deterministic");
}

#[test]
fn test_hash_bytes_to_field_different_inputs() {
    let mut bytes_a: BoundedVec<u8, MAX_SUB_LENGTH> = BoundedVec::new();
    bytes_a.push(65); // 'A'

    let mut bytes_b: BoundedVec<u8, MAX_SUB_LENGTH> = BoundedVec::new();
    bytes_b.push(66); // 'B'

    let hash_a = hash_bytes_to_field(bytes_a);
    let hash_b = hash_bytes_to_field(bytes_b);
    assert(hash_a != hash_b, "different inputs should produce different hashes");
}

#[test]
fn test_hash_bytes_to_field_length_sensitive() {
    // "A" and "A\0" should produce different hashes because length is included
    let mut bytes_a: BoundedVec<u8, MAX_SUB_LENGTH> = BoundedVec::new();
    bytes_a.push(65); // 'A'

    let mut bytes_a_null: BoundedVec<u8, MAX_SUB_LENGTH> = BoundedVec::new();
    bytes_a_null.push(65); // 'A'
    bytes_a_null.push(0);  // '\0'

    let hash_a = hash_bytes_to_field(bytes_a);
    let hash_a_null = hash_bytes_to_field(bytes_a_null);
    assert(hash_a != hash_a_null, "different length inputs should produce different hashes");
}
