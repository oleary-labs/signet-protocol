use jwt::JWT;

// Max length of JWT signed data (base64(header) || "." || base64(payload)).
// 1024 bytes supports JWTs with ~750 byte decoded payloads.
global MAX_DATA_LENGTH: u32 = 1024;

// Max lengths for claim values (bytes).
global MAX_ISS_LENGTH: u32 = 128;
global MAX_SUB_LENGTH: u32 = 128;
global MAX_AUD_LENGTH: u32 = 128;
global MAX_AZP_LENGTH: u32 = 128;

fn main(
    // Private witness
    data: BoundedVec<u8, MAX_DATA_LENGTH>,
    base64_decode_offset: u32,
    redc_params_limbs: [u128; 18],
    signature_limbs: [u128; 18],

    // Public inputs
    pubkey_modulus_limbs: pub [u128; 18],
    expected_iss: pub BoundedVec<u8, MAX_ISS_LENGTH>,
    expected_sub: pub BoundedVec<u8, MAX_SUB_LENGTH>,
    expected_exp: pub u64,
    expected_aud: pub BoundedVec<u8, MAX_AUD_LENGTH>,
    expected_azp: pub BoundedVec<u8, MAX_AZP_LENGTH>,
    session_pub: pub [u8; 33],
) {
    // 1. Verify RSA-SHA256 signature over the JWT header.payload
    let jwt_token = JWT::init(
        data,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );
    jwt_token.verify();

    // 2. Assert JWT claims match the public inputs
    jwt_token.assert_claim_string("iss".as_bytes(), expected_iss);
    jwt_token.assert_claim_string("sub".as_bytes(), expected_sub);
    jwt_token.assert_claim_number("exp".as_bytes(), expected_exp);
    jwt_token.assert_claim_string("aud".as_bytes(), expected_aud);
    jwt_token.assert_claim_string("azp".as_bytes(), expected_azp);

    // 3. session_pub is bound to the proof as a public input.
    //    A proof generated with session_pub=P1 will not verify against P2.
}
