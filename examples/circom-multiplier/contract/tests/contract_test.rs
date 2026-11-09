use astrolabe_core::snarkjs::{parse_snarkjs_proof, parse_snarkjs_public_inputs, parse_snarkjs_vk};
use astrolabe_core::{encode_proof, encode_public_inputs, encode_vk, BN254_R_BE};
use astrolabe_verifier::VerifierError;
use multiplier_verifier::{MultiplierVerifier, MultiplierVerifierClient, VK_BYTES};
use soroban_sdk::{BytesN, Env, Vec};

const PROOF_JSON: &str = include_str!("../../artifacts/proof.json");
const VK_JSON: &str = include_str!("../../artifacts/verification_key.json");
const PUBLIC_JSON: &str = include_str!("../../artifacts/public.json");

#[test]
fn baked_vk_matches_snarkjs_verification_key() {
    let vk = parse_snarkjs_vk(VK_JSON).expect("valid verification_key.json");
    let encoded_vk = encode_vk(&vk);
    assert_eq!(encoded_vk.as_slice(), &VK_BYTES);
}

#[test]
fn verify_valid_multiplier_proof_succeeds() {
    let env = Env::default();
    let contract_id = env.register(MultiplierVerifier, ());
    let client = MultiplierVerifierClient::new(&env, &contract_id);

    let proof = parse_snarkjs_proof(PROOF_JSON).expect("valid proof.json");
    let proof_bytes = encode_proof(&proof);
    let proof_arg = BytesN::from_array(&env, &proof_bytes);

    let pub_inputs = parse_snarkjs_public_inputs(PUBLIC_JSON).expect("valid public.json");
    let pub_bytes = encode_public_inputs(&pub_inputs);

    let mut pub_vec = Vec::new(&env);
    for chunk in pub_bytes.chunks_exact(32) {
        let mut s = [0u8; 32];
        s.copy_from_slice(chunk);
        pub_vec.push_back(BytesN::from_array(&env, &s));
    }

    assert!(client.verify(&proof_arg, &pub_vec));
    assert_eq!(client.get_vk().len(), 644);
}

#[test]
fn verify_rejects_wrong_public_signal_and_non_canonical_scalar() {
    let env = Env::default();
    let contract_id = env.register(MultiplierVerifier, ());
    let client = MultiplierVerifierClient::new(&env, &contract_id);

    let proof = parse_snarkjs_proof(PROOF_JSON).expect("valid proof.json");
    let proof_arg = BytesN::from_array(&env, &encode_proof(&proof));

    // 1. Wrong public output: c = 34 instead of 33 (with a = 3)
    let mut s0_wrong = [0u8; 32];
    s0_wrong[31] = 34;
    let mut s1 = [0u8; 32];
    s1[31] = 3;

    let mut wrong_pub = Vec::new(&env);
    wrong_pub.push_back(BytesN::from_array(&env, &s0_wrong));
    wrong_pub.push_back(BytesN::from_array(&env, &s1));

    let res_wrong = client.try_verify(&proof_arg, &wrong_pub);
    assert_eq!(res_wrong, Err(Ok(VerifierError::InvalidProof)));

    // 2. Non-canonical scalar >= r (aliased signal s_0 = r)
    let mut non_canonical_pub = Vec::new(&env);
    non_canonical_pub.push_back(BytesN::from_array(&env, &BN254_R_BE));
    non_canonical_pub.push_back(BytesN::from_array(&env, &s1));

    let res_non_canonical = client.try_verify(&proof_arg, &non_canonical_pub);
    assert_eq!(res_non_canonical, Err(Ok(VerifierError::NonCanonicalField)));

    // 3. Public-input count mismatch (1 input instead of 2)
    let mut short_pub = Vec::new(&env);
    short_pub.push_back(BytesN::from_array(&env, &s1));

    let res_count = client.try_verify(&proof_arg, &short_pub);
    assert_eq!(res_count, Err(Ok(VerifierError::PublicInputCount)));
}
