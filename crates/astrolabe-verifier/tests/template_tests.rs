use astrolabe_core::snarkjs::{parse_snarkjs_proof, parse_snarkjs_vk};
use astrolabe_core::{encode_proof, encode_vk, G1, G2};
use astrolabe_verifier::{
    MerkleMembershipContract, MerkleMembershipContractClient, NullifierClaimContract,
    NullifierClaimContractClient, PrivateVoteContract, PrivateVoteContractClient, VerifierError,
};
use soroban_sdk::{
    crypto::bn254::{Bn254Fr, Bn254G1Affine},
    testutils::Address as _,
    Address, Bytes, BytesN, Env,
};
use std::fs;

fn load_circuit(circuit: &str) -> (std::vec::Vec<u8>, [u8; 256]) {
    let base = format!(
        "{}/../../spec/fixtures/snarkjs/{}",
        env!("CARGO_MANIFEST_DIR"),
        circuit
    );
    let proof_json = fs::read_to_string(format!("{base}/proof.json")).unwrap();
    let vk_json = fs::read_to_string(format!("{base}/verification_key.json")).unwrap();

    let proof = parse_snarkjs_proof(&proof_json).unwrap();
    let vk = parse_snarkjs_vk(&vk_json).unwrap();

    (encode_vk(&vk), encode_proof(&proof))
}

/// Constructs a valid 4-input BN254 Groth16 verification key and proof for the given
/// 4 canonical public scalars (`s_0..s_3`), satisfying:
/// `e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1`
/// where `alpha = IC[0..=4] = C = G1`, `beta = gamma = delta = B = G2`,
/// and `A = alpha + vk_x + C`.
fn build_valid_4_input_vk_and_proof(env: &Env, signals: &[[u8; 32]; 4]) -> (Bytes, BytesN<256>) {
    let g1_bytes = G1::GENERATOR.encode();
    let g2_bytes = G2::GENERATOR.encode();

    // Build VK with n_ic = 5 (4 public inputs)
    let mut vk_raw = std::vec::Vec::with_capacity(452 + 5 * 64);
    vk_raw.extend_from_slice(&g1_bytes); // alpha_g1
    vk_raw.extend_from_slice(&g2_bytes); // beta_g2
    vk_raw.extend_from_slice(&g2_bytes); // gamma_g2
    vk_raw.extend_from_slice(&g2_bytes); // delta_g2
    vk_raw.extend_from_slice(&5u32.to_be_bytes()); // n_ic = 5
    for _ in 0..5 {
        vk_raw.extend_from_slice(&g1_bytes); // IC[0..5] = G1
    }

    let bn254 = env.crypto().bn254();
    let g1 = Bn254G1Affine::from_array(env, &g1_bytes);
    let mut vk_x = g1.clone();
    for sig in signals {
        let fr = Bn254Fr::from_bytes(BytesN::from_array(env, sig));
        let term = bn254.g1_mul(&g1, &fr);
        vk_x = bn254.g1_add(&vk_x, &term);
    }

    // A = alpha + vk_x + C = G1 + vk_x + G1
    let alpha_plus_vk_x = bn254.g1_add(&g1, &vk_x);
    let a_pt = bn254.g1_add(&alpha_plus_vk_x, &g1);
    let a_bytes = a_pt.to_array();

    let mut proof_raw = [0u8; 256];
    proof_raw[0..64].copy_from_slice(&a_bytes);
    proof_raw[64..192].copy_from_slice(&g2_bytes);
    proof_raw[192..256].copy_from_slice(&g1_bytes);

    (
        Bytes::from_slice(env, &vk_raw),
        BytesN::from_array(env, &proof_raw),
    )
}

#[test]
fn test_merkle_membership_contract_lifecycle() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register(MerkleMembershipContract, ());
    let client = MerkleMembershipContractClient::new(&env, &contract_id);

    // square circuit has 1 public input (signal = 144)
    let (vk_raw, proof_raw) = load_circuit("square");
    let vk_bytes = Bytes::from_slice(&env, &vk_raw);
    let proof_bytes = BytesN::from_array(&env, &proof_raw);

    let mut root_arr = [0u8; 32];
    root_arr[31] = 144; // public signal 144 (12 * 12)
    let root = BytesN::from_array(&env, &root_arr);

    // 1. Initialize
    client.initialize(&admin, &vk_bytes, &root);
    assert_eq!(client.get_root(), root);
    assert_eq!(client.get_vk(), vk_bytes);

    // 2. Verify valid membership
    let verified = client.verify_membership(&proof_bytes, &root);
    assert!(verified);

    // 3. Verify mismatching root rejects
    let mut wrong_root_arr = [0u8; 32];
    wrong_root_arr[31] = 99;
    let wrong_root = BytesN::from_array(&env, &wrong_root_arr);
    let rejected = client.verify_membership(&proof_bytes, &wrong_root);
    assert!(!rejected);

    // 4. Update root and VK as admin
    client.set_root(&admin, &wrong_root);
    assert_eq!(client.get_root(), wrong_root);
    client.set_vk(&admin, &vk_bytes);
    assert_eq!(client.get_vk(), vk_bytes);
}

#[test]
fn test_private_vote_nullifier_replay_protection() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register(PrivateVoteContract, ());
    let client = PrivateVoteContractClient::new(&env, &contract_id);

    let voter_root_arr = [0x01u8; 32];
    let nullifier_arr = [0x02u8; 32];
    let proposal_arr = [0x03u8; 32];
    let option: u32 = 1;
    let mut option_arr = [0u8; 32];
    option_arr[28..32].copy_from_slice(&option.to_be_bytes());

    let (vk_bytes, proof_bytes) = build_valid_4_input_vk_and_proof(
        &env,
        &[voter_root_arr, nullifier_arr, proposal_arr, option_arr],
    );

    let voter_root = BytesN::from_array(&env, &voter_root_arr);
    let proposal_id = BytesN::from_array(&env, &proposal_arr);
    let nullifier = BytesN::from_array(&env, &nullifier_arr);

    client.initialize(&admin, &vk_bytes, &voter_root, &proposal_id);
    assert_eq!(client.get_voter_root(), voter_root);
    assert_eq!(client.get_proposal_id(), proposal_id);
    assert_eq!(client.get_vk(), vk_bytes);

    assert!(!client.has_voted(&nullifier));
    assert_eq!(client.get_tally(&option), 0);

    // 1. Negative control: tampered option (option = 2) fails pairing check
    let tampered_res = client.try_cast_vote(&proof_bytes, &nullifier, &2);
    assert_eq!(tampered_res, Err(Ok(VerifierError::InvalidProof)));
    assert!(!client.has_voted(&nullifier));
    assert_eq!(client.get_tally(&1), 0);

    // 2. Positive control: valid vote succeeds, marks nullifier spent, increments tally
    let new_tally = client.cast_vote(&proof_bytes, &nullifier, &option);
    assert_eq!(new_tally, 1);
    assert!(client.has_voted(&nullifier));
    assert_eq!(client.get_tally(&option), 1);

    // 3. Replay control: re-submitting the exact same valid proof & nullifier is rejected
    let replay_res = client.try_cast_vote(&proof_bytes, &nullifier, &option);
    assert_eq!(replay_res, Err(Ok(VerifierError::InvalidProof)));
    assert_eq!(client.get_tally(&option), 1);

    // 4. Admin can rotate voter_root
    let next_root = BytesN::from_array(&env, &[0x09u8; 32]);
    client.set_voter_root(&admin, &next_root);
    assert_eq!(client.get_voter_root(), next_root);
}

#[test]
fn test_nullifier_claim_contract_lifecycle() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register(NullifierClaimContract, ());
    let client = NullifierClaimContractClient::new(&env, &contract_id);

    let claim_root_arr = [0x05u8; 32];
    let nullifier_arr = [0x06u8; 32];
    let recipient_arr = [0x07u8; 32];
    let amount: u64 = 5_000_000;
    let mut amount_arr = [0u8; 32];
    amount_arr[24..32].copy_from_slice(&amount.to_be_bytes());

    let (vk_bytes, proof_bytes) = build_valid_4_input_vk_and_proof(
        &env,
        &[claim_root_arr, nullifier_arr, recipient_arr, amount_arr],
    );

    let claim_root = BytesN::from_array(&env, &claim_root_arr);
    let nullifier = BytesN::from_array(&env, &nullifier_arr);
    let recipient = BytesN::from_array(&env, &recipient_arr);

    client.initialize(&admin, &vk_bytes, &claim_root);
    assert_eq!(client.get_claim_root(), claim_root);
    assert_eq!(client.get_vk(), vk_bytes);
    assert!(!client.is_claimed(&nullifier));

    // 1. Negative control: wrong amount fails pairing check
    let wrong_amt = client.try_claim(&proof_bytes, &nullifier, &recipient, &(amount + 1));
    assert_eq!(wrong_amt, Err(Ok(VerifierError::InvalidProof)));
    assert!(!client.is_claimed(&nullifier));

    // 2. Positive control: valid claim succeeds and records nullifier
    let claimed = client.claim(&proof_bytes, &nullifier, &recipient, &amount);
    assert!(claimed);
    assert!(client.is_claimed(&nullifier));

    // 3. Replay control: double-claim with the same valid proof & nullifier is rejected
    let replay_res = client.try_claim(&proof_bytes, &nullifier, &recipient, &amount);
    assert_eq!(replay_res, Err(Ok(VerifierError::InvalidProof)));

    // 4. Admin can update claim_root
    let new_root = BytesN::from_array(&env, &[0x0au8; 32]);
    client.set_claim_root(&admin, &new_root);
    assert_eq!(client.get_claim_root(), new_root);
}
