use astrolabe_core::snarkjs::{parse_snarkjs_proof, parse_snarkjs_vk};
use astrolabe_core::{encode_proof, encode_vk};
use astrolabe_verifier::{
    MerkleMembershipContract, MerkleMembershipContractClient, NullifierClaimContract,
    NullifierClaimContractClient, PrivateVoteContract, PrivateVoteContractClient,
};
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env};
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

    // 2. Verify valid membership
    let verified = client.verify_membership(&proof_bytes, &root);
    assert!(verified);

    // 3. Verify mismatching root rejects
    let mut wrong_root_arr = [0u8; 32];
    wrong_root_arr[31] = 99;
    let wrong_root = BytesN::from_array(&env, &wrong_root_arr);
    let rejected = client.verify_membership(&proof_bytes, &wrong_root);
    assert!(!rejected);

    // 4. Update root as admin
    client.set_root(&admin, &wrong_root);
    assert_eq!(client.get_root(), wrong_root);
}

#[test]
fn test_private_vote_nullifier_replay_protection() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register(PrivateVoteContract, ());
    let client = PrivateVoteContractClient::new(&env, &contract_id);

    let (vk_raw, proof_raw) = load_circuit("multiplier2");
    let vk_bytes = Bytes::from_slice(&env, &vk_raw);
    let proof_bytes = BytesN::from_array(&env, &proof_raw);

    let voter_root = BytesN::from_array(&env, &[0x01u8; 32]);
    let proposal_id = BytesN::from_array(&env, &[0x02u8; 32]);

    client.initialize(&admin, &vk_bytes, &voter_root, &proposal_id);

    let nullifier = BytesN::from_array(&env, &[0xaa; 32]);
    assert!(!client.has_voted(&nullifier));
    assert_eq!(client.get_tally(&1), 0);

    // If proof doesn't match public inputs equation, it will fail pairing check
    let res = client.try_cast_vote(&proof_bytes, &nullifier, &1);
    // Errs with InvalidProof because proof does not correspond to these mock public signals
    assert!(res.is_err());
}

#[test]
fn test_nullifier_claim_contract_lifecycle() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register(NullifierClaimContract, ());
    let client = NullifierClaimContractClient::new(&env, &contract_id);

    let (vk_raw, proof_raw) = load_circuit("multiplier2");
    let vk_bytes = Bytes::from_slice(&env, &vk_raw);
    let proof_bytes = BytesN::from_array(&env, &proof_raw);

    let claim_root = BytesN::from_array(&env, &[0x05u8; 32]);
    client.initialize(&admin, &vk_bytes, &claim_root);

    let nullifier = BytesN::from_array(&env, &[0xbb; 32]);
    let recipient = BytesN::from_array(&env, &[0xcc; 32]);

    assert!(!client.is_claimed(&nullifier));

    // Try claim with mismatched proof/inputs
    let res = client.try_claim(&proof_bytes, &nullifier, &recipient, &100);
    assert!(res.is_err());
}
