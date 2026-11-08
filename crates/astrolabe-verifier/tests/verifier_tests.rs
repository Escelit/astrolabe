use astrolabe_core::snarkjs::{parse_snarkjs_proof, parse_snarkjs_public_inputs, parse_snarkjs_vk};
use astrolabe_core::{encode_proof, encode_public_inputs, encode_vk};
use astrolabe_verifier::{
    parse_proof, parse_vk, verify_groth16_bytes, verify_groth16_slice, StoredVkVerifierContract,
    StoredVkVerifierContractClient, VerifierError, BN254_R_BE,
};
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, Vec};

fn load_circuit(circuit: &str) -> (std::vec::Vec<u8>, [u8; 256], std::vec::Vec<[u8; 32]>) {
    let base = format!(
        "{}/../../spec/fixtures/snarkjs/{}",
        env!("CARGO_MANIFEST_DIR"),
        circuit
    );
    let proof_json = std::fs::read_to_string(format!("{base}/proof.json")).unwrap();
    let vk_json = std::fs::read_to_string(format!("{base}/verification_key.json")).unwrap();
    let pub_json = std::fs::read_to_string(format!("{base}/public.json")).unwrap();

    let proof = parse_snarkjs_proof(&proof_json).unwrap();
    let vk = parse_snarkjs_vk(&vk_json).unwrap();
    let pub_inputs = parse_snarkjs_public_inputs(&pub_json).unwrap();

    let proof_bytes = encode_proof(&proof);
    let vk_bytes = encode_vk(&vk);
    let pub_bytes = encode_public_inputs(&pub_inputs);

    assert_eq!(pub_bytes.len() % 32, 0);
    let mut signals = std::vec::Vec::new();
    for chunk in pub_bytes.chunks_exact(32) {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(chunk);
        signals.push(arr);
    }

    (vk_bytes, proof_bytes, signals)
}

#[test]
fn test_verify_all_circuits_via_direct_function() {
    let env = Env::default();

    for circuit in ["multiplier2", "square", "linear3"] {
        let (vk_raw, proof_raw, signals_raw) = load_circuit(circuit);

        let vk_bytes = Bytes::from_slice(&env, &vk_raw);
        let proof_bytes = BytesN::from_array(&env, &proof_raw);

        let mut pub_vec = Vec::new(&env);
        for sig in &signals_raw {
            pub_vec.push_back(BytesN::from_array(&env, sig));
        }

        let res = verify_groth16_bytes(&env, &vk_bytes, &proof_bytes, &pub_vec);
        assert_eq!(res, Ok(true), "Circuit {circuit} verification failed");

        // Also test verify_groth16_slice (baked-in VK path)
        let slice_res = verify_groth16_slice(&env, &vk_raw, &proof_bytes, &pub_vec);
        assert_eq!(
            slice_res,
            Ok(true),
            "Circuit {circuit} slice verification failed"
        );
    }
}

#[test]
fn test_stored_vk_verifier_contract_lifecycle() {
    let env = Env::default();
    let contract_id = env.register(StoredVkVerifierContract, ());
    let client = StoredVkVerifierContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let (vk_raw, proof_raw, signals_raw) = load_circuit("multiplier2");

    let vk_bytes = Bytes::from_slice(&env, &vk_raw);
    let proof_bytes = BytesN::from_array(&env, &proof_raw);

    let mut pub_vec = Vec::new(&env);
    for sig in &signals_raw {
        pub_vec.push_back(BytesN::from_array(&env, sig));
    }

    // 1. Initialize contract
    client.initialize(&admin, &vk_bytes);

    // 2. Initializing again fails with Unsupported
    let re_init = client.try_initialize(&admin, &vk_bytes);
    assert_eq!(re_init, Err(Ok(VerifierError::Unsupported)));

    // 3. Verify returns Ok(true)
    let verified = client.verify(&proof_bytes, &pub_vec);
    assert!(verified);

    // 4. verify_with_vk directly
    let direct_verified = client.verify_with_vk(&vk_bytes, &proof_bytes, &pub_vec);
    assert!(direct_verified);

    // 5. get_vk returns the stored VK
    let stored_vk = client.get_vk();
    assert_eq!(stored_vk, vk_bytes);

    // 6. Negative control: corrupted public signal returns InvalidProof
    let mut corrupted_pub = pub_vec.clone();
    let mut wrong_sig = signals_raw[0];
    wrong_sig[31] ^= 0x01; // flip last byte
    corrupted_pub.set(0, BytesN::from_array(&env, &wrong_sig));
    let corrupted_res = client.try_verify(&proof_bytes, &corrupted_pub);
    assert_eq!(corrupted_res, Err(Ok(VerifierError::InvalidProof)));

    // 7. Security control: uncanonical scalar >= r returns NonCanonicalField
    let mut uncanonical_pub = pub_vec.clone();
    uncanonical_pub.set(0, BytesN::from_array(&env, &BN254_R_BE));
    let uncanonical_res = client.try_verify(&proof_bytes, &uncanonical_pub);
    assert_eq!(uncanonical_res, Err(Ok(VerifierError::NonCanonicalField)));

    // 8. Degenerate proof point: all-zero A returns InvalidProof
    let mut degenerate_proof = proof_raw;
    degenerate_proof[0..64].fill(0);
    let degenerate_proof_bytes = BytesN::from_array(&env, &degenerate_proof);
    let degen_res = client.try_verify(&degenerate_proof_bytes, &pub_vec);
    assert_eq!(degen_res, Err(Ok(VerifierError::InvalidProof)));

    // 9. Public input count mismatch returns PublicInputCount
    let mut truncated_pub = pub_vec.clone();
    truncated_pub.pop_back();
    let count_mismatch_res = client.try_verify(&proof_bytes, &truncated_pub);
    assert_eq!(count_mismatch_res, Err(Ok(VerifierError::PublicInputCount)));
}

#[test]
fn test_parse_vk_and_proof() {
    let env = Env::default();
    let (vk_raw, proof_raw, _) = load_circuit("square");

    let vk_bytes = Bytes::from_slice(&env, &vk_raw);
    let parsed_vk = parse_vk(&env, &vk_bytes).expect("parse_vk should succeed");
    assert_eq!(parsed_vk.ic.len(), 2); // 1 public input + 1 = 2 IC points

    let proof_bytes = BytesN::from_array(&env, &proof_raw);
    let parsed_proof = parse_proof(&env, &proof_bytes).expect("parse_proof should succeed");
    assert_eq!(parsed_proof.a.to_array(), proof_raw[0..64]);
    assert_eq!(parsed_proof.b.to_array(), proof_raw[64..192]);
    assert_eq!(parsed_proof.c.to_array(), proof_raw[192..256]);
}
