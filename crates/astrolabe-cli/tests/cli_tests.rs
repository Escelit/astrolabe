use std::path::PathBuf;
use std::process::Command;

fn get_cli_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_astrolabe"))
}

fn get_fixture_path(subpath: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/fixtures/snarkjs")
        .join(subpath)
}

#[test]
fn test_cli_export_acf_hex() {
    let proof_path = get_fixture_path("multiplier2/proof.json");
    let vk_path = get_fixture_path("multiplier2/verification_key.json");
    let pub_path = get_fixture_path("multiplier2/public.json");

    let output = get_cli_bin()
        .args([
            "export",
            "--proof",
            proof_path.to_str().unwrap(),
            "--vk",
            vk_path.to_str().unwrap(),
            "--public",
            pub_path.to_str().unwrap(),
            "--format",
            "acf-hex",
        ])
        .output()
        .expect("Failed to execute export");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // proof is 256 bytes = 512 hex chars; vk is 644 bytes = 1288 hex chars; public is 64 bytes = 128 hex chars
    assert!(stdout.contains("04096acfdf56605a9073e3ae082184ce")); // Proof prefix from multiplier2 fixture
    assert!(stdout.contains("0c728c8c242d4b792f7b625c3173ae4f")); // VK prefix from multiplier2 fixture
    assert!(stdout.contains("0000000000000000000000000000000000000000000000000000000000000021"));
    // 33
}

#[test]
fn test_cli_export_canonical_json() {
    let proof_path = get_fixture_path("square/proof.json");

    let output = get_cli_bin()
        .args([
            "export",
            "--proof",
            proof_path.to_str().unwrap(),
            "--format",
            "canonical-json",
        ])
        .output()
        .expect("Failed to execute export");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"acf\": \"0.1\""));
    assert!(stdout.contains("\"kind\": \"proof\""));
    assert!(stdout.contains("\"curve\": \"bn254\""));
    assert!(stdout.contains("\"system\": \"groth16\""));
}

#[test]
fn test_cli_export_soroban_args() {
    let proof_path = get_fixture_path("multiplier2/proof.json");
    let pub_path = get_fixture_path("multiplier2/public.json");

    let output = get_cli_bin()
        .args([
            "export",
            "--proof",
            proof_path.to_str().unwrap(),
            "--public",
            pub_path.to_str().unwrap(),
            "--format",
            "soroban-args",
        ])
        .output()
        .expect("Failed to execute export");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--proof 04096acfdf56605a9073e3ae082184ce"));
    assert!(stdout.contains("--public-inputs '[\"0000000000000000000000000000000000000000000000000000000000000021\", \"0000000000000000000000000000000000000000000000000000000000000003\"]'"));
}

#[test]
fn test_cli_export_out_dir() {
    let temp_dir = std::env::temp_dir().join("astrolabe_test_export_out_dir");
    let _ = std::fs::remove_dir_all(&temp_dir);

    let proof_path = get_fixture_path("linear3/proof.json");
    let vk_path = get_fixture_path("linear3/verification_key.json");
    let pub_path = get_fixture_path("linear3/public.json");

    let output = get_cli_bin()
        .args([
            "export",
            "--proof",
            proof_path.to_str().unwrap(),
            "--vk",
            vk_path.to_str().unwrap(),
            "--public",
            pub_path.to_str().unwrap(),
            "--format",
            "envelope",
            "--out-dir",
            temp_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute export");

    assert!(output.status.success());
    assert!(temp_dir.join("proof.astr").exists());
    assert!(temp_dir.join("vk.astr").exists());
    assert!(temp_dir.join("public.astr").exists());

    let proof_astr = std::fs::read(temp_dir.join("proof.astr")).unwrap();
    assert_eq!(&proof_astr[0..4], b"ASTR");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_gen_verifier_baked_and_stored() {
    let temp_dir = std::env::temp_dir().join("astrolabe_test_gen_verifier");
    let _ = std::fs::remove_dir_all(&temp_dir);

    let vk_path = get_fixture_path("multiplier2/verification_key.json");

    // 1. Baked mode package
    let baked_dir = temp_dir.join("baked_pkg");
    let output = get_cli_bin()
        .args([
            "gen-verifier",
            "--vk",
            vk_path.to_str().unwrap(),
            "--mode",
            "baked",
            "--name",
            "MultiplierVerifier",
            "--out",
            baked_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute gen-verifier");

    assert!(output.status.success());
    assert!(baked_dir.join("Cargo.toml").exists());
    assert!(baked_dir.join("src/lib.rs").exists());
    let lib_rs = std::fs::read_to_string(baked_dir.join("src/lib.rs")).unwrap();
    assert!(lib_rs.contains("pub const VK_BYTES: [u8; 644] = ["));
    assert!(lib_rs.contains("pub struct MultiplierVerifier;"));

    // 2. Stored mode single .rs file
    let stored_file = temp_dir.join("stored_verifier.rs");
    let output2 = get_cli_bin()
        .args([
            "gen-verifier",
            "--vk",
            vk_path.to_str().unwrap(),
            "--mode",
            "stored",
            "--name",
            "CustomStoredVerifier",
            "--out",
            stored_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute gen-verifier");

    assert!(output2.status.success());
    assert!(stored_file.exists());
    let stored_rs = std::fs::read_to_string(&stored_file).unwrap();
    assert!(stored_rs
        .contains("pub use astrolabe_verifier::StoredVkVerifierContract as CustomStoredVerifier;"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_verify_local() {
    for circuit in ["multiplier2", "square", "linear3"] {
        let proof_path = get_fixture_path(&format!("{circuit}/proof.json"));
        let vk_path = get_fixture_path(&format!("{circuit}/verification_key.json"));
        let pub_path = get_fixture_path(&format!("{circuit}/public.json"));

        let output = get_cli_bin()
            .args([
                "verify",
                "--proof",
                proof_path.to_str().unwrap(),
                "--vk",
                vk_path.to_str().unwrap(),
                "--public",
                pub_path.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to execute verify");

        assert!(
            output.status.success(),
            "Failed verifying circuit {circuit}"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Proof verification SUCCEEDED!"));
    }
}

#[test]
fn test_cli_verify_negative_control() {
    // Pass multiplier2 proof with square public input -> public input count mismatch
    let proof_path = get_fixture_path("multiplier2/proof.json");
    let vk_path = get_fixture_path("multiplier2/verification_key.json");
    let wrong_pub_path = get_fixture_path("square/public.json");

    let output = get_cli_bin()
        .args([
            "verify",
            "--proof",
            proof_path.to_str().unwrap(),
            "--vk",
            vk_path.to_str().unwrap(),
            "--public",
            wrong_pub_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute verify");

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ERR_PUBLIC_INPUT_COUNT"));
}

#[test]
fn test_cli_doctor() {
    let output = get_cli_bin()
        .args(["doctor", "--offline"])
        .output()
        .expect("Failed to execute doctor");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "doctor --offline failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("Astrolabe Environment Diagnostics"));
    assert!(stdout.contains("[✓] rustc"));
    assert!(stdout.contains("[✓] wasm32v1-none target"));
    assert!(stdout.contains("[✓] cargo"));
    assert!(stdout.contains("stellar:"));
    assert!(stdout.contains("SATISFIED"));
}

#[test]
fn test_example_circom_multiplier_artifacts() {
    let example_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/circom-multiplier/artifacts");
    let proof_json = example_dir.join("proof.json");
    let vk_json = example_dir.join("verification_key.json");
    let pub_json = example_dir.join("public.json");
    let proof_hex = example_dir.join("proof.hex");
    let vk_hex = example_dir.join("vk.hex");
    let pub_hex = example_dir.join("public.hex");

    // Verify from snarkjs JSON artifacts
    let out_json = get_cli_bin()
        .args([
            "verify",
            "--proof",
            proof_json.to_str().unwrap(),
            "--vk",
            vk_json.to_str().unwrap(),
            "--public",
            pub_json.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute verify on example JSON artifacts");
    assert!(out_json.status.success());
    assert!(String::from_utf8_lossy(&out_json.stdout).contains("Proof verification SUCCEEDED!"));

    // Verify from exported ACF hex artifacts
    let out_hex = get_cli_bin()
        .args([
            "verify",
            "--proof",
            proof_hex.to_str().unwrap(),
            "--vk",
            vk_hex.to_str().unwrap(),
            "--public",
            pub_hex.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute verify on example hex artifacts");
    assert!(out_hex.status.success());
    assert!(String::from_utf8_lossy(&out_hex.stdout).contains("Proof verification SUCCEEDED!"));
}

#[test]
fn test_cli_export_noir_artifacts() {
    let temp_dir = std::env::temp_dir().join("astrolabe_test_noir_artifacts");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();
    let bundle_path = temp_dir.join("noir_bundle.json");

    let proof_raw = std::fs::read_to_string(get_fixture_path("multiplier2/proof.json")).unwrap();
    let vk_raw =
        std::fs::read_to_string(get_fixture_path("multiplier2/verification_key.json")).unwrap();

    let noir_json = format!(
        r#"{{
            "noir_version": "0.33.0",
            "backend": "sunspot-groth16",
            "circuit": "multiplier_noir",
            "proof": {proof_raw},
            "verification_key": {vk_raw},
            "public_inputs": ["0x21", "0x0b"]
        }}"#
    );
    std::fs::write(&bundle_path, noir_json).unwrap();

    let output = get_cli_bin()
        .args([
            "export",
            "--source",
            "noir",
            "--proof",
            bundle_path.to_str().unwrap(),
            "--vk",
            bundle_path.to_str().unwrap(),
            "--public",
            bundle_path.to_str().unwrap(),
            "--format",
            "acf-hex",
        ])
        .output()
        .expect("Failed to execute export for Noir");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Noir provenance metadata"));
    assert!(stdout.contains("04096acfdf56605a9073e3ae082184ce"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_export_risc0_artifacts() {
    let temp_dir = std::env::temp_dir().join("astrolabe_test_risc0_artifacts");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();
    let receipt_path = temp_dir.join("risc0_receipt.json");

    let proof_raw = std::fs::read_to_string(get_fixture_path("multiplier2/proof.json")).unwrap();
    let original_proof = astrolabe_core::parse_snarkjs_proof(&proof_raw).unwrap();
    let seal_hex = hex::encode(original_proof.encode());

    let image_id_hex = "1111111111111111111111111111111111111111111111111111111111111111";
    let journal_hex = "2222222222222222222222222222222222222222222222222222222222222222";

    let receipt_json = format!(
        r#"{{
            "seal": "0x{seal_hex}",
            "image_id": "0x{image_id_hex}",
            "journal": "0x{journal_hex}"
        }}"#
    );
    std::fs::write(&receipt_path, receipt_json).unwrap();

    let output = get_cli_bin()
        .args([
            "export",
            "--source",
            "risc0",
            "--proof",
            receipt_path.to_str().unwrap(),
            "--public",
            receipt_path.to_str().unwrap(),
            "--format",
            "acf-hex",
        ])
        .output()
        .expect("Failed to execute export for RISC Zero");

    if !output.status.success() {
        eprintln!("STDOUT: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("STDERR: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&seal_hex[0..32]));
    // In limb16, length of public inputs is 4 scalars = 128 bytes = 256 hex chars
    assert!(stdout.contains("0000000000000000000000000000000011111111111111111111111111111111"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_profile_human_and_json() {
    let proof_path = get_fixture_path("multiplier2/proof.json");
    let vk_path = get_fixture_path("multiplier2/verification_key.json");
    let pub_path = get_fixture_path("multiplier2/public.json");

    // 1. Human-readable profile
    let output = get_cli_bin()
        .args([
            "profile",
            "--proof",
            proof_path.to_str().unwrap(),
            "--vk",
            vk_path.to_str().unwrap(),
            "--public",
            pub_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute profile");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Astrolabe Cost Profiler"));
    assert!(stdout.contains("CPU Instructions"));
    assert!(stdout.contains("RAM Memory Bytes"));
    assert!(stdout.contains("Overall Status: ✓ PASSED ALL SOROBAN CONSTRAINTS"));

    // 2. JSON structured profile
    let output_json = get_cli_bin()
        .args([
            "profile",
            "--proof",
            proof_path.to_str().unwrap(),
            "--vk",
            vk_path.to_str().unwrap(),
            "--public",
            pub_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("Failed to execute profile with --json");

    assert!(output_json.status.success());
    let report: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("Failed to parse profile JSON");
    assert_eq!(report["proof_valid"], true);
    assert_eq!(report["n_public_inputs"], 2);
    assert_eq!(report["n_ic_points"], 3);
    assert!(report["cpu_instructions"].as_u64().unwrap() > 0);
    assert!(report["memory_bytes"].as_u64().unwrap() > 0);
    assert_eq!(report["cpu_limit"], 100_000_000);
    assert_eq!(report["memory_limit"], 41_943_040);
}
