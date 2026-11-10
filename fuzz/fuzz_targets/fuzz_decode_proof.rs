#![no_main]

use astrolabe_core::decode_proof;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(proof) = decode_proof(data) {
        let enc = proof.encode();
        assert_eq!(enc.len(), 256);
        let roundtrip =
            decode_proof(&enc).expect("decoded Groth16 proof must roundtrip successfully");
        assert_eq!(proof, roundtrip);
    }
});
