#![no_main]

use astrolabe_core::snarkjs::{parse_snarkjs_proof, parse_snarkjs_proof_envelope};
use astrolabe_core::decode_proof;
use core::str;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = str::from_utf8(data) {
        if let Ok(proof) = parse_snarkjs_proof(s) {
            let enc = proof.encode();
            assert_eq!(enc.len(), 256);
            let roundtrip = decode_proof(&enc).expect("decoded proof from snarkjs must decode via ACF");
            assert_eq!(proof, roundtrip);
        }
        let _ = parse_snarkjs_proof_envelope(s);
    }
});
