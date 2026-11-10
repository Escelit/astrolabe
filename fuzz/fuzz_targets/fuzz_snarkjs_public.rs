#![no_main]

use astrolabe_core::snarkjs::{parse_snarkjs_public_inputs, parse_snarkjs_public_inputs_envelope};
use astrolabe_core::decode_public_inputs;
use core::str;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = str::from_utf8(data) {
        if let Ok(pub_inputs) = parse_snarkjs_public_inputs(s) {
            let enc = pub_inputs.encode();
            let roundtrip = decode_public_inputs(&enc).expect("decoded public inputs must decode via ACF");
            assert_eq!(pub_inputs, roundtrip);
        }
        let _ = parse_snarkjs_public_inputs_envelope(s);
    }
});
