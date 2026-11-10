#![no_main]

use astrolabe_core::decode_g1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(pt) = decode_g1(data) {
        let enc = pt.encode();
        assert_eq!(enc.len(), 64);
        let roundtrip = decode_g1(&enc).expect("decoded G1 point must roundtrip successfully");
        assert_eq!(pt, roundtrip);
    }
});
