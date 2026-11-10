#![no_main]

use astrolabe_core::decode_g2;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(pt) = decode_g2(data) {
        let enc = pt.encode();
        assert_eq!(enc.len(), 128);
        let roundtrip = decode_g2(&enc).expect("decoded G2 point must roundtrip successfully");
        assert_eq!(pt, roundtrip);
    }
});
