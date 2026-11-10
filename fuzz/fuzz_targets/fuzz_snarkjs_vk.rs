#![no_main]

use astrolabe_core::snarkjs::{parse_snarkjs_vk, parse_snarkjs_vk_envelope};
use astrolabe_core::decode_vk;
use core::str;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = str::from_utf8(data) {
        if let Ok(vk) = parse_snarkjs_vk(s) {
            let enc = vk.encode();
            let roundtrip = decode_vk(&enc).expect("decoded VK from snarkjs must decode via ACF");
            assert_eq!(vk, roundtrip);
        }
        let _ = parse_snarkjs_vk_envelope(s);
    }
});
