#![no_main]

use astrolabe_core::decode_vk;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(vk) = decode_vk(data) {
        let enc = vk.encode();
        let roundtrip = decode_vk(&enc).expect("decoded Groth16 VK must roundtrip successfully");
        assert_eq!(vk, roundtrip);
    }
});
