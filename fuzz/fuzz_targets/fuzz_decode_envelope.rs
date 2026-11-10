#![no_main]

use astrolabe_core::decode_envelope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = decode_envelope(data) {
        let enc = env.encode();
        let roundtrip = decode_envelope(&enc).expect("decoded ACF envelope must roundtrip");
        assert_eq!(env, roundtrip);
    }
});
