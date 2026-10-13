//! Every host-side decoder of guest-controlled payloads.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pocket_proto::guest::decode_any_from_guest(data);
});
