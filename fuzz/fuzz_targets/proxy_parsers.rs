#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    pocket_net::proxy::fuzz_parsers(data);
});
