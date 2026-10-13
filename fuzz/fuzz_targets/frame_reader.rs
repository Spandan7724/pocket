//! Length-prefixed framing with arbitrary split points, then the decoders.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pocket_proto::frame::FrameReader;

fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else { return };
    let cut = (split as usize).min(rest.len());
    let mut r = FrameReader::default();
    for part in [&rest[..cut], &rest[cut..]] {
        r.push(part);
        while let Ok(Some(frame)) = r.next_frame() {
            pocket_proto::guest::decode_any_from_guest(&frame);
        }
    }
    let _ = pocket_proto::frame::read_frame(&mut &rest[..]);
});
