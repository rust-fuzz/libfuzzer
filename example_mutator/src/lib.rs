use flate2::read::GzDecoder;
use std::io::Read;

pub fn test(data: &[u8]) {
    if let Some(data) = decompress(data) {
        if data.starts_with(b"boom") {
            panic!();
        }
    }
}

fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    if decoder.read_to_end(&mut decompressed).is_ok() {
        Some(decompressed)
    } else {
        None
    }
}
