#![no_main]

use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use libfuzzer_sys::{fuzz_mutator, fuzz_target};
use std::io::{Read, Write};

fuzz_target!(|data: &[u8]| {
    // Decompress the input data and crash if it starts with "boom".
    if let Some(data) = decompress(data) {
        if data.starts_with(b"boom") {
            panic!();
        }
    }
});

fuzz_mutator!(
    |data: &mut [u8], size: usize, max_size: usize, _seed: u32| {
        // Decompress the input data. If that fails, use a dummy value.
        let mut decompressed = decompress(&data[..size]).unwrap_or_else(|| b"hi".to_vec());

        // Mutate the decompressed data with `libFuzzer`'s default mutator. Make
        // the `decompressed` vec's extra capacity available for insertion
        // mutations via `resize`.
        let len = decompressed.len();
        let cap = decompressed.capacity();
        decompressed.resize(cap, 0);
        let new_decompressed_size = libfuzzer_sys::fuzzer_mutate(&mut decompressed, len, cap);

        // Recompress the mutated data.
        let compressed = compress(&decompressed[..new_decompressed_size]);

        // Copy the recompressed mutated data into `data` and return the new size.
        let new_size = std::cmp::min(max_size, compressed.len());
        data[..new_size].copy_from_slice(&compressed[..new_size]);
        new_size
    }
);

fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    if decoder.read_to_end(&mut decompressed).is_ok() {
        Some(decompressed)
    } else {
        None
    }
}

fn compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .expect("writing into a vec is infallible");
    encoder.finish().expect("writing into a vec is infallible")
}
