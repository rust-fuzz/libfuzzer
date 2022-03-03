#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|rgb: example_arbitrary::Rgb| {
    example_arbitrary::test(rgb);
});
