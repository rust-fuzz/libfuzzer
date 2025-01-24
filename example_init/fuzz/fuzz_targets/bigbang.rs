#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(
    init: {
        // Custom initialization code here
        println!("Initializing fuzzer...");
        example_init::initialize();
    },
    |data: &[u8]| {
    example_init::bigbang(data);
});
