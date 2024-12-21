#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(
    init: {
        // Custom initialization code here
        println!("Initializing fuzzer...");
        std::env::set_var("MY_FUZZER_INIT", "1337");
    },
    |data: &[u8]| {
    if std::env::var("MY_FUZZER_INIT").unwrap() == "1337" && data == "bigbang!".as_bytes() {
        panic!("success!");
    }
    example_init::bigbang(data);
});
