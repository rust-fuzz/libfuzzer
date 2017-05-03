#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

fuzz_setup!({
    // Enter your setup here.
});

fuzz_teardown!({
    // Enter your teardown here.
});

fuzz_target!(|data| {
    if data == b"banana" {
        panic!("success!");
    }
});
