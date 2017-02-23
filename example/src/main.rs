#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

fuzz_target!(|data| {
    if data == b"banana" {
        panic!("success!");
    }
});
