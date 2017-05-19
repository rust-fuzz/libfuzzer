#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

fuzz_target!(|data: u16| {
    if data == 0xba7 { // ba[nana]
        panic!("success!");
    }
});
