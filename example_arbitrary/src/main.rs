#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: u16| {
    if data == 0xba7 { // ba[nana]
        panic!("success!");
    }
});
