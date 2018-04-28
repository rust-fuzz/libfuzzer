#[macro_use]
extern crate libfuzzer_sys;
extern crate arbitrary;

fn main() {
    // Here you can parse `std::env::args and
    // setup / initialize your project

    // The fuzz macro gives an arbitrary object (see `arbitrary crate`)
    // to a closure-like block of code.
    // For performance, it is recommended that you use the native type
    // `&[u8]` when possible.
    // Here, this slice will contain a "random" quantity of "random" data.
    fuzz!(|data: u16| {
        if data == 0xba7 { // ba[nana]
        panic!("success!");
        }
    });
}
