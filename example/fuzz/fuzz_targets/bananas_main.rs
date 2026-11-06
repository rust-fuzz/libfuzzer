use libfuzzer_sys::fuzz;

fn main() {
    fuzz!(|data: &[u8]| {
        if data == "banana!".as_bytes() {
            panic!("success!");
        }
        example::bananas(data);
    });
}
