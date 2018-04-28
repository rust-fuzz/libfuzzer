use libfuzzer_sys::fuzz;

fn main() {
    fuzz!(|data: &[u8]| {
        if data == b"banana!" {
            panic!("success!");
        }
    });   
}
