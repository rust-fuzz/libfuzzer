use libfuzzer_sys::fuzz;

fn main() {
    // Custom initialization code here
    println!("Initializing fuzzer...");
    example_init::initialize();

    fuzz!(|data: &[u8]| {
        example_init::bigbang(data);
    });
}
