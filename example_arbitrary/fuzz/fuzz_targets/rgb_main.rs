use libfuzzer_sys::fuzz;

fn main() {
    fuzz!(|rgb: example_arbitrary::Rgb| {
        example_arbitrary::test(rgb);
    });
}
