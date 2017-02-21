#[macro_use]
pub mod libfuzzer {
    #[macro_export]
    macro_rules! fuzzer_target {
        (|$bytes:ident| $body:block) => {
            #[no_mangle]
            pub extern fn rust_fuzzer_test_input($bytes: &[u8]) {
                $body
            }
        }
    }
}
