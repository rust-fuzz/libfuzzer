#![feature(process_abort)]

extern "C" {
    #![allow(improper_ctypes)] // we do not actually cross the FFI bound here

    fn rust_fuzzer_test_input(input: &[u8]);
    fn rust_fuzzer_setup();
    fn rust_fuzzer_teardown();
}

#[export_name="LLVMFuzzerTestOneInput"]
pub fn test_input_wrap(data: *const u8, size: usize) -> i32 {
    ::std::panic::catch_unwind(|| unsafe {
        let data_slice = ::std::slice::from_raw_parts(data, size);
        rust_fuzzer_test_input(data_slice);
    }).err().map(|_| ::std::process::abort());
    0
}

#[export_name="LLVMFuzzerSetup"]
pub fn test_setup_wrap() -> () {
    unsafe {
        rust_fuzzer_setup()
    }
}

#[export_name="LLVMFuzzerTeardown"]
pub fn test_teardown_wrap() -> () {
    unsafe {
        rust_fuzzer_teardown()
    }
}

#[macro_export]
macro_rules! fuzz_target {
    (|$bytes:ident| $body:block) => {
        #[no_mangle]
        pub extern fn rust_fuzzer_test_input($bytes: &[u8]) {
            $body
        }
    };
    (|$bytes:ident: &[u8]| $body:block) => {
        #[no_mangle]
        pub extern fn rust_fuzzer_test_input($bytes: &[u8]) {
            $body
        }
    }
}

#[macro_export]
macro_rules! fuzz_setup {
    ($body: block) => {
        #[no_mangle]
        pub extern fn rust_fuzzer_setup() {
            $body
        }
    }
}

#[macro_export]
macro_rules! fuzz_teardown {
    ($body: block) => {
        #[no_mangle]
        pub extern fn rust_fuzzer_teardown() {
            $body
        }
    }
}
