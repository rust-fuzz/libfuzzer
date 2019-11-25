#![allow(improper_ctypes)] // we do not actually cross the FFI bound here

extern "C" {
    fn rust_fuzzer_test_input(input: &[u8]);
}

#[export_name = "LLVMFuzzerTestOneInput"]
pub fn test_input_wrap(data: *const u8, size: usize) -> i32 {
    let test_input = ::std::panic::catch_unwind(|| unsafe {
        let data_slice = ::std::slice::from_raw_parts(data, size);
        rust_fuzzer_test_input(data_slice);
    });
    if test_input.err().is_some() {
        // hopefully the custom panic hook will be called before and abort the
        // process before the stack frames are unwinded.
        ::std::process::abort();
    }
    0
}

#[export_name = "LLVMFuzzerInitialize"]
pub fn initialize(_argc: *const isize, _argv: *const *const *const u8) -> isize {
    // Registers a panic hook that aborts the process before unwinding.
    // It is useful to abort before unwinding so that the fuzzer will then be
    // able to analyse the process stack frames to tell different bugs appart.
    //
    // HACK / FIXME: it would be better to use `-C panic=abort` but it's currently
    // impossible to build code using compiler plugins with this flag.
    // We will be able to remove this code when
    // https://github.com/rust-lang/cargo/issues/5423 is fixed.
    ::std::panic::set_hook(Box::new(|_| {
        ::std::process::abort();
    }));
    0
}

#[macro_export]
macro_rules! fuzz_target {
    (|$bytes:ident| $body:block) => {
        #[no_mangle]
        pub extern "C" fn rust_fuzzer_test_input($bytes: &[u8]) {
            $body
        }
    };
    (|$data:ident: &[u8]| $body:block) => {
        fuzz_target!(|$data| $body);
    };
    (|$data:ident: $dty: ty| $body:block) => {
        #[no_mangle]
        pub extern "C" fn rust_fuzzer_test_input(bytes: &[u8]) {
            use arbitrary::{Arbitrary, RingBuffer};

            let mut buf = match RingBuffer::new(bytes, bytes.len()) {
                Ok(b) => b,
                Err(_) => return,
            };

            let $data: $dty = match Arbitrary::arbitrary(&mut buf) {
                Ok(d) => d,
                Err(_) => return,
            };

            $body
        }
    };
}
