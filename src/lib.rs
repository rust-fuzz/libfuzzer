//! Bindings to [libFuzzer](http://llvm.org/docs/LibFuzzer.html): a runtime for
//! coverage-guided fuzzing.
//!
//! See [the `cargo-fuzz`
//! guide](https://rust-fuzz.github.io/book/cargo-fuzz.html) for a usage
//! tutorial.
//!
//! The main export of this crate is [the `fuzz_target!`
//! macro](./macro.fuzz_target.html), which allows you to define targets for
//! libFuzzer to exercise.

#![deny(missing_docs, missing_debug_implementations)]
use std::os::unix::ffi::OsStrExt;
use std::os::raw::{c_int, c_char};

pub use arbitrary;

#[link(name="fuzzer", kind="static")]
extern "C" {
    fn LLVMFuzzerRunDriver(
        argc: *mut c_int,
        argv: *mut *mut *mut c_char,
        cb: unsafe extern fn(data: *const u8, size: usize) -> c_int
    ) -> c_int;
}

#[doc(hidden)]
pub fn test_case(body: unsafe extern fn(*const u8, usize) -> c_int) {
    let args_os = std::env::args_os();
    let mut len = args_os.len() as _;
    let mut args: Vec<*mut c_char> = args_os.map(|arg| arg.as_bytes().as_ptr() as *mut _).collect();
    unsafe {
        std::process::exit(LLVMFuzzerRunDriver(&mut len, &mut args.as_mut_ptr(), body) as _);
    }
}

#[doc(hidden)]
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
    let default_hook = ::std::panic::take_hook();
    ::std::panic::set_hook(Box::new(move |panic_info| {
        default_hook(panic_info);
        ::std::process::abort();
    }));
    0
}

/// Define a fuzz target.
///
/// ## Example
///
/// This example takes a `&[u8]` slice and attempts to parse it. The parsing
/// might fail and return an `Err`, but it shouldn't ever panic or segfault.
///
/// ```no_run
/// #![no_main]
///
/// use libfuzzer_sys::fuzz_target;
///
/// // Note: `|input|` is short for `|input: &[u8]|`.
/// fuzz_target!(|input| {
///     let _result: Result<_, _> = my_crate::parse(input);
/// });
/// # mod my_crate { pub fn parse(_: &[u8]) -> Result<(), ()> { unimplemented!() } }
/// ```
///
/// ## Arbitrary Input Types
///
/// The input is a `&[u8]` slice by default, but you can take arbitrary input
/// types, as long as the type implements [the `arbitrary` crate's `Arbitrary`
/// trait](https://docs.rs/arbitrary/*/arbitrary/trait.Arbitrary.html) (which is
/// also re-exported as `libfuzzer_sys::arbitrary::Arbitrary` for convenience).
///
/// For example, if you wanted to take an arbitrary RGB color, you could do the
/// following:
///
/// ```no_run
/// #![no_main]
///
/// use libfuzzer_sys::{arbitrary::{Arbitrary, Unstructured}, fuzz_target};
///
/// #[derive(Debug)]
/// pub struct Rgb {
///     r: u8,
///     g: u8,
///     b: u8,
/// }
///
/// impl Arbitrary for Rgb {
///     fn arbitrary<U>(raw: &mut U) -> Result<Self, U::Error>
///     where
///         U: Unstructured + ?Sized
///     {
///         let mut buf = [0; 3];
///         raw.fill_buffer(&mut buf)?;
///         let r = buf[0];
///         let g = buf[1];
///         let b = buf[2];
///         Ok(Rgb { r, g, b })
///     }
/// }
///
/// // Write a fuzz target that works with RGB colors instead of raw bytes.
/// fuzz_target!(|color: Rgb| {
///     my_crate::convert_color(color);
/// });
/// # mod my_crate { fn convert_color(_: super::Rgb) {} }
#[macro_export]
macro_rules! fuzz_target {
    (|$bytes:ident| $body:block) => {
        unsafe extern fn test_body(data: *const u8, size: usize) -> ::std::os::raw::c_int {
            let $bytes = unsafe {
                // SAFE: We expect libfuzzer to be well formed and call this with
                // dereferenceable `data` and accurate `size`.
                ::std::slice::from_raw_parts(data, size)
            };

            // When `RUST_LIBFUZZER_DEBUG_PATH` is set, write the debug
            // formatting of the input to that file. This is only intended for
            // `cargo fuzz`'s use!
            if let Ok(path) = ::std::env::var("RUST_LIBFUZZER_DEBUG_PATH") {
                use ::std::io::Write;
                let mut file = ::std::fs::File::create(path)
                    .expect("failed to create `RUST_LIBFUZZER_DEBUG_PATH` file");
                ::std::writeln!(&mut file, "{:?}", $bytes)
                    .expect("failed to write to `RUST_LIBFUZZER_DEBUG_PATH` file");
                return 0;
            }
            if ::std::panic::catch_unwind(|| $body).is_err() {
                // hopefully the custom panic hook will be called before and abort the
                // process before the stack frames are unwinded.
                ::std::process::abort();
            }
            0
        }

        fn main() {
            $crate::test_case(test_body)
        }
    };

    (|$data:ident: &[u8]| $body:block) => {
        fuzz_target!(|$data| $body);
    };

    (|$data:ident: $dty: ty| $body:block) => {
        unsafe extern fn test_body(data: *const u8, size: usize) -> ::std::os::raw::c_int {
            use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
            let bytes = unsafe {
                // SAFE: We expect libfuzzer to be well formed and call this with
                // dereferenceable `data` and accurate `size`.
                ::std::slice::from_raw_parts(data, size)
            };

            // Early exit if we don't have enough bytes for the `Arbitrary`
            // implementation. This helps the fuzzer avoid exploring all the
            // different not-enough-input-bytes paths inside the `Arbitrary`
            // implementation. Additionally, it exits faster, letting the fuzzer
            // get to longer inputs that actually lead to interesting executions
            // quicker.
            if bytes.len() < <$dty as Arbitrary>::size_hint(0).0 {
                return 0;
            }

            let mut u = Unstructured::new(bytes);
            let data = <$dty as Arbitrary>::arbitrary_take_rest(u);

            // When `RUST_LIBFUZZER_DEBUG_PATH` is set, write the debug
            // formatting of the input to that file. This is only intended for
            // `cargo fuzz`'s use!
            if let Ok(path) = std::env::var("RUST_LIBFUZZER_DEBUG_PATH") {
                use std::io::Write;
                let mut file = std::fs::File::create(path)
                    .expect("failed to create `RUST_LIBFUZZER_DEBUG_PATH` file");
                (match data {
                    Ok(data) => writeln!(&mut file, "{:#?}", data),
                    Err(err) => writeln!(&mut file, "Arbitrary Error: {}", err),
                })
                .expect("failed to write to `RUST_LIBFUZZER_DEBUG_PATH` file");
                return;
            }

            let $data = match data {
                Ok(d) => d,
                Err(_) => return,
            };
            if ::std::panic::catch_unwind(|| $body).is_err() {
                // hopefully the custom panic hook will be called before and abort the
                // process before the stack frames are unwinded.
                ::std::process::abort();
            }
            0
        }

        fn main() {
            $crate::test_case(test_body);
        }
    };
}
