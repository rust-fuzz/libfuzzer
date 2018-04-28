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

pub use arbitrary;


use std::os::raw::c_char;
use std::os::raw::c_int;
use std::ffi::CString;
use std::{panic, ptr};

extern "C" {
    // This is the mangled name of the C++ function starting the fuzzer
    fn _ZN6fuzzer12FuzzerDriverEPiPPPcPFiPKhmE(argc: *mut c_int, argv: *mut *mut *mut c_char, callback: extern fn(*const u8, usize) -> c_int );
}

static mut STATIC_CLOSURE: *const () = ptr::null();

#[doc(hidden)]
pub extern "C" fn test_one_input<F>(data: *const u8, size: usize) -> c_int where F: Fn(&[u8]) + panic::RefUnwindSafe {
    unsafe {
        let data_slice = ::std::slice::from_raw_parts(data, size);
        let closure = STATIC_CLOSURE as *const F;
        // We still catch unwinding panics just in case the fuzzed code modifies
        // the panic hook.
        // If so, the fuzzer will be unable to tell different bugs appart and you will
        // only be able to find one bug at a time before fixing it to then find a new one.
        let did_panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (&*closure)(data_slice);
        })).is_err();

        if did_panic {
            // hopefully the custom panic hook will be called before and abort the
            // process before the stack frames are unwinded.
            std::process::abort();
        }
    }
    0
}

/// Run libfuzzer with a given closure
///
/// This is the undelying API used by the [`fuzz!()`] macro, use that instead where possible.
pub fn fuzz<F>(closure: F) where F: Fn(&[u8]) + std::panic::RefUnwindSafe + Sync + Send {
    // Converts env::args() to C format
    let args   = std::env::args()
                    .map(|arg| CString::new(arg).unwrap()) // convert args to null terminated C strings
                    .collect::<Vec<_>>();
    let c_args = args.iter()
                    .map(|arg| arg.as_ptr())
                    .chain(std::iter::once(std::ptr::null())) // C standard expects the array of args to be null terminated
                    .collect::<Vec<*const c_char>>();

    let mut argc = c_args.len() as c_int - 1;
    let mut argv = c_args.as_ptr() as *mut *mut c_char;

    // Registers a panic hook that aborts the process before unwinding.
    // It is useful to abort before unwinding so that the fuzzer will then be
    // able to analyse the process stack frames to tell different bugs appart.
    // 
    // HACK / FIXME: it would be better to use `-C panic=abort` but it's currently
    // impossible to build code using compiler plugins with this flag.
    // We will be able to remove this code when
    // https://github.com/rust-lang/cargo/issues/5423 is fixed.
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        default_hook(panic_info);
        std::process::abort();
    }));

    unsafe {
        assert!(STATIC_CLOSURE.is_null());
        // save closure capture at static location
        STATIC_CLOSURE = Box::into_raw(Box::new(closure)) as *const ();

        // call C++ mangled method `fuzzer::FuzzerDriver()`
        _ZN6fuzzer12FuzzerDriverEPiPPPcPFiPKhmE(&mut argc, &mut argv, test_one_input::<F>);
    }
}

/// Define a fuzz target.
///
/// ## Example
///
/// This example takes a `&[u8]` slice and attempts to parse it. The parsing
/// might fail and return an `Err`, but it shouldn't ever panic or segfault.
///
/// ```no_run
/// use libfuzzer_sys::fuzz;
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
/// use libfuzzer_sys::{arbitrary, fuzz};
///
/// #[derive(Debug, arbitrary::Arbitrary)]
/// pub struct Rgb {
///     r: u8,
///     g: u8,
///     b: u8,
/// }
///
/// // Write a fuzz target that works with RGB colors instead of raw bytes.
/// fuzz!(|color: Rgb| {
///     my_crate::convert_color(color);
/// });
/// # mod my_crate { fn convert_color(_: super::Rgb) {} }
#[macro_export]
macro_rules! fuzz {
    (|$buf:ident| $body:block) => {
        $crate::fuzz(|$buf| $body);
    };
    (|$buf:ident: &[u8]| $body:block) => {
        $crate::fuzz(|$buf| $body);
    };
    (|$buf:ident: $dty: ty| $body:block) => {
        $crate::fuzz(|$buf| {
            let $buf: $dty = {
                use $crate::arbitrary::{Arbitrary, RingBuffer};
                let mut buf = match RingBuffer::new($buf, $buf.len()) {
                    Ok(b) => b,
                    Err(_) => return,
                };

                let d: $dty = match Arbitrary::arbitrary(&mut buf) {
                    Ok(d) => d,
                    Err(_) => return,
                };
                d
            };

            $body
        });
    };
}
