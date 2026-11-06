//! Support libFuzzer running from `main` via [`fuzz`] - without `#![no_main]`.
//!
//! Enter libFuzzer via `LLVMFuzzerRunDriver` and coordinate crash signal handling with
//! Rust.

use crate::initialize;
use std::{
    ffi::{c_char, c_int},
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(windows)]
extern "C" {
    fn __p___argc() -> *mut c_int;
    fn __p___argv() -> *mut *mut *mut c_char;
}

extern "C-unwind" {
    fn LLVMFuzzerRunDriver(
        argc: *mut c_int,
        argv: *mut *mut *mut c_char,
        callback: unsafe extern "C" fn(*const u8, usize) -> c_int,
    ) -> c_int;
}

static LIBFUZZER_STARTED: AtomicBool = AtomicBool::new(false);

/// Runs libFuzzer with fuzz `target`, backing [`fuzz`].
#[doc(hidden)]
pub fn run_libfuzzer<F>(mut target: F) -> !
where
    F: FnMut(&[u8]) -> c_int,
{
    assert!(
        !LIBFUZZER_STARTED.swap(true, Ordering::SeqCst),
        "libFuzzer driver can only be started once"
    );
    // best-effort against accidental misuse
    assert_eq!(
        std::thread::current().name(),
        Some("main"),
        "fuzz! must run on the process's main thread"
    );
    initialize();

    // windows: libFuzzer's own `main` gets the CRT's arguments
    #[cfg(windows)]
    let (mut argc, mut argv) = unsafe { (*__p___argc(), *__p___argv()) };
    #[cfg(not(windows))]
    let (mut argc, mut argv) = {
        let args = std::env::args_os();
        let argc = args.len() as c_int;
        let argv: Vec<*mut c_char> = args
            .map(|arg| {
                std::ffi::CString::new(arg.as_encoded_bytes())
                    .expect("OS args do not contain NUL")
                    .into_raw()
            })
            .chain(std::iter::once(std::ptr::null_mut()))
            .collect();
        (argc, argv.leak().as_mut_ptr())
    };

    #[cfg(unix)]
    crash_signals::release();
    callback::run_with_handler(&mut target, || unsafe {
        LLVMFuzzerRunDriver(&mut argc, &mut argv, callback::trampoline)
    })
}

mod callback {
    use crate::catch_and_abort;
    use std::{cell::Cell, ffi::c_int, slice};

    type Callback<'a> = *mut (dyn FnMut(&[u8]) -> c_int + 'a);

    thread_local! {
        /// The installed handler; taken out while it runs, so calls can't overlap.
        static SLOT: Cell<Option<Callback<'static>>> = const { Cell::new(None) };
    }

    /// Invokes the closure stored in [`SLOT`].
    ///
    /// Call it from within [`run_with_handler`]'s `run`, to be used as the callback for
    /// `LLVMFuzzerRunDriver`.
    ///
    /// # Safety
    ///
    /// See [`std::slice::from_raw_parts`], in particular
    /// - `data` is non-null, and valid for reads for `len` bytes
    /// - `data` points to `len` consecutive properly initialized `u8`'s
    pub unsafe extern "C" fn trampoline(data: *const u8, len: usize) -> c_int {
        catch_and_abort(|| -> Option<c_int> {
            SLOT.try_with(|slot| {
                let closure = slot.take()?;

                // SAFETY: caller ensured
                let data = unsafe { slice::from_raw_parts(data, len) };
                // SAFETY: taking it out of SLOT blocks reentrant calls; run_with_handler
                // keeps the handler live until the process exits or aborts.
                let status = unsafe { (*closure)(data) };
                slot.set(Some(closure));
                Some(status)
            })
            .unwrap_or_default()
        })
        .unwrap_or_else(|| {
            eprintln!("libfuzzer: aborting (callback unavailable)");
            std::process::abort()
        })
    }

    pub fn run_with_handler<'a>(
        handler: &'a mut (dyn FnMut(&[u8]) -> c_int + 'a),
        run: impl FnOnce() -> c_int,
    ) -> ! {
        let status = catch_and_abort(|| {
            SLOT.with(|slot| {
                assert!(slot.get().is_none(), "handler already installed");

                // SAFETY: this function exits when `run` returns and aborts on unwind,
                // so the borrowed handler stays live whenever SLOT can be used.
                let handler: Callback<'static> =
                    unsafe { std::mem::transmute(handler as Callback<'a>) };
                slot.set(Some(handler));
                run()
            })
        });

        std::process::exit(status)
    }
}

/// Keeps Rust from installing SIGSEGV/SIGBUS handlers that interfere with
/// libFuzzer's, by claiming them before `main` in [`fuzz`] binaries.
#[doc(hidden)]
#[macro_export]
macro_rules! __crash_signals {
    () => {
        #[cfg(all(unix, not(target_vendor = "apple")))]
        #[used]
        #[link_section = ".init_array"]
        static CLAIM_CRASH_SIGNALS: extern "C" fn() = $crate::fuzz_macro::crash_signals::claim;

        // prevent ASan padding statics with redzones (null pointers)
        #[cfg(target_vendor = "apple")]
        mod __claim_crash_signals {
            ::std::arch::global_asm!(
                ".pushsection __DATA,__mod_init_func,mod_init_funcs",
                ".balign {}",
                ".dc.a {}",
                ".popsection",
                const ::std::mem::align_of::<usize>(),
                sym $crate::fuzz_macro::crash_signals::claim,
            );
        }
    };
}

#[cfg(unix)]
#[doc(hidden)]
pub mod crash_signals {
    use super::{Ordering, LIBFUZZER_STARTED};
    use std::{ffi::c_int, mem, ptr};

    pub extern "C" fn claim() {
        replace(libc::SIGSEGV, libc::SIG_DFL, placeholder as *const () as _);
        replace(libc::SIGBUS, libc::SIG_DFL, placeholder as *const () as _);
    }

    /// Restores `SIG_DFL` so that libFuzzer installs its own crash handlers.
    pub(crate) fn release() {
        replace(libc::SIGSEGV, placeholder as *const () as _, libc::SIG_DFL);
        replace(libc::SIGBUS, placeholder as *const () as _, libc::SIG_DFL);
    }

    /// Preserves the original signal before fuzzing; aborts once libFuzzer starts
    /// so it also sees crashes from handlers that chain here.
    extern "C" fn placeholder(signal: c_int) {
        if LIBFUZZER_STARTED.load(Ordering::SeqCst) {
            std::process::abort();
        }
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
            libc::raise(signal);
        }
    }

    fn replace(signal: c_int, from: libc::sighandler_t, to: libc::sighandler_t) {
        unsafe {
            let mut action: libc::sigaction = mem::zeroed();
            libc::sigaction(signal, ptr::null(), &mut action);
            if action.sa_sigaction == from {
                action.sa_sigaction = to;
                libc::sigaction(signal, &action, ptr::null_mut());
            }
        }
    }
}

/// Fuzz a closure-like block of code by passing it an object of arbitrary type.
///
/// Call this macro only from the process's main thread.
///
/// On Unix, `SIGPIPE` stays ignored by default, as in a normal Rust `main`.
/// Broken-pipe writes can therefore panic and produce a crash file, while
/// `fuzz_target!` binaries usually terminate silently. For silent termination,
/// set `SIGPIPE` to `SIG_DFL` before calling `fuzz!`.
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
/// fn main() {
///     fuzz!(|input| {
///         let _result: Result<_, _> = my_crate::parse(input);
///     });
/// }
/// # mod my_crate { pub fn parse(_: &[u8]) -> Result<(), ()> { unimplemented!() } }
/// ```
///
/// ## Rejecting Inputs
///
/// It may be desirable to reject some inputs, i.e. to not add them to the
/// corpus.
///
/// For example, when fuzzing an API consisting of parsing and other logic,
/// one may want to allow only those inputs into the corpus that parse
/// successfully. To indicate whether an input should be kept in or rejected
/// from the corpus, return either [`Corpus::Keep`](crate::Corpus::Keep) or
/// [`Corpus::Reject`](crate::Corpus::Reject) from your fuzz target. The default
/// behavior (e.g. if `()` is returned) is to keep the input in the corpus.
///
/// For example:
///
/// ```no_run
/// use libfuzzer_sys::{Corpus, fuzz};
///
/// fn main() {
///     fuzz!(|input: String| -> Corpus {
///         let parts: Vec<&str> = input.splitn(2, '=').collect();
///         if parts.len() != 2 {
///             return Corpus::Reject;
///         }
///
///         let key = parts[0];
///         let value = parts[1];
///         let _result: Result<_, _> = my_crate::parse(key, value);
///         Corpus::Keep
///     });
/// }
/// # mod my_crate { pub fn parse(_key: &str, _value: &str) -> Result<(), ()> { unimplemented!() } }
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
/// use libfuzzer_sys::{arbitrary::{Arbitrary, Error, Unstructured}, fuzz};
///
/// #[derive(Debug)]
/// pub struct Rgb {
///     r: u8,
///     g: u8,
///     b: u8,
/// }
///
/// impl<'a> Arbitrary<'a> for Rgb {
///     fn arbitrary(raw: &mut Unstructured<'a>) -> Result<Self, Error> {
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
/// fn main() {
///     fuzz!(|color: Rgb| {
///         my_crate::convert_color(color);
///     });
/// }
/// # mod my_crate {
/// #     use super::Rgb;
/// #     pub fn convert_color(_: Rgb) {}
/// # }
/// ```
///
/// You can also enable the `arbitrary` crate's custom derive via this crate's
/// `"arbitrary-derive"` cargo feature.
///
/// ## Init Code
///
/// Init code to the fuzz target can be placed outside the fuzz macro within the
/// main function. If setup code before `fuzz!` panics, it uses normal Rust panic
/// handling and is not reported as a crash found by libFuzzer.
///
/// ```no_run
/// use libfuzzer_sys::fuzz;
/// use std::collections::HashSet;
///
/// fn main() {
///     let read_dictionary = |_| unimplemented!();
///     let dictionary: HashSet<String> = read_dictionary("/usr/share/dict/words");
///
///     fuzz!(|input| {
///         // Use the initialized `dictionary` here...
///     });
/// }
/// ```
///
#[cfg_attr(docsrs, doc(cfg(feature = "fuzz_macro")))]
#[macro_export]
macro_rules! fuzz {
    (|$bytes:ident| $body:expr) => {
        $crate::fuzz!(|$bytes: &[u8]| -> () { $body })
    };

    (|$bytes:ident: &[u8]| $body:expr) => {
        $crate::fuzz!(|$bytes: &[u8]| -> () { $body })
    };

    (|$bytes:ident: &[u8]| -> $rty:ty $body:block) => {{
        $crate::__crash_signals!();

        // Keep the fuzzer in a separate function so crash backtraces contain
        // a uniquely named stack frame, helping oss-fuzz deduplicate crashes
        // across different targets correctly.
        //
        // Since nested functions cannot access the outer item's generics or
        // `Self`, pass the user's types as generic parameters instead.
        #[inline(never)]
        fn __libfuzzer_sys_run<R>(
            body: &mut dyn FnMut(&[::std::primitive::u8]) -> R,
            data: &[::std::primitive::u8],
        ) -> R {
            body(data)
        }

        let mut __libfuzzer_sys_body = |$bytes: &[::std::primitive::u8]| -> $rty { $body };
        let debug_path = $crate::rust_libfuzzer_debug_path();

        $crate::fuzz_macro::run_libfuzzer(|bytes: &[::std::primitive::u8]| -> ::std::ffi::c_int {
            // When `RUST_LIBFUZZER_DEBUG_PATH` is set, write the debug
            // formatting of the input to that file. This is only intended for
            // `cargo fuzz`'s use!

            if let ::std::option::Option::Some(path) = debug_path {
                $crate::write_debug_path(path, ::std::format_args!("{:?}", bytes));
                return 0;
            }

            let result =
                $crate::Corpus::from(__libfuzzer_sys_run(&mut __libfuzzer_sys_body, bytes));
            result.into_libfuzzer_code()
        })
    }};

    (|$data:ident: $dty:ty| $body:expr) => {
        $crate::fuzz!(|$data: $dty| -> () { $body })
    };

    (|$data:ident: $dty:ty| -> $rty:ty $body:block) => {{
        $crate::__crash_signals!();

        // See above for why this function is separate and generic.
        #[inline(never)]
        fn __libfuzzer_sys_run<T, R>(body: &mut dyn FnMut(T) -> R, data: T) -> R {
            body(data)
        }

        let mut __libfuzzer_sys_body = |$data: $dty| -> $rty { $body };

        let min_size = <$dty as $crate::arbitrary::Arbitrary>::size_hint(0).0;
        let debug_path = $crate::rust_libfuzzer_debug_path();

        $crate::fuzz_macro::run_libfuzzer(|bytes: &[::std::primitive::u8]| -> ::std::ffi::c_int {
            // Early exit if we don't have enough bytes for the `Arbitrary`
            // implementation. This helps the fuzzer avoid exploring all the
            // different not-enough-input-bytes paths inside the `Arbitrary`
            // implementation. Additionally, it exits faster, letting the fuzzer
            // get to longer inputs that actually lead to interesting executions
            // quicker.
            if bytes.len() < min_size {
                return -1;
            }

            let u = $crate::arbitrary::Unstructured::new(bytes);
            let data = <$dty as $crate::arbitrary::Arbitrary>::arbitrary_take_rest(u);

            // When `RUST_LIBFUZZER_DEBUG_PATH` is set, write the debug
            // formatting of the input to that file. This is only intended for
            // `cargo fuzz`'s use!

            if let ::std::option::Option::Some(path) = debug_path {
                match data {
                    ::std::result::Result::Ok(data) => {
                        $crate::write_debug_path(path, ::std::format_args!("{:#?}", data))
                    }
                    ::std::result::Result::Err(err) => $crate::write_debug_path(
                        path,
                        ::std::format_args!("Arbitrary Error: {}", err),
                    ),
                };
                return -1;
            }

            let data = match data {
                ::std::result::Result::Ok(d) => d,
                ::std::result::Result::Err(_) => return -1,
            };

            let result = $crate::Corpus::from(__libfuzzer_sys_run(&mut __libfuzzer_sys_body, data));
            result.into_libfuzzer_code()
        })
    }};
}
