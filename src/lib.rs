use std::os::raw::c_char;
use std::os::raw::c_int;
use std::ffi::CString;

extern "C" {
    // This is the mangled name of the C++ function starting the fuzzer
    fn _ZN6fuzzer12FuzzerDriverEPiPPPcPFiPKhmE(argc: *mut c_int, argv: *mut *mut *mut c_char, callback: extern fn(*const u8, usize) -> c_int );
}

static mut STATIC_CLOSURE: Option<Box<FnMut(&[u8])>> = None;

// #[no_mangle]
// pub extern "C" fn LLVMFuzzerInitialize(_argc: *const isize, _argv: *const *const *const u8) -> isize {
//     0
// }

#[no_mangle]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> c_int {
    unsafe {
        let data_slice = ::std::slice::from_raw_parts(data, size);
        if let Some(ref mut closure) = STATIC_CLOSURE {
            // We still catch unwinding panics just in case the fuzzed code modifies
            // the panic hook.
            // If so, the fuzzer will be unable to tell different bugs appart and you will
            // only be able to find one bug at a time before fixing it to then find a new one.
            let did_panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                closure(data_slice);
            })).is_err();

            if did_panic {
                // hopefully the custom panic hook will be called before and abort the
                // process before the stack frames are unwinded.
                std::process::abort();
            }
        }
    }
    0
}

pub fn fuzz<F>(closure: F) where F: Fn(&[u8]) + std::panic::RefUnwindSafe + 'static {
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
    std::panic::set_hook(Box::new(|_| {
            std::process::abort();
    }));

    unsafe {
        // save closure at static location
        STATIC_CLOSURE = Some(Box::new(closure));

        // call C++ mangled method `fuzzer::FuzzerDriver()`
        _ZN6fuzzer12FuzzerDriverEPiPPPcPFiPKhmE(&mut argc, &mut argv, LLVMFuzzerTestOneInput);
    }
}

#[macro_export]
macro_rules! fuzz {
    (|$buf:ident| $body:block) => {
        libfuzzer_sys::fuzz(move |$buf| $body);
    };
    (|$buf:ident: &[u8]| $body:block) => {
        libfuzzer_sys::fuzz(move |$buf| $body);
    };
    (|$buf:ident: $dty: ty| $body:block) => {
        libfuzzer_sys::fuzz(move |$buf| {
            let $buf: $dty = {
                use arbitrary::{Arbitrary, RingBuffer};
                if let Ok(d) = RingBuffer::new($buf, $buf.len()).and_then(|mut b|{
                        Arbitrary::arbitrary(&mut b).map_err(|_| "")
                    }) {
                    d
                } else {
                    return
                }
            };

            $body
        });
    };
}
