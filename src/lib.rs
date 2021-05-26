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
use once_cell::sync::OnceCell;

extern "C" {
    // We do not actually cross the FFI bound here.
    #[allow(improper_ctypes)]
    fn rust_fuzzer_test_input(input: &[u8]);

    fn LLVMFuzzerMutate(data: *mut u8, size: usize, max_size: usize) -> usize;
}

#[doc(hidden)]
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

#[doc(hidden)]
pub static RUST_LIBFUZZER_DEBUG_PATH: OnceCell<String> = OnceCell::new();

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

    // Initialize the `RUST_LIBFUZZER_DEBUG_PATH` cell with the path so it can be
    // reused with little overhead.
    if let Ok(path) = std::env::var("RUST_LIBFUZZER_DEBUG_PATH") {
        RUST_LIBFUZZER_DEBUG_PATH
            .set(path)
            .expect("Since this is initialize it is only called once so can never fail");
    }
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
/// # mod foo {
///
/// use libfuzzer_sys::{arbitrary::{Arbitrary, Error, Unstructured}, fuzz_target};
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
/// fuzz_target!(|color: Rgb| {
///     my_crate::convert_color(color);
/// });
/// # mod my_crate {
/// #     use super::Rgb;
/// #     pub fn convert_color(_: Rgb) {}
/// # }
/// # }
/// ```
///
/// You can also enable the `arbitrary` crate's custom derive via this crate's
/// `"arbitrary-derive"` cargo feature.
#[macro_export]
macro_rules! fuzz_target {
    (|$bytes:ident| $body:block) => {
        /// Auto-generated function
        #[no_mangle]
        pub extern "C" fn rust_fuzzer_test_input($bytes: &[u8]) {
            // When `RUST_LIBFUZZER_DEBUG_PATH` is set, write the debug
            // formatting of the input to that file. This is only intended for
            // `cargo fuzz`'s use!

            // `RUST_LIBFUZZER_DEBUG_PATH` is set in initialization.
            if let Some(path) = $crate::RUST_LIBFUZZER_DEBUG_PATH.get() {
                use std::io::Write;
                let mut file = std::fs::File::create(path)
                    .expect("failed to create `RUST_LIBFUZZER_DEBUG_PATH` file");
                writeln!(&mut file, "{:?}", $bytes)
                    .expect("failed to write to `RUST_LIBFUZZER_DEBUG_PATH` file");
                return;
            }

            $body
        }
    };

    (|$data:ident: &[u8]| $body:block) => {
        fuzz_target!(|$data| $body);
    };

    (|$data:ident: $dty: ty| $body:block) => {
        /// Auto-generated function
        #[no_mangle]
        pub extern "C" fn rust_fuzzer_test_input(bytes: &[u8]) {
            use $crate::arbitrary::{Arbitrary, Unstructured};

            // Early exit if we don't have enough bytes for the `Arbitrary`
            // implementation. This helps the fuzzer avoid exploring all the
            // different not-enough-input-bytes paths inside the `Arbitrary`
            // implementation. Additionally, it exits faster, letting the fuzzer
            // get to longer inputs that actually lead to interesting executions
            // quicker.
            if bytes.len() < <$dty as Arbitrary>::size_hint(0).0 {
                return;
            }

            let mut u = Unstructured::new(bytes);
            let data = <$dty as Arbitrary>::arbitrary_take_rest(u);

            // When `RUST_LIBFUZZER_DEBUG_PATH` is set, write the debug
            // formatting of the input to that file. This is only intended for
            // `cargo fuzz`'s use!

            // `RUST_LIBFUZZER_DEBUG_PATH` is set in initialization.
            if let Some(path) = $crate::RUST_LIBFUZZER_DEBUG_PATH.get() {
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

            $body
        }
    };
}

/// Define a custom mutator.
///
/// This is optional, and libFuzzer will use its own, default mutation strategy
/// if this is not provided.
///
/// You might consider using a custom mutator when your fuzz target is very
/// particular about the shape of its input:
///
/// * You want to fuzz "deeper" than just the parser.
/// * The input contains checksums that have to match the hash of some subset of
///   the data or else the whole thing is invalid, and therefore mutating any of
///   that subset means you need to recompute the checksums.
/// * Small random changes to the input buffer make it invalid.
///
/// That is, a custom mutator is useful in similar situations where [a `T:
/// Arbitrary` input type](macro.fuzz_target.html#arbitrary-input-types) is
/// useful. Note that the two approaches are not mutually exclusive; you can use
/// whichever is easier for your problem domain or both!
///
/// ## Implementation Contract
///
/// The original, unmodified input is given in `data[..size]`.
///
/// You must modify the data in place and return the new size.
///
/// The new size should not be greater than `max_size`. If this is not the case,
/// then the `data` will be truncated to fit within `max_size`. Note that
/// `max_size < size` is possible when shrinking test cases.
///
/// You must produce the same mutation given the same `seed`. Generally, when
/// choosing what kind of mutation to make or where to mutate, you should start
/// by creating a random number generator (RNG) that is seeded with the given
/// `seed` and then consult the RNG whenever making a decision:
///
/// ```no_run
/// #![no_main]
///
/// use rand::{rngs::StdRng, Rng, SeedableRng};
///
/// libfuzzer_sys::fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
///     let mut rng = StdRng::seed_from_u64(seed as u64);
///
/// #   let first_mutation = |_, _, _, _| todo!();
/// #   let second_mutation = |_, _, _, _| todo!();
/// #   let third_mutation = |_, _, _, _| todo!();
/// #   let fourth_mutation = |_, _, _, _| todo!();
///     // Choose which of our four supported kinds of mutations we want to make.
///     match rng.gen_range(0..4) {
///         0 => first_mutation(rng, data, size, max_size),
///         1 => second_mutation(rng, data, size, max_size),
///         2 => third_mutation(rng, data, size, max_size),
///         3 => fourth_mutation(rng, data, size, max_size),
///         _ => unreachable!()
///     }
/// });
/// ```
///
/// ## Example: Compression
///
/// Consider a simple fuzz target that takes compressed data as input,
/// decompresses it, and then asserts that the decompressed data doesn't begin
/// with "boom". It is difficult for `libFuzzer` (or any other fuzzer) to crash
/// this fuzz target because nearly all mutations it makes will invalidate the
/// compression format. Therefore, we use a custom mutator that decompresses the
/// raw input, mutates the decompressed data, and then recompresses it. This
/// allows `libFuzzer` to quickly discover crashing inputs.
///
/// ```no_run
/// #![no_main]
///
/// use flate2::{read::GzDecoder, write::GzEncoder, Compression};
/// use libfuzzer_sys::{fuzz_mutator, fuzz_target};
/// use std::io::{Read, Write};
///
/// fuzz_target!(|data: &[u8]| {
///     // Decompress the input data and crash if it starts with "boom".
///     if let Some(data) = decompress(data) {
///         if data.starts_with(b"boom") {
///             panic!();
///         }
///     }
/// });
///
/// fuzz_mutator!(
///     |data: &mut [u8], size: usize, max_size: usize, _seed: u32| {
///         // Decompress the input data. If that fails, use a dummy value.
///         let mut decompressed = decompress(&data[..size]).unwrap_or_else(|| b"hi".to_vec());
///
///         // Mutate the decompressed data with `libFuzzer`'s default mutator. Make
///         // the `decompressed` vec's extra capacity available for insertion
///         // mutations via `resize`.
///         let len = decompressed.len();
///         let cap = decompressed.capacity();
///         decompressed.resize(cap, 0);
///         let new_decompressed_size = libfuzzer_sys::fuzzer_mutate(&mut decompressed, len, cap);
///
///         // Recompress the mutated data.
///         let compressed = compress(&decompressed[..new_decompressed_size]);
///
///         // Copy the recompressed mutated data into `data` and return the new size.
///         let new_size = std::cmp::min(max_size, compressed.len());
///         data[..new_size].copy_from_slice(&compressed[..new_size]);
///         new_size
///     }
/// );
///
/// fn decompress(compressed_data: &[u8]) -> Option<Vec<u8>> {
///     let mut decoder = GzDecoder::new(compressed_data);
///     let mut decompressed = Vec::new();
///     if decoder.read_to_end(&mut decompressed).is_ok() {
///         Some(decompressed)
///     } else {
///         None
///     }
/// }
///
/// fn compress(data: &[u8]) -> Vec<u8> {
///     let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
///     encoder
///         .write_all(data)
///         .expect("writing into a vec is infallible");
///     encoder.finish().expect("writing into a vec is infallible")
/// }
/// ```
///
/// This example is inspired by [a similar example from the official `libFuzzer`
/// docs](https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md#example-compression).
///
/// ## More Example Ideas
///
/// * A PNG custom mutator that decodes a PNG, mutates the image, and then
/// re-encodes the mutated image as a new PNG.
///
/// * A [`serde`](https://serde.rs/) custom mutator that deserializes your
///   structure, mutates it, and then reserializes it.
///
/// * A Wasm binary custom mutator that inserts, replaces, and removes a
///   bytecode instruction in a function's body.
///
/// * An HTTP request custom mutator that inserts, replaces, and removes a
///   header from an HTTP request.
#[macro_export]
macro_rules! fuzz_mutator {
    (
        |
        $data:ident : &mut [u8] ,
        $size:ident : usize ,
        $max_size:ident : usize ,
        $seed:ident : u32 $(,)*
        |
        $body:block
    ) => {
        /// Auto-generated function.
        #[export_name = "LLVMFuzzerCustomMutator"]
        pub fn rust_fuzzer_custom_mutator(
            $data: *mut u8,
            $size: usize,
            $max_size: usize,
            $seed: std::os::raw::c_uint,
        ) -> usize {
            // Depending on if we are growing or shrinking the test case, `size`
            // might be larger or smaller than `max_size`. The `data`'s capacity
            // is the maximum of the two.
            let len = std::cmp::max($max_size, $size);
            let $data: &mut [u8] = unsafe { std::slice::from_raw_parts_mut($data, len) };

            // `unsigned int` is generally a `u32`, but not on all targets. Do
            // an infallible (and potentially lossy, but that's okay because it
            // preserves determinism) conversion.
            let $seed = $seed as u32;

            // Truncate the new size if it is larger than the max.
            let new_size = { $body };
            std::cmp::min(new_size, $max_size)
        }
    };
}

/// The default `libFuzzer` mutator.
///
/// You generally don't have to use this at all unless you're defining a
/// custom mutator with [the `fuzz_mutator!` macro][crate::fuzz_mutator].
///
/// Mutates `data[..size]` in place such that the mutated data is no larger than
/// `max_size` and returns the new size of the mutated data.
///
/// To only allow shrinking mutations, make `max_size < size`.
///
/// To additionally allow mutations that grow the size of the data, make
/// `max_size > size`.
///
/// Both `size` and `max_size` must be less than or equal to `data.len()`.
///
/// # Example
///
/// ```no_run
/// // Create some data in a buffer.
/// let mut data = vec![0; 128];
/// data[..b"hello".len()].copy_from_slice(b"hello");
///
/// // Ask `libFuzzer` to mutate the data. By setting `max_size` to our buffer's
/// // full length, we are allowing `libFuzzer` to perform mutations that grow
/// // the size of the data, such as insertions.
/// let size = b"hello".len();
/// let max_size = data.len();
/// let new_size = libfuzzer_sys::fuzzer_mutate(&mut data, size, max_size);
///
/// // Get the mutated data out of the buffer.
/// let mutated_data = &data[..new_size];
/// ```
pub fn fuzzer_mutate(data: &mut [u8], size: usize, max_size: usize) -> usize {
    assert!(size <= data.len());
    assert!(max_size <= data.len());
    let new_size = unsafe { LLVMFuzzerMutate(data.as_mut_ptr(), size, max_size) };
    assert!(new_size <= data.len());
    new_size
}
