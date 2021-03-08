# The `libfuzzer-sys` Crate

Barebones wrapper around LLVM's libFuzzer runtime library.

The CPP parts are extracted from compiler-rt git repository with `git filter-branch`.

libFuzzer relies on LLVM sanitizer support. The Rust compiler has built-in support for LLVM sanitizer support, for now, it's limited to Linux. As a result, `libfuzzer-sys` only works on Linux.

## Usage

### Use `cargo fuzz`!

[The recommended way to use this crate with `cargo fuzz`!][cargo-fuzz].

[cargo-fuzz]: https://github.com/rust-fuzz/cargo-fuzz

### Manual Usage

This crate can also be used manually as following:

First create a new cargo project:

```
$ cargo new --bin fuzzed
$ cd fuzzed
```

Then add a dependency on the `fuzzer-sys` crate and your own crate:

```toml
[dependencies]
libfuzzer-sys = "0.4.0"
your_crate = { path = "../path/to/your/crate" }
```

Change the `fuzzed/src/main.rs` to fuzz your code:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // code to fuzz goes here
});
```

Build by running the following command:

```sh
$ cargo rustc -- \
    -C passes='sancov' \
    -C llvm-args='-sanitizer-coverage-level=3' \
    -C llvm-args='-sanitizer-coverage-inline-8bit-counters' \
    -Z sanitizer=address
```

And finally, run the fuzzer:

```sh
$ ./target/debug/fuzzed
```

## Updating libfuzzer from upstream

```
./update-libfuzzer.sh <github.com/llvm-mirror/llvm-project SHA1>
```

## License

All files in `libfuzzer` directory are licensed NCSA.

Everything else is dual-licensed Apache 2.0 and MIT.
