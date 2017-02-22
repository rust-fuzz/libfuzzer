Barebones wrapper around libFuzzer runtime library.

The CPP parts are extracted from llvm git repository with `git filter-branch`.

libFuzzer relies on LLVM sanitizer support. The Rust compiler has built-in support for LLVM sanitizer support, for now, it's limited to Linux. As a result, libfuzzer-sys only works on Linux.

# How to use

“Manual” usage of this library looks like this:

```
$ cargo new --bin fuzzed
$ cd fuzzed

$ tail Cargo.toml -n2 # add libfuzzer-sys dependency
[dependencies]
fuzzer-sys = { path = "../libfuzzer-sys" } # or something

$ cat src/main.rs
#![no_main]

#[macro_use]
extern crate fuzzer_sys;

fuzz_target!(|data| {
    // code to fuzz goes here
});

$ cargo rustc -- -C passes='sancov' -C llvm-args='-sanitizer-coverage-level=3' -Z sanitizer=address -Cpanic=abort
$ ./target/debug/fuzzed # runs fuzzing
```

For a nice wrapper see [cargo-fuzz].

[cargo-fuzz]: https://github.com/rust-fuzz/cargo-fuzz
