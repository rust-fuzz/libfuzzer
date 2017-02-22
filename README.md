Barebones wrapper around libFuzzer runtime library.

The CPP parts are extracted from llvm git repository with `git filter-branch`.

libFuzzer relies on LLVM sanitizer support. The Rust compiler has built-in support for LLVM sanitizer support, for now, it's limited to Linux. As a result, libfuzzer-sys only works on Linux.

# How to use

Use [cargo-fuzz].

[cargo-fuzz]: https://github.com/rust-fuzz/cargo-fuzz

This crate can also be used manually as following:

First create a new cargo project:

```
$ cargo new --bin fuzzed
$ cd fuzzed
```

Then add a dependency on the fuzzer-sys crate and your own crate:

```toml
[dependencies]
fuzzer-sys = { path = "../libfuzzer-sys" } # or something, will eventually publish to crates.io
your_crate = "*" # or something
```

and change the `src/main.rs` to fuzz your code:

```rust
#![no_main]

#[macro_use]
extern crate fuzzer_sys;
extern crate your_crate;

fuzz_target!(|data| {
    // code to fuzz goes here
});
```

Finally, run the following commands:

```
$ cargo rustc -- -C passes='sancov' -C llvm-args='-sanitizer-coverage-level=3' -Z sanitizer=address -Cpanic=abort
$ ./target/debug/fuzzed # runs fuzzing
```
