Barebones wrapper around libFuzzer runtime library.

The CPP parts are extracted from llvm git repository with `git filter-branch`.

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
extern crate fuzzer_sys;

#[export_name="LLVMFuzzerTestOneInput"]
pub extern fn go(data: *const u8, size: isize) -> i32 {
    // fuzzed code goes here
    0
}

$ cargo rustc -- -C passes='sancov' -C llvm-args='-sanitizer-coverage-level=3' -Z sanitizer=address -Cpanic=abort
$ ./target/debug/fuzzed # runs fuzzing
```

Nice wrappers incoming soon
