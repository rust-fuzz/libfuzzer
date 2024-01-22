# A Custom Crossover Example

## Overview

This example is a reimplementation of [Erik Rigtorp's floating point summation fuzzing example][1]
in the Rust bindings for LibFuzzer, provided by this crate.  In this particular example, Erik uses
both a custom mutator, and a custom crossover function, which provides a well-documented, complex
code example.

## Implementation

This is mostly a one-to-one rewrite of the C++ code in the blog post, with the big difference
being the method of converting the raw bytes that is exposed to the custom functions, into the
decoded double-precision floating-point values. Where in C++ we can simply do:

```c++
uint8_t *Data = ...;
size_t Size = ...;
double *begin = (double *)Data;
double *end = (double *)Data + Size / sizeof(double);
```

In Rust, however, the task seems a bit more complex due to strictness on alignment:

* [Rust, how to slice into a byte array as if it were a float array? - Stack Overflow][2]
* [Re-interpret slice of bytes (e.g. [u8]) as slice of [f32] - help - The Rust Programming Language Forum][3]
* [How to transmute a u8 buffer to struct in Rust? - Stack Overflow][4]

So the casting of `Data` in the blog post's C++ are now `slice::align_to{_mut}` calls

[1]: https://rigtorp.se/fuzzing-floating-point-code/
[2]: https://stackoverflow.com/a/73174764
[3]: https://users.rust-lang.org/t/re-interpret-slice-of-bytes-e-g-u8-as-slice-of-f32/34551
[4]: https://stackoverflow.com/a/59292352
