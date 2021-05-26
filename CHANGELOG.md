## Unreleased

Released YYYY-MM-DD.

### Added

* TODO (or remove section if none)

### Changed

* TODO (or remove section if none)

### Deprecated

* TODO (or remove section if none)

### Removed

* TODO (or remove section if none)

### Fixed

* TODO (or remove section if none)

### Security

* TODO (or remove section if none)

--------------------------------------------------------------------------------

## 0.4.2

Released 2020-05-26.

### Changed

* Improved performance of checking for whether `cargo fuzz` is requesting the
  `std::fmt::Debug` output of an input or not. This is always false during
  regular fuzzing, so making this check faster should give slightly better
  fuzzing throughput.

--------------------------------------------------------------------------------

## 0.4.1

Released 2020-05-13.

### Added

* Added support for defining custom mutators. See [the documentation for the
  `fuzz_mutator!`
  macro](https://docs.rs/libfuzzer-sys/0.4.1/libfuzzer_sys/macro.fuzz_mutator.html)
  for details.

### Changed

* Upgraded libfuzzer to llvm/llvm-project's 70cbc6d.

--------------------------------------------------------------------------------

## 0.4.0

Released 2021-02-24.

### Changed

* The public `arbitrary` dependency was updated to version 1.0.

--------------------------------------------------------------------------------

## 0.3.5

Released 2020-11-18.

### Changed

* [Upgrade libfuzzer to 7bf89c2](https://github.com/rust-fuzz/libfuzzer/pull/68)

--------------------------------------------------------------------------------

## 0.3.4

Released 2020-08-22.

### Changed

* Updated `arbitrary` dependency to 0.4.6

--------------------------------------------------------------------------------

## 0.3.3

Released 2020-07-27.

### Changed

* Upgraded libfuzzer to commit
  [4a4cafa](https://github.com/llvm/llvm-project/commit/4a4cafabc9067fced5890a245b03ef5897ad988b).

  Notably, this pulls in [the new Entropic engine for
  libFuzzer](https://mboehme.github.io/paper/FSE20.Entropy.pdf), which should
  boost fuzzing efficiency when enabled. You can enable Entropic by passing
  `-entropic=1` to your built fuzz targets (although, note that it is still
  labeled "experimental").

--------------------------------------------------------------------------------

## 0.3.2

Released 2020-03-18.

### Changed

* Upgraded the `arbitrary` dependency re-export to version 0.4.1.

--------------------------------------------------------------------------------

## 0.3.1

Released 2020-02-27.

### Changed

* Fixed a fuzzing performance issue where libfuzzer could unnecessarily spend
  time exploring all the ways that an `Arbitrary` implementation could fail to
  construct an instance of itself because the fuzzer provided too few bytes. See
  https://github.com/rust-fuzz/libfuzzer/issues/59 for details.

--------------------------------------------------------------------------------

## 0.3.0

Released 2019-01-22.

### Changed

* Now works with and re-exports `arbitrary` versions 0.4.x.

--------------------------------------------------------------------------------

## 0.2.1

Released 2019-01-16.

### Added

* Added support for the `CUSTOM_LIBFUZZER_STD_CXX=<lib>` environment variable
  during builds that already use a custom libFuzzer checkout with
  `CUSTOM_LIBFUZZER_PATH`. This allows you to explicitly choose to link LLVM or
  GNU C++ standard libraries.

--------------------------------------------------------------------------------

## 0.2.0

Released 2020-01-14.

### Changed

* Using `arbitrary` 0.3.x now. It is re-exported as `libfuzzer_sys::arbitrary`.

### Added

* You can enable support for `#[derive(Arbitrary)]` with the
  `"arbitrary-derive"` cargo feature. This is a synonym for the `arbitrary`
  crate's `"derive"` cargo feature.

--------------------------------------------------------------------------------

## 0.1.0
