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
