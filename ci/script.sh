#!/usr/bin/env bash

set -eux
cd $(dirname $0)/..

export CARGO_TARGET_DIR=$(pwd)/target

cargo test --doc --features fuzz_macro

pushd ./example
cargo fuzz build
cargo fuzz build  --dev
(! cargo fuzz run bananas -- -runs=100000)
(! cargo fuzz run bananas-main -- -runs=100000)
rm -rf fuzz/artifacts/segfault-main
(! cargo fuzz run -s none segfault-main -- -runs=1000 -handle_abrt=0)
ls fuzz/artifacts/segfault-main/crash-*
popd

pushd ./example_arbitrary
cargo fuzz build
cargo fuzz build  --dev
(! cargo fuzz run rgb -- -runs=10000000)
(! cargo fuzz run rgb-main -- -runs=10000000)
RUST_LIBFUZZER_DEBUG_PATH=$(pwd)/debug_output \
    cargo fuzz run rgb \
    $(ls ./fuzz/artifacts/rgb/crash-* | head -n 1)
cat $(pwd)/debug_output
grep -q Rgb $(pwd)/debug_output
RUST_LIBFUZZER_DEBUG_PATH=$(pwd)/debug_output2 \
    cargo fuzz run rgb-main \
    $(ls ./fuzz/artifacts/rgb-main/crash-* | head -n 1)
cat $(pwd)/debug_output2
grep -q Rgb $(pwd)/debug_output2
popd

pushd ./example_mutator
cargo fuzz build
cargo fuzz build  --dev
(! cargo fuzz run boom -- -runs=10000000)
popd

pushd ./example_crossover
cargo fuzz build
cargo fuzz build  --dev
(! cargo fuzz run --release boom -- -runs=10000000)
popd

pushd ./example_init
cargo fuzz build
cargo fuzz build  --dev
(! cargo fuzz run --release bigbang -- -runs=10000000)
(! cargo fuzz run --release bigbang-main -- -runs=10000000)
popd

echo "All good!"
