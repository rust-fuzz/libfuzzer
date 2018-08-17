#!/bin/bash -ex

project_dir="$(pwd)"
tmp_dir="$(mktemp -d)"

git clone https://github.com/llvm-mirror/compiler-rt.git "$tmp_dir"
cd "$tmp_dir"
git checkout "$1"
rm -rf "$project_dir/libfuzzer/"
mv "$tmp_dir/lib/fuzzer/" "$project_dir/libfuzzer/"
