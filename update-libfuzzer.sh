#!/bin/bash -ex

# Usage:
#
#     ./update-libfuzzer $commit_hash
#
# Where `$commit_hash` is a commit hash from
# https://github.com/llvm-mirror/llvm-project

set -ex

cd "$(dirname $0)"
project_dir="$(pwd)"

tmp_dir="$(mktemp -d)"

git clone https://github.com/llvm/llvm-project.git "$tmp_dir"
cd "$tmp_dir"
git checkout "$1"
rm -rf "$project_dir/libfuzzer/"
mv "$tmp_dir/compiler-rt/lib/fuzzer/" "$project_dir/libfuzzer/"
