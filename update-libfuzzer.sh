#!/bin/bash -ex

# Usage:
#
#     $ ./update-libfuzzer.sh

set -ex

# The LLVM commit from which we are vendoring libfuzzer. This must be a commit
# hash from https://github.com/llvm/llvm-project
COMMIT=a47b42eb9f9b302167b4fc413e6c92798d65dd0b

cd "$(dirname $0)"
project_dir="$(pwd)"

tmp_dir="$(mktemp -d)"
cd "$tmp_dir"

git init
git remote add llvm https://github.com/llvm/llvm-project.git
git sparse-checkout set compiler-rt/lib/fuzzer

git fetch --depth 1 llvm "$COMMIT" --filter=blob:none
git checkout "$COMMIT"

rm -rf "$project_dir/libfuzzer/"
mv "$tmp_dir/compiler-rt/lib/fuzzer/" "$project_dir/libfuzzer/"
