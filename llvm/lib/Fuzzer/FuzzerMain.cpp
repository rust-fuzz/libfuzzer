//===- FuzzerMain.cpp - main() function and flags -------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// main() and flags.
//===----------------------------------------------------------------------===//

#include "FuzzerDefs.h"

extern "C" {
// This function should be defined by the user.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

// This function should be defined by the user.
void LLVMFuzzerSetup(void);

// This function should be defined by the user.
void LLVMFuzzerTeardown(void);
}  // extern "C"

int main(int argc, char **argv) {

  LLVMFuzzerSetup();
  auto res = fuzzer::FuzzerDriver(&argc, &argv, LLVMFuzzerTestOneInput);
  LLVMFuzzerTeardown();

  return res;
}
