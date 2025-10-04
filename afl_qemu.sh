#!/bin/bash

INPUT_DIR="input"
OUTPUT_DIR="output"
WRAPPER_SCRIPT="run_qemu"
WRAPPER_SOURCE="run_qemu.c"

cat <<EOF > $WRAPPER_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_elf>\n", argv[0]);
        return 1;
    }
    char *args[] = {
        "~/arm_sim_fuzz/qemu/build/qemu-system-aarch64",
        "-machine", "raspi4b",
        "-display", "none", " -serial","stdio",
        "-kernel", argv[1],
        NULL
    };
     execvp(args[0], args);

    return 1;
}
EOF

gcc  -o $WRAPPER_SCRIPT $WRAPPER_SOURCE
export AFL_SKIP_BIN_CHECK=1
export AFL_SKIP_CPUFREQ=1
export AFL_CUSTOM_MUTATOR_LIBRARY="~/AFLplusplus/custom_mutators/aflpp/aflpp-mutator.so"
export AFL_CUSTOM_MUTATOR_ONLY=1
afl-fuzz  -P exploit -i $INPUT_DIR -o $OUTPUT_DIR -- ./$WRAPPER_SCRIPT @@ 
