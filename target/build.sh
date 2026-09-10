#!/usr/bin/env bash
set -eu

projectDir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$projectDir/build"
x86_64-w64-mingw32-g++ \
    -std=c++17 \
    -O2 \
    -Wall \
    -Wextra \
    -Werror \
    -static \
    "$projectDir/src/main.cpp" \
    -ladvapi32 \
    -o "$projectDir/build/ntiolib_target.exe"
