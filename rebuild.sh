#!/usr/bin/env bash
# Reconstructs the Oj fuzzing build from scratch. The build tree lives in tmpfs
# and does not survive a reboot; everything under campaign/ does.
set -euo pipefail
BUILD="${OJFUZZ_BUILD:-/tmp/ojfuzz-build}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REF="${1:-develop}"

mkdir -p "$BUILD" && cd "$BUILD"
rm -rf oj && curl -sSL "https://codeload.github.com/ohler55/oj/tar.gz/${REF}" | tar xz && mv "oj-${REF}" oj

cd oj/ext/oj && ruby extconf.rb >/dev/null
# -fsanitize=fuzzer-no-link on oj.so itself is mandatory; without it there is no
# coverage feedback and the fuzzer runs blind at cov:~6.
make -j"$(nproc)" CC=clang LDSHARED="clang -shared" \
  CFLAGS="-fPIC -fsanitize=fuzzer-no-link,address -fno-omit-frame-pointer -g -O1 -std=gnu99" \
  ldflags="-fsanitize=fuzzer-no-link,address" >/dev/null
cd "$BUILD"

mkdir -p shim/oj && ln -sf "$BUILD/oj/ext/oj/oj.so" shim/oj/oj.so
RB=$(pkg-config --list-all | awk '/^ruby-[0-9]/{print $1}' | sort -V | tail -1)
clang -fsanitize=fuzzer,address -fno-omit-frame-pointer -g -O1 \
  $(pkg-config --cflags "$RB" | sed 's/-flto=auto//') \
  "$HERE/harness.c" -o ojfuzz \
  $(pkg-config --libs "$RB" | sed 's/-flto=auto//;s/-Wl,--compress-debug-sections=none//') -rdynamic

cd "$BUILD/oj" && git init -q 2>/dev/null || true
echo "built $REF -> $BUILD/ojfuzz"
echo "run with OJ_PRELUDE=$HERE/prelude.rb"
