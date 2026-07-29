#!/usr/bin/env bash
# Launches a detached campaign. Corpus/artifacts/logs persist across reboots.
set -euo pipefail
BUILD="${OJFUZZ_BUILD:-/tmp/ojfuzz-build}"
C="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOURS="${1:-4}"; JOBS="${2:-4}"

[ -x "$BUILD/ojfuzz" ] || { echo "no build; run rebuild.sh first" >&2; exit 1; }
mkdir -p "$C/corpus" "$C/artifacts" "$C/logs"
# -fork=N, the mode upstream intends to replace -jobs/-workers with. Per the
# libFuzzer docs -ignore_crashes keeps fuzzing after a crash and still saves the
# reproducer, the same as -ignore_ooms does for OOMs. Run 2 nonetheless counted
# 244 crashes against an empty artifacts/ dir, which is still unexplained, so
# confirm a crash really lands in artifacts/ before trusting a long run.
# Per-run log dir: libFuzzer writes fuzz-N.log per job and two campaigns sharing
# a directory silently overwrite each other's exec counts.
# fd 1 goes to /dev/null: Oj's :debug parser and trace hooks printf() to stdout
# and libc buffering defeats any in-process redirect. libFuzzer itself writes
# progress and coverage to stderr, which is what campaign.log captures.
RUN="$C/logs/$(date +%Y%m%d-%H%M%S)"; mkdir -p "$RUN"

cd "$RUN"
# replace_intrin=0 is REQUIRED with Ruby 4.0. ASAN's memcpy interceptor runs on
# Ruby VM-stack memory it cannot describe and trips its own internal check:
#
#   AddressSanitizer: CHECK failed: asan_thread.cpp:370
#     "((ptr[0] == kCurrentStackFrameMagic)) != (0)"
#     #6  memcpy (asan interceptor)
#     #8  rb_yield_values2
#     #12 rb_hash_foreach
#
# Oj is not in that stack. It aborts the process with no ERROR line, so it looks
# exactly like a crash in whatever target happened to be running -- the site
# moves between runs and never minimises. Cost of the flag: OOB inside libc
# memcpy/memset is no longer caught. Oj's own instrumented loads and stores
# still are. The proper fix is an ASAN-instrumented Ruby.
OJ_SHIM="$BUILD/shim" OJ_LIB="$BUILD/oj/lib" OJ_PRELUDE="$C/../prelude.rb" \
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:allocator_may_return_null=1:dedup_token_length=3:replace_intrin=0 \
setsid nohup "$BUILD/ojfuzz" "$C/corpus" "$C/../corpus_seeds" \
  -dict="$C/../json.dict" -max_len=262144 -use_value_profile=1 -rss_limit_mb=4096 \
  -artifact_prefix="$C/artifacts/" -max_total_time=$((HOURS*3600)) \
  -fork="$JOBS" -ignore_crashes=1 -print_final_stats=1 \
  2> "$RUN/campaign.log" > /dev/null &
echo $! > "$C/campaign.pid"
echo "started pid $(cat "$C/campaign.pid") -> $RUN"
