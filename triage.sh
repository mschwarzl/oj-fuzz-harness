#!/usr/bin/env bash
# Groups campaign artifacts by (sanitizer, top oj frame) so a run that rediscovers
# one known bug 200 times collapses to one line. Anything whose signature is not
# in KNOWN below needs deduping against develop HEAD and the open PRs.
set -uo pipefail
BUILD="${OJFUZZ_BUILD:-/tmp/ojfuzz-build}"
C="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KNOWN="oj_set_error_at"

declare -A seen
for f in "$C"/artifacts/*; do
  [ -f "$f" ] || continue
  out=$(OJ_SHIM="$BUILD/shim" OJ_LIB="$BUILD/oj/lib" \
        ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:allocator_may_return_null=1 \
        timeout 120 "$BUILD/ojfuzz" "$f" 2>&1)
  kind=$(grep -m1 -oE "AddressSanitizer: [a-z-]+" <<<"$out" | awk '{print $2}')
  frame=$(grep -E "^    #[0-9]+ 0x" <<<"$out" \
          | grep -oE "in [a-z_0-9]+ [^ ]*ext/oj/[a-z_0-9]+\.[ch]:[0-9]+" \
          | head -1 | sed 's|.*in \([a-z_0-9]*\) .*/\([a-z_0-9.]*:[0-9]*\)|\1 (\2)|')
  [ -z "$kind" ] && kind="none"
  [ -z "$frame" ] && frame="(no oj frame)"
  key="$kind|$frame"
  seen[$key]=$(( ${seen[$key]:-0} + 1 ))
  echo "${key}|$(basename "$f")" >> "$C/triage.raw"
done

echo "=== signatures ==="
for k in "${!seen[@]}"; do
  mark=""; grep -q "$KNOWN" <<<"$k" && mark="  [known: issue #1059 follow-up]"
  printf "%4d  %s%s\n" "${seen[$k]}" "$k" "$mark"
done | sort -rn
