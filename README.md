# Oj fuzzing harness

libFuzzer + ASAN harness for [ohler55/oj](https://github.com/ohler55/oj), with Ruby
embedded in-process. Built for the findings reported in
[issue #1059](https://github.com/ohler55/oj/issues/1059).

**114 targets, 83.6% of `ext/oj` functions covered, ~74M executions.**

## Why one harness with many targets

Oj implements the same grammar several times over: `parse.c` (String),
`sparse.c` (IO/streaming), `usual.c` + `safe.c` + `saj2.c` (the `Oj::Parser`
family), `saj.c` (legacy SAJ) and `fast.c` (`Oj::Doc`). Several of the reported
bugs existed in one implementation while the sibling had the correct guard:

* `saj.c` `read_hash` called `read_quoted_value` without checking for a quote;
  `fast.c` does exactly that check.
* `parse.c` and `sparse.c` narrowed the key length to `uint16_t`; `usual.c`
  already had the 32000-byte guard.
* `parser_parse()` calls `validate_document_end()`; `parser_file()` does not.

So byte 0 of each input selects an entry point and the rest is the document.
Fuzzing one parser finds bugs in one parser.

The target table lives in `prelude.rb`, not in `harness.c`, so adding an entry
point is an edit rather than a rebuild.

## Build

```bash
curl -sSL https://codeload.github.com/ohler55/oj/tar.gz/develop | tar xz && mv oj-develop oj
cd oj/ext/oj
ruby extconf.rb
make -j8 CC=clang LDSHARED="clang -shared" \
     CFLAGS="-fPIC -fsanitize=fuzzer-no-link,address -fno-omit-frame-pointer -g -O1 -std=gnu99" \
     ldflags="-fsanitize=fuzzer-no-link,address"
cd ../../..

mkdir -p shim/oj && ln -sf "$PWD/oj/ext/oj/oj.so" shim/oj/oj.so

clang -fsanitize=fuzzer,address -fno-omit-frame-pointer -g -O1 \
      $(pkg-config --cflags ruby-3.4 | sed 's/-flto=auto//') \
      harness.c -o ojfuzz \
      $(pkg-config --libs ruby-3.4 | sed 's/-flto=auto//;s/-Wl,--compress-debug-sections=none//') \
      -rdynamic
```

Adjust `ruby-3.4` to your `pkg-config` name.

## Run

```bash
mkdir -p corpus artifacts
ruby gen_corpus.rb

OJ_SHIM="$PWD/shim" OJ_LIB="$PWD/oj/lib" OJ_PRELUDE="$PWD/prelude.rb" OJ_PROFILE=plain \
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:allocator_may_return_null=1:replace_intrin=0 \
./ojfuzz corpus -dict=json.dict -max_len=262144 -use_value_profile=1 \
         -artifact_prefix=artifacts/ -fork=8 -ignore_crashes=1 \
         2> campaign.log > /dev/null
```

Run it once with `OJ_PROFILE=plain` and once with `OJ_PROFILE=mimic`, and union
the coverage — see below for why.

`run.sh` and `rebuild.sh` do the above; `triage.sh` groups artifacts by stack
signature.

## Two profiles, and why they are mandatory

`Oj.optimize_rails` installs a global encoder that diverts custom-mode dumps:

```ruby
# plain
Oj.dump(Time.at(0), mode: :custom)  # => {"^o":"Time","time":0.000000000}
# after Oj.optimize_rails
Oj.dump(Time.at(0), mode: :custom)  # => "1970-01-01T01:00:00.000+01:00"
```

So `custom.c`'s `time_dump` / `date_dump` / `*_load` family and
`rails.c` + `mimic_json.c` **cannot be covered by the same process**.
`OJ_PROFILE=mimic` turns on `Oj.mimic_JSON`, `Oj::Rails.mimic_JSON` and
`Oj.optimize_rails`; anything else leaves them off.

| profile | ext/oj functions |
|---|---|
| plain | 558 / 703 |
| mimic | 573 / 703 |
| **union** | **588 / 703 = 83.6%** |

## Gotchas that cost real time

Roughly in order of how much time each one wasted.

* **`replace_intrin=0` is required on Ruby 4.0.** ASAN's `memcpy` interceptor
  runs on Ruby VM-stack memory it cannot describe and fails its own check:

  ```
  AddressSanitizer: CHECK failed: asan_thread.cpp:370
    "((ptr[0] == kCurrentStackFrameMagic)) != (0)"
    #6  memcpy (asan interceptor)
    #8  rb_yield_values2
    #12 rb_hash_foreach
  ```

  Oj is not in that stack. It aborts with no `ERROR:` line, so it looks exactly
  like a crash in whichever target was running: the site moves between runs,
  inputs do not reproduce in isolation, and it never minimises. Cost of the
  flag: OOB inside libc `memcpy`/`memset` is no longer caught.

* **There is a second ASAN/Ruby problem with no flag for it.**
  `attempting to call malloc_usable_size() for pointer which is not owned` —
  Ruby mmaps its object heap and ASAN's allocator does not own it. It produced
  ~360 phantom "crashes" in one 6-hour run *with* `replace_intrin=0` set. The
  only real fix is building Ruby itself with ASAN.

* **The crash counters lie.** Between the above, `-fork` accounting, and
  `-rss_limit_mb` attributing accumulated interpreter RSS to whatever input was
  in flight, all three of libFuzzer's signals produce false positives here.
  **Triage rule: an artifact is a finding only if it reproduces standalone.**
  In the last run, 2 crash + 72 oom artifacts were all noise.

* **`oj.so` must be built with `-fsanitize=fuzzer-no-link`.** Without it there
  is no coverage feedback, `cov:` reads ~6, and the fuzzer runs blind. A blind
  run of 6.5M execs found nothing; the instrumented run found the same bug in
  seconds.

* **`saj2.c` picks its callbacks by arity, not by which methods exist.**
  Arity 1 on `hash_start`/`hash_end`/`array_start`/`array_end` and arity 2 on
  `add_value` select the plain variants; anything else selects the `_loc` ones.
  A handler using `(*)` splats is arity -1, so half the file is unreachable no
  matter how long you run.

* **`Oj.mimic_JSON` changes `:indent` process-wide** to JSON's String
  semantics. `indent: 2` raises `TypeError` afterwards.

* **Arbitrary fuzz bytes cannot build a `Regexp` or a `Symbol`.** Scrub to
  UTF-8 first, or every dump target using them raises before reaching Oj and
  the subsystem stays dark while looking exercised.

* **Every `Oj::Rails` method takes a class argument** —
  `optimize(Hash)`, `optimized?(Hash)`, `Encoder#optimize(*classes)`. Called
  without one they raise cleanly, so the target runs and covers nothing.

* **`Oj::Parser#load` takes an IO**, not a String; `#parse` is the String entry
  point.

* **Dump sample objects one at a time.** ActiveSupport 8.1 patches
  `DateTime#as_json` to call a `super` that does not exist on Ruby 4.0 once
  `optimize_rails` is on; dumping an array aborts on the first bad element and
  costs coverage for all the others.

* **Do not point two campaigns at the same directory.** libFuzzer writes
  `fuzz-N.log` per job and the second campaign silently overwrites the first.

* **Dedup against `develop` and the open PRs, not `master`.** Of ten initial
  findings, six were already fixed or in flight.

## Coverage

Pick targets against `-print_coverage=1`, not intuition. The first table had 26
entries and reached 289/702 functions, with `rails.c` and `mimic_json.c` at
**zero** because nothing ever called `Oj.mimic_JSON` or the Rails encoder.

| | 26 targets | 114 targets, both profiles |
|---|---|---|
| ext/oj functions | 289 / 702 (41.2%) | **588 / 703 (83.6%)** |
| edges | 1790 | 5020 |

Known-unreachable, which caps the ceiling near 95%:

* ~25 init-once functions (`Init_oj`, `oj_hash_init`, `oj_parser_init`, …). They
  run inside `LLVMFuzzerInitialize`, before libFuzzer records observed PCs, so
  they can never appear in `-print_coverage`.
* `trace.c`, 5 functions — **`oj_trace` has zero call sites in the codebase.**
  The `trace:` option does nothing.
* SIMD dispatch and debug printers.

## Corpus

`gen_corpus.rb` emits seeds around the internal limits, which is where the bugs
cluster: key lengths at the `karray` inline limit and the old `uint16_t` wrap,
nesting at `STACK_INC` boundaries, the object-mode directives `^o ^c ^i ^r ^u
^t ^m`, truncations where a key or value is expected, and exponents at 4932 /
32768 / 327683.

## Findings

Reported via [issue #1059](https://github.com/ohler55/oj/issues/1059).

Fixed and merged:

| | |
|---|---|
| use-after-free of a key when the value stack grows | #1062 |
| over-read when a document ends where a key belongs | #1063 |
| circular reference id used unchecked (x2) | #1064 |
| a `max_*` limit of exactly 4 ignored | #1065 |
| exponent bound checked after narrowing | #1066 |
| escaped hash key never freed | #1067 |
| **stack-buffer-overflow write in `oj_set_error_at`** | #1071 |

Open:

* **`Oj::Parser#file` never calls `validate_document_end()`**, so a truncated
  document is never diagnosed and `p->result(p)` returns an uninitialized
  `VALUE` — an Integer that is not in the document, then SEGV.
* **`Oj::Doc` SEGV on a top-level malformed number.** `-.` is enough, at two
  bytes; the same token nested raises `Oj::ParseError` correctly. See
  `crashes/doc_each_value_crashers.txt`.
* **`usual.c` GC-marking gap.** `mark()` covers only `vhead..vtail` while
  `start()` rewinds `vtail`, so an object can stay reachable through
  `result()` after the GC stops protecting it.
