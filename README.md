# Oj fuzzing harness

libFuzzer + ASAN harness for [ohler55/oj](https://github.com/ohler55/oj), with Ruby
embedded in-process. Built for the findings reported in
[issue #1059](https://github.com/ohler55/oj/issues/1059).

## Why one harness with many targets

Oj implements the same grammar several times over: `parse.c` (String),
`sparse.c` (IO/streaming), `usual.c` + `safe.c` + `saj2.c` (the `Oj::Parser`
family), `saj.c` (legacy SAJ) and `fast.c` (`Oj::Doc`). Several of the reported
bugs existed in one implementation while the sibling had the correct guard:

* `saj.c` `read_hash` called `read_quoted_value` without checking for a quote;
  `fast.c` does exactly that check.
* `parse.c` and `sparse.c` narrowed the key length to `uint16_t`; `usual.c`
  already had the 32000-byte guard from the CVE-2026-54899 fix.
* `object.c` `str_to_value` guarded a circular-reference id with `0 > i`; the
  two sibling call sites use `0 < i`.

So byte 0 of each input selects an entry point and the rest is the document.
Fuzzing one parser finds bugs in one parser.

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
ruby gen_corpus.rb          # writes the structural seeds
OJ_SHIM="$PWD/shim" OJ_LIB="$PWD/oj/lib" OJ_PRELUDE="$PWD/prelude.rb" \
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:allocator_may_return_null=1 \
./ojfuzz corpus -dict=json.dict -max_len=262144 -use_value_profile=1 \
         -artifact_prefix=artifacts/ -jobs=4 -workers=4
```

Reproduce a single artifact:

```bash
OJ_SHIM="$PWD/shim" OJ_LIB="$PWD/oj/lib" ./ojfuzz artifacts/crash-<hash>
```

## Gotchas that cost real time

* **`oj.so` must be built with `-fsanitize=fuzzer-no-link`.** Without it the
  fuzzer has no coverage feedback, reports `cov: 6`, and runs blind. A blind run
  of 6.5M execs found nothing; the instrumented run found the same bug in
  seconds. Always sanity-check that `cov:` is in the thousands.
* **ASAN and Ruby threads are incompatible** — `failed to deallocate ... error
  22`, from Ruby's mmap'd fiber pool, which ASAN's allocator does not own. Keep
  the harness single-threaded. Concurrency testing needs a non-ASAN build.
* **Leaks need their own run.** `detect_leaks=1` found the `sparse.c` escaped-key
  leak. Ruby leaks plenty at exit, so attribute by stack frame rather than by
  total bytes.
* **Do not point two campaigns at the same directory.** libFuzzer writes
  `fuzz-N.log` per job and the second campaign silently overwrites the first,
  corrupting the exec counts.
* **Dedup against `develop` and open topic branches, not `master`.** Of ten
  findings, six turned out to be already fixed or in flight, including one
  sitting in an unmerged branch (`fix-doc-path-limit`).

## Corpus

`gen_corpus.rb` emits seeds around the internal limits, which is where the bugs
cluster:

* key lengths at 29/30/31/32 (`karray` inline limit), 32000 (`usual.c` guard),
  65535/65536/65541 (the old `uint16_t klen` wrap)
* nesting at 63/64/65 and 128/129 (`STACK_INC` is 64; the first growth copies
  out of the embedded `base`, so only later growths can dangle), and 1023/1024
  (`parser.c` `stack[1024]`)
* object-mode directives `^o ^c ^i ^r ^u ^t ^m` and the `~` attribute prefix
* truncations where a key or value is expected but input ends
* exponents at 4932/32768/327683 and surrogate escapes

## Targets

The target table lives in `prelude.rb`, not in `harness.c`, so adding an entry
point is an edit rather than a rebuild. 69 targets covering the parsers, the
`Oj::Parser` family, `Oj::Doc`, the writers, mimic_JSON, and the rails, custom
and compat dump paths.

Pick targets against `-print_coverage=1`, not intuition. The first table had 26
entries and reached 289/702 `ext/oj` functions; `rails.c` and `mimic_json.c`
were at zero because nothing ever called `Oj.mimic_JSON` or the Rails encoder.
Adding targets for the uncovered names took it to 415/703, 59.0%.

Two things that silently cost coverage:

* `Oj.mimic_JSON` switches `:indent` process-wide to JSON's String semantics,
  so `indent: 2` raises `TypeError` afterwards. Pass a String.
* Arbitrary fuzz bytes cannot build a `Regexp` or a `Symbol`. Scrub to UTF-8
  before constructing sample objects, or every dump target using them raises
  before Oj is reached and the whole subsystem stays dark.

## Status

Findings 1-7 from [issue #1059](https://github.com/ohler55/oj/issues/1059) are
merged (#1062-#1067), as is the `oj_set_error_at` stack-buffer-overflow write
found afterwards (#1071).

Current finding, reported and not yet fixed: `Oj::Parser#file` never calls
`validate_document_end()`, so a truncated document is never diagnosed and
`p->result(p)` returns an uninitialized `VALUE`.

```ruby
File.binwrite('/tmp/t.json', '{"a":')
Oj::Parser.usual.file('/tmp/t.json')   # => 286326800, then SEGV
Oj::Parser.usual.parse('{"a":')        # => EncodingError, correct
```
