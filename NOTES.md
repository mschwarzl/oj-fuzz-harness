# State notes

## Reported and handled — issue #1059

All 7 reproduced by the maintainer on `develop`; PRs #1062-#1067
(#1062, #1063, #1064 merged). Maintainer corrections worth remembering:

* My suggested fix for finding 7 (`kalloc = 1`) was **wrong** — the key is freed
  with `OJ_R_FREE` (`xfree`) but allocated with plain `malloc`, so that would
  have created an allocator mismatch. Correct fix routes through `oj_strndup()`.
* Finding 1: only growths after the first can dangle; the first copies out of the
  `base` array embedded in `_valStack`, which lives in `_parseInfo` on the C
  stack and is never freed. Explains why ASAN reproduces at depth 129 while the
  glibc crash depth wanders with heap state.
* Finding 3: `objs[-1]` reads the malloc chunk header; 8224 with the in-use bit
  is 8225, odd, which Ruby reads as Fixnum 4112 — hence `{"a" => 4112}` looked
  harmless. A different allocator or layout puts an even word there and Ruby
  takes it as a pointer.
* Maintainer also found `test/test_parser*.rb` was never being run: the
  `Rake::TestTask` is commented out and `test_all`'s invoke resolves to the
  `test` directory as a synthesized file task.

## Found after those fixes -- reported: oj_set_error_at

**Stack-buffer-overflow WRITE in `oj_set_error_at` (`ext/oj/parse.c`).**
Found against `develop` *after* #1062-#1064 merged, by the rebuilt harness.

```
WRITE of size 1
  oj_set_error_at   parse.c:1112
  resolve_classpath resolve.c:67
  oj_name2struct    resolve.c:88
  hat_value         object.c:340     <- "^u" struct directive
  add_value         sparse.c:73
```

Cause: the guard reserves 3 bytes, the body writes 8.

```c
char msg[256];
char *end = msg + sizeof(msg) - 2;
...
if (p + 3 < end) {
    *p++ = ' '; *p++ = '('; *p++ = 'a'; *p++ = 'f';
    *p++ = 't'; *p++ = 'e'; *p++ = 'r'; *p++ = ' ';   /* 8 writes */
```

Reproducer (`poc_set_error_at.rb`), class-name lengths **224-227**:

```ruby
n = 226
Oj.load(StringIO.new(%({"^u":["#{"A" * n}",1]})), mode: :object)
```

Outside 224-227 it raises `ArgumentError` cleanly. Note the single bracket:
`[["a"],1]` takes the anonymous-struct path and does *not* reach
`oj_name2struct`.

**Two callers, because `resolve_classpath` is duplicated** (`intern.c:204` and
`resolve.c:33`). Reported the `resolve.c`/`^u` one first; the longer campaign
found `^c` -> `hat_cstr` -> `oj_class_intern` -> `resolve_classpath`
(`intern.c:238`), which needs no StringIO and no Struct and is the more
reachable path. Corrected in issue comment 5108857339. Fixing the call sites
rather than `oj_set_error_at` itself would leave one of them.

Reachable from any `Oj.load` in `:object` mode, String or IO, whenever a
`^u`/`^o`/`^c` class name is long enough to push the formatted message into that
window. Fix: reserve 8 rather than 3, or bound each write against `end`.
