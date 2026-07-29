// libFuzzer harness for Oj, with Ruby embedded in-process.
//
// Byte 0 of each input selects a parser/serializer entry point; the remaining
// bytes are the document. Covering every entry point in one harness matters:
// the parsers are separate implementations of the same grammar, and several
// bugs existed in one while the sibling had the guard (saj.c read_hash vs
// fast.c, parse.c klen vs usual.c).
//
// The target table lives in prelude.rb, pointed at by OJ_PRELUDE, so adding an
// entry point is an edit rather than a rebuild.
//
// Build:
//   cd oj/ext/oj && ruby extconf.rb
//   make CC=clang LDSHARED="clang -shared" \
//        CFLAGS="-fPIC -fsanitize=fuzzer-no-link,address -fno-omit-frame-pointer -g -O1 -std=gnu99" \
//        ldflags="-fsanitize=fuzzer-no-link,address"
//   mkdir -p shim/oj && ln -s $PWD/oj.so shim/oj/oj.so
//   clang -fsanitize=fuzzer,address -g -O1 $(pkg-config --cflags ruby-3.4) \
//         harness.c -o ojfuzz $(pkg-config --libs ruby-3.4) -rdynamic
//
// Run:
//   OJ_SHIM=$PWD/shim OJ_LIB=$PWD/oj/lib OJ_PRELUDE=$PWD/prelude.rb \
//   ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
//   ./ojfuzz corpus -dict=json.dict -max_len=262144 -use_value_profile=1 \
//            -artifact_prefix=artifacts/ -fork=14 -ignore_crashes=1
//
// Notes:
//   * ASAN and Ruby's threaded fiber pool are incompatible ("failed to
//     deallocate", error 22). Keep the harness single-threaded.
//   * detect_leaks=1 is useful on its own run: it found the sparse.c escaped
//     key leak. Ruby leaks at exit, so attribute by frame, not by total.
//   * Coverage only works if oj.so itself is built with fuzzer-no-link.
//     Without it the fuzzer runs blind and reports cov: ~6.

#include <ruby.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

static VALUE g_targets;
static int   g_n;
static int   g_ready;

struct args { const uint8_t *d; size_t n; int t; };

static VALUE do_call(VALUE a) {
    struct args *x = (struct args *)a;
    VALUE s = rb_str_new((const char *)x->d, (long)x->n);
    rb_funcall(rb_ary_entry(g_targets, x->t), rb_intern("call"), 1, s);
    return Qnil;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    ruby_sysinit(argc, argv);
    ruby_init_stack((VALUE *)argc);
    ruby_init();
    /* full option processing so RubyGems and default gems (bigdecimal) resolve */
    { char *r[] = {(char *)"ojfuzz", (char *)"-e", (char *)"", NULL}; ruby_options(3, r); }

    int st = 0;
    rb_eval_string_protect(
        "$LOAD_PATH.unshift(ENV.fetch('OJ_SHIM'), ENV.fetch('OJ_LIB'))\n"
        "load ENV.fetch('OJ_PRELUDE')\n", &st);
    if (st) {
        VALUE e = rb_errinfo();
        VALUE m = rb_funcall(e, rb_intern("message"), 0);
        fprintf(stderr, "ruby setup failed: %s\n", StringValueCStr(m));
        abort();
    }
    g_targets = rb_eval_string("TARGETS");
    rb_gc_register_address(&g_targets);
    g_n = (int)RARRAY_LEN(g_targets);
    fprintf(stderr, "ojfuzz: %d targets\n", g_n);
    g_ready = 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_ready || size < 2) return 0;

    struct args a = { data + 1, size - 1, data[0] % g_n };
    int st = 0;
    rb_protect(do_call, (VALUE)&a, &st);
    if (st) rb_set_errinfo(Qnil);   /* Ruby-level parse errors are expected */

    return 0;
}
