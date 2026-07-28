#!/usr/bin/env ruby
# Generates the seed corpus for the Oj fuzzing harness.
#
# Seeds cluster around Oj's internal limits, because that is where the bugs are:
# buffer sizes, integer widths, and the depths at which a stack is reallocated.
# Byte 0 of each file selects the harness target, so every seed is emitted once
# per target.

require "fileutils"

OUT     = ARGV[0] || "corpus"
TARGETS = Integer(ARGV[1] || 26)   # must match TARGETS.size in harness.c

FileUtils.mkdir_p(OUT)

seeds = []

# plain shapes
seeds += ['{}', '[]', 'null', '1', '"s"', '{"a":1,"b":[1,2],"c":{"d":null}}']

# object-mode directives: circarray.c and object.c hat_* handling.
# 3 of the 7 reported bugs lived behind these.
seeds += ['{"a":"^r0"}', '{"a":"^r1"}', '{"^i":1,"a":1}', '{"^i":1000000,"a":1}',
          '{"^o":"Object","~a":1}', '{"^c":"String"}', '{"^u":[["a"],1]}',
          '{"^t":1}', '{"^m":"sym"}', '{"^#":[1,2]}']

# long class names reach resolve_classpath -> oj_set_error_at
[64, 200, 225, 226, 250, 1023, 1024, 2048].each do |n|
  seeds << %({"^u":[["#{'A' * n}"],1]})
  seeds << %({"^o":"#{'A' * n}"})
end

# key lengths: 30 is the karray inline limit, 32000 the usual.c guard,
# 65536 the old uint16_t klen wrap
[29, 30, 31, 32, 255, 4096, 31_999, 32_000, 32_768, 65_535, 65_536, 65_541].each do |n|
  seeds << %({"#{'k' * n}":1})
  seeds << %({"~#{'A' * n}":1})          # form_attr '~' branch
  seeds << %({"a":"#{'v' * n}"})         # long value rather than key
end

# nesting: STACK_INC is 64, and only growths after the first can dangle
# because the first copies out of the embedded base array
[63, 64, 65, 128, 129, 1023, 1024, 2048].each do |d|
  seeds << ('{"a":' * d) + "1" + ("}" * d)
  seeds << ("[" * d) + "1" + ("]" * d)
  seeds << ("[" * d)                     # unterminated
end

# truncations: input ends where a key or value is expected
seeds += ['[{"":[{', '{"a":', '["', '{"a":"\\', '["\\ud800', '//x', '{}/*', '[]//',
          '{"a":1}//x', '{"^u":[["a"']

# escapes and encoding
seeds += ['["\\u0041\\u0042"]', '["\\ud800\\udc00"]', '["\\n\\t\\\\"]',
          '{"\\u00e9":1}', '[' + '"\\ud800\\udc00",' * 100 + '"x"]']

# numbers: exponent narrowing in parser.c
seeds += ['[1e308]', '[1e4932]', '[1e32768]', '[1e327683]', '[-1e65536]',
          '[123456789012345678901234567890]', '[0.0000000000000000000001]']

# escaped hash keys: sparse.c leaks one allocation per key
seeds << "{" + (0...200).map { |i| %("\\u0041k#{i}":#{i}) }.join(",") + "}"

n = 0
TARGETS.times do |m|
  seeds.each do |s|
    File.binwrite(File.join(OUT, "s#{m}_#{n}"), [m].pack("C") + s)
    n += 1
  end
end

puts "wrote #{n} seeds to #{OUT}/"
