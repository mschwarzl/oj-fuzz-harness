# Stack-buffer-overflow WRITE in oj_set_error_at (ext/oj/parse.c).
#
# The guard reserves 3 bytes and the body then writes 8:
#
#   char msg[256];
#   char *end = msg + sizeof(msg) - 2;
#   if (p + 3 < end) {
#       *p++ = ' '; *p++ = '('; *p++ = 'a'; *p++ = 'f';
#       *p++ = 't'; *p++ = 'e'; *p++ = 'r'; *p++ = ' ';
#
# Reachable whenever a class name is long enough to push the formatted message
# into that window. Two distinct callers, because resolve_classpath is
# duplicated:
#
#   ^c / ^o  -> hat_cstr  -> oj_class_intern -> resolve_classpath (intern.c:238)
#   ^u       -> hat_value -> oj_name2struct  -> resolve_classpath (resolve.c:67)
#
# Lengths 224-227 overflow; 223 and 228 raise ArgumentError cleanly.
# Run under ASAN; without it the write lands in adjacent stack and is silent.

require "oj"
require "stringio"

(220..230).each do |n|
  %w[^c ^u].each do |hat|
    doc = hat == "^c" ? %({"^c":"#{"A" * n}"}) : %({"^u":["#{"A" * n}",1]})
    # Note the single bracket for ^u: [["a"],1] takes the anonymous-struct
    # path and never reaches oj_name2struct.
    [doc, StringIO.new(doc)].each do |src|
      kind = src.is_a?(String) ? "str" : "io "
      begin
        Oj.load(src, mode: :object)
        puts "n=#{n} #{hat} #{kind}: no error"
      rescue StandardError => e
        puts "n=#{n} #{hat} #{kind}: #{e.class}"
      end
    end
  end
end
