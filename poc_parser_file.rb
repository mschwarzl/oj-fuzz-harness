# Oj::Parser#file returns an uninitialized VALUE on a truncated document.
#
# parser_parse() diagnoses an incomplete document; parser_file() does not:
#
#   static VALUE parser_parse(VALUE self, VALUE json) {
#       parse(p, ptr, (size_t)RSTRING_LEN(json), false);
#       validate_document_end(p);          <-- raises
#       return p->result(p);
#   }
#   static VALUE parser_file(VALUE self, VALUE filename) {
#       while (true) { ... parse(p, buf, rsize, true); }
#                                          <-- no validate_document_end()
#       return p->result(p);
#   }
#
# So p->result(p) hands back whatever the value stack holds. Observed: an
# Integer that is not in the document, then a SEGV on the next use.
#
# Not fixed by PR #1072, which addresses read() returning -1 (a different
# mechanism in the same function). Confirmed on develop d0d84b8b and on
# 9e99aaaf, #1072's head.
#
# Fix: call validate_document_end(p) after the read loop.

require "oj"

# The process usually dies partway through, so flush as we go.
$stdout.sync = true

path = "/tmp/oj_parser_file_poc.json"

DOCS = ['{"a":', '[', '{', '{"a":1', '[1,', '"abc'].freeze

DOCS.each do |doc|
  File.binwrite(path, doc)

  parsed = begin
    Oj::Parser.usual.parse(doc).inspect
  rescue StandardError => e
    e.class.to_s
  end

  from_file = begin
    Oj::Parser.usual.file(path).inspect
  rescue StandardError => e
    e.class.to_s
  end

  puts format("%-8s  parse => %-22s  file => %s", doc.inspect, parsed, from_file)
end

# parse   => EncodingError for every one of them
# file    => a stale Integer, or a SEGV that takes the process down
