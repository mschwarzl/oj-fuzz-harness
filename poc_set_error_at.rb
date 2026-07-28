$LOAD_PATH.unshift File.expand_path("shim", __dir__)
$LOAD_PATH.unshift File.expand_path("oj/lib", __dir__)
require "oj"; require "stringio"
n = Integer(ARGV[0])
doc = %({"^u":["#{"A" * n}",1]})
begin
  Oj.load(StringIO.new(doc), mode: :object)
  puts "  ok"
rescue => e
  puts "  raise:#{e.class.name.split('::').last}"
end
