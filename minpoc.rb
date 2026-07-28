$LOAD_PATH.unshift File.expand_path("shim", __dir__)
$LOAD_PATH.unshift File.expand_path("oj/lib", __dir__)
require "oj"; require "stringio"
# "class '%s' is not defined" = 23 chars + name. oj_set_error_at guards with
# p+3 < end but then writes 8 bytes, so a message length leaving p at
# msg+248..250 overflows msg[256].
n = Integer(ARGV[0])
name = "A" * n
doc = %({"^u":[["#{name}"],1]})
begin
  Oj.load(StringIO.new(doc), mode: :object)
  puts "  n=#{n} (msg len ~#{23+n}) ok"
rescue => e
  puts "  n=#{n} (msg len ~#{23+n}) raise:#{e.class.name.split('::').last}"
end
