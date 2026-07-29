# Target table for the Oj fuzzing harness.
#
# harness.c evals this file and then calls TARGETS[byte0 % TARGETS.size] with
# the rest of the input. Keeping the table here means adding a target is an
# edit, not a rebuild.
#
# Targets are chosen against the uncovered-function list from
# `-print_coverage=1`, not by guesswork. The large gaps were whole subsystems
# the first harness never entered at all: rails.c and mimic_json.c sat at zero
# covered functions, and custom.c, fast.c and string_writer.c were only
# reachable through the one or two entry points the old table used.

require "oj"
require "stringio"
require "date"
require "bigdecimal"
require "time"

# ostruct is a bundled gem that Oj has a branch to stop depending on, and Data
# only exists on 3.2+. Neither is worth failing init over.
HAVE_OSTRUCT = begin
  require "ostruct"
  true
rescue LoadError
  false
end

FZ_FILE = "/tmp/ojfuzz_#{Process.pid}.json"

class NullSaj < Oj::Saj
  def hash_start(*) = nil
  def hash_end(*) = nil
  def array_start(*) = nil
  def array_end(*) = nil
  def add_value(*) = nil
  def hash_key(*) = nil
  def hash_set(*) = nil
  def array_append(*) = nil
  def error(*) = nil
end

# saj2.c picks its callbacks by ARITY, not by which methods exist:
# arity 1 on hash_start/hash_end/array_start/array_end and arity 2 on add_value
# select the plain variants, anything else selects the _loc ones. NullSaj uses
# (*) splats, arity -1, so it only ever exercised the _loc half of the file.
class PlainSaj
  def hash_start(key) = nil
  def hash_end(key) = nil
  def array_start(key) = nil
  def array_end(key) = nil
  def add_value(value, key) = nil
end

# Responds to none of the callbacks, which leaves every slot on saj2.c's noop.
class EmptySaj
end

H       = NullSaj.new
H_PLAIN = PlainSaj.new
H_EMPTY = EmptySaj.new
LIM = { max_array_size: 50_000, max_hash_size: 50_000,
        max_depth: 32, max_total_elements: 100_000 }.freeze

USUAL = Oj::Parser.usual
SAFE  = Oj::Parser.safe(LIM)
SAJ2  = Oj::Parser.new(:saj)
SAJ2.handler = H

FZ_STRUCT = Struct.new(:a, :b)
FZ_DATA   = (Data.define(:a, :b) if defined?(Data) && Data.respond_to?(:define))

# An object with instance variables reaches dump_obj_attrs / dump_attr_cb in
# both rails.c and custom.c.
class FzObj
  def initialize(s)
    @s = s
    @n = s.bytesize
  end

  def to_json(*) = %({"fz":#{@n}})
  def as_json(*) = { "fz" => @n }
end

# An object exposing raw_json reaches oj_dump_raw_json.
class FzRaw
  def initialize(s) = @s = s
  def raw_json(_depth = 0, _indent = 0) = %({"raw":#{@s.bytesize}})
end

# Oj.register_odd needs a class with a named dump method (odd.c).
class FzOdd
  attr_reader :v

  def initialize(v) = @v = v
  def self.create(v) = new(v)
end

def objs(s)
  # The fuzzer hands us arbitrary bytes. Building a Regexp or a Symbol out of
  # them raises before Oj is ever called, which silently disables every dump
  # target that uses this list, so scrub once here.
  t = s.dup.force_encoding(Encoding::UTF_8).scrub("?")

  o = [
    s,
    { s => s, "k" => [s, 1, nil, true] },
    [s, { "n" => s }],
    FzObj.new(s),
    FZ_STRUCT.new(s, 1),
    Time.at(0),
    Date.new(2000, 1, 1),
    DateTime.new(2000, 1, 1),
    BigDecimal("1.25"),
    Complex(1, 2),
    Rational(1, 3),
    (1..5),
    Regexp.new(Regexp.escape(t[0, 8].to_s)),
    Object.new,
    t[0, 32].to_sym,
    StandardError.new(t),
  ]
  o << FZ_DATA.new(s, 1) if FZ_DATA
  o << OpenStruct.new(a: s) if HAVE_OSTRUCT
  o.concat(as_objs(t)) if HAVE_AS
  o
end

# rails.c dispatches on the ActiveSupport classes by name, so these are the only
# way into dump_timewithzone, dump_bigdecimal, dump_as_json and dump_to_s.
# dump_activerecord and dump_actioncontroller_parameters additionally need
# activerecord and actionpack, which are not installed.
def as_objs(t)
  [
    Time.now.in_time_zone("UTC"),
    Time.now.in_time_zone("Asia/Tokyo"),
    ActiveSupport::Duration.build(3661),
    ActiveSupport::TimeZone["UTC"],
    { "a" => t }.with_indifferent_access,
    ActiveSupport::SafeBuffer.new(t),
    Date.today.in_time_zone,
  ].concat(ar_objs(t))
rescue StandardError
  []
end

def ar_objs(t)
  return [] unless HAVE_AR

  [
    ActiveRecord::Result.new(%w[a b], [[1, t], [nil, 2.5]]),
    ActionController::Parameters.new({ "a" => t, "n" => [1, { "k" => t }] }),
  ]
rescue StandardError
  []
end

def pick(s, i) = objs(s)[i % objs(s).size]

# Dump the sample objects one at a time. Dumping the array in one call means a
# single object that raises (ActiveSupport 8.1 patches DateTime#as_json to call
# a super that does not exist on Ruby 4.0, once optimize_rails is on) aborts the
# whole dump and costs coverage for every other object in the list.
def dump_all(list, opts)
  list.map { |o| Oj.dump(o, opts) rescue nil }
end

def roundtrip_all(list, opts)
  list.map do |o|
    d = Oj.dump(o, opts) rescue next
    Oj.load(d, opts) rescue nil
  end
end

# debug.c and the trace hooks print with libc printf(). A Ruby-level redirect
# cannot reach that FILE buffer -- the output just sits there and flushes to
# whatever fd 1 is when the buffer fills or the process exits. run.sh therefore
# points fd 1 at /dev/null for the whole process; libFuzzer writes progress and
# -print_coverage to stderr, so nothing useful is lost.
#
# Deliberately NOT silencing stderr here: that is where ASAN reports go.
def silenced
  yield
end

def to_file(s)
  File.binwrite(FZ_FILE, s)
  FZ_FILE
end

# Toggle parser options from the input so usual.c's option setters and its
# per-option add_* variants are reachable. Without this the whole option
# surface is dead code to the fuzzer.
def usual_with(s, n)
  p = Oj::Parser.new(:usual)
  p.cache_keys     = n[0] == 1
  p.cache_strings  = (n >> 1) & 3
  p.symbol_keys    = n[3] == 1
  p.capacity       = ((n >> 4) & 3) * 256
  p.decimal        = %i[auto ruby bigdecimal float][(n >> 6) & 3]
  p.omit_null      = n[2] == 1
  p.parse(s)
end

def dump_opts(n)
  { mode: %i[strict compat object custom rails wab][n % 6],
    indent: " " * ((n >> 3) & 7),
    circular: n[6] == 1,
    class_cache: n[7] == 1,
    escape_mode: %i[json xss_safe ascii unicode_xss][(n >> 4) & 3],
    bigdecimal_as_decimal: n[2] == 1,
    float_precision: (n >> 1) & 15 }
end

# mimic_JSON and the Rails encoder are global switches. Flipping them per call
# would be most of the runtime, so they are installed once here; that also
# covers oj_define_mimic_json and oj_mimic_rails_init.
#
# Note this changes the meaning of the :indent option process-wide: JSON's
# indent is a String, so `indent: 2` raises TypeError from here on. Every dump
# target below passes a String.
# PROFILE SPLIT.
#
# Oj.optimize_rails installs a global encoder that diverts custom-mode dumps of
# Time and Date away from custom.c into rails.c:
#
#   plain:     Oj.dump(Time.at(0), mode: :custom) => {"^o":"Time","time":0.0}
#   optimized: Oj.dump(Time.at(0), mode: :custom) => "1970-01-01T01:00:00.000+01:00"
#
# So custom.c's time_dump/date_dump/*_load family and rails.c/mimic_json.c can
# never be covered by the same process. OJ_PROFILE=mimic turns the global
# switches on; anything else leaves them off. Run a campaign of each and union
# the coverage.
MIMIC = ENV.fetch("OJ_PROFILE", "plain") == "mimic"

Oj.mimic_JSON if MIMIC

# Most of rails.c is only reachable with ActiveSupport loaded: optimize_rails
# raises "ActiveSupport not loaded" without it, and the dump_activerecord /
# dump_timewithzone / dump_actioncontroller_parameters paths need real AS
# classes. Oj::Rails::Encoder and the standalone setters still work, so cover
# what is reachable and skip the rest rather than failing to load.
HAVE_AS = begin
  raise LoadError unless MIMIC

  require "active_support"
  require "active_support/time"
  require "oj/active_support_helper"
  Oj.optimize_rails
  true
rescue LoadError, StandardError
  false
end

# dump_activerecord_result and dump_actioncontroller_parameters dispatch on
# these concrete classes, and Oj::Rails.optimize references ActiveRecord
# internally, so the encoder_optimize / rails_optimize paths need them too.
# Both classes construct standalone; no database connection is involved.
HAVE_AR = begin
  require "active_record"
  require "action_controller"
  # dump_activerecord_result and dump_actioncontroller_parameters are only
  # reached once these specific classes are registered as optimized; a bare
  # Oj.dump of them goes through the generic as_json path instead.
  Oj::Rails.optimize(ActiveRecord::Result, ActionController::Parameters)
  true
rescue LoadError, StandardError
  false
end

# Oj::Rails.mimic_JSON is a second global switch, separate from Oj.mimic_JSON.
# It is the only way into rails_mimic_json / oj_mimic_rails_init /
# rails_set_encoder / rails_set_decoder.
Oj::Rails.mimic_JSON if HAVE_AS && Oj::Rails.respond_to?(:mimic_JSON)

HAVE_RAILS_ENC = defined?(Oj::Rails::Encoder) ? true : false

Oj.register_odd(FzOdd, FzOdd, :create, :v) rescue nil

TARGETS = [
  # --- Oj::Parser family: parser.c / usual.c / safe.c / saj2.c ---
  ->(s) { USUAL.parse(s) },
  ->(s) { SAFE.parse(s) },
  ->(s) { SAJ2.parse(s) },
  ->(s) { usual_with(s[1..].to_s, s.getbyte(0) || 0) },
  ->(s) { Oj::Parser.usual.file(to_file(s)) },          # #1072 territory
  ->(s) { Oj::Parser.safe(LIM).file(to_file(s)) },
  ->(s) { p = Oj::Parser.new(:saj); p.handler = H; p.file(to_file(s)) },

  # --- legacy string parser: parse.c, every mode ---
  ->(s) { Oj.load(s, mode: :strict) },
  ->(s) { Oj.load(s, mode: :compat) },
  ->(s) { Oj.load(s, mode: :object) },
  ->(s) { Oj.load(s, mode: :custom) },
  ->(s) { Oj.load(s, mode: :rails) },
  ->(s) { Oj.load(s, mode: :wab) },
  ->(s) { Oj.load(s, mode: :object, circular: true) },
  ->(s) { Oj.safe_load(s) },
  ->(s) { Oj.load(s, dump_opts(s.getbyte(0) || 0)) },

  # --- streaming parser: sparse.c ---
  ->(s) { Oj.load(StringIO.new(s), mode: :strict) },
  ->(s) { Oj.load(StringIO.new(s), mode: :compat) },
  ->(s) { Oj.load(StringIO.new(s), mode: :object) },
  ->(s) { Oj.load(StringIO.new(s), mode: :rails) },
  ->(s) { Oj.load(StringIO.new(s), mode: :custom) },
  ->(s) { Oj.load_file(to_file(s), mode: :object) },
  ->(s) { Oj.load_file(to_file(s), symbol_keys: true) },

  # --- SAX/callback: scp.c ---
  ->(s) { Oj.sc_parse(H, s) },
  ->(s) { Oj.sc_parse(H, StringIO.new(s)) },
  ->(s) { Oj.saj_parse(H, s) },
  ->(s) { Oj.saj_parse(H, StringIO.new(s)) },

  # --- fast.c: the whole Oj::Doc surface, not just each_leaf ---
  ->(s) { Oj::Doc.open(s) { |d| d.size; d.each_leaf { |x| x } } },
  ->(s) { Oj::Doc.open(s) { |d| d.dump } },
  ->(s) {
    Oj::Doc.open(s) do |d|
      d.each_child { |c| c.where?; c.local_key; c.type }
      d.home
    end
  },
  ->(s) {
    Oj::Doc.open(s) do |d|
      d.each_value { |v| v }
      d.path
    end
  },
  ->(s) {
    # Paths built from the input drive move/fetch/exists?, which is where the
    # doc-path limit bug lived.
    Oj::Doc.open(s) do |d|
      parts = s.dup.force_encoding(Encoding::UTF_8).scrub("").scan(%r{[\w/\[\]-]+}).first(4)
      parts.each do |p|
        d.move(p) rescue nil
        d.exists?(p)
        d.fetch(p)
      end
      d.where?
    end
  },
  ->(s) { Oj::Doc.open_file(to_file(s)) { |d| d.size; d.dump } },

  # --- mimic_json.c: zero covered functions before this ---
  ->(s) { JSON.parse(s) },
  ->(s) { JSON.parse(s, symbolize_names: true) },
  ->(s) { JSON.parse(s, create_additions: true) },
  ->(s) { JSON.parse!(s) },
  ->(s) { JSON.load(s) },
  ->(s) { JSON.generate(pick(s, s.getbyte(0) || 0)) },
  ->(s) { JSON.pretty_generate(pick(s, s.getbyte(0) || 0)) },
  ->(s) { JSON.dump(pick(s, s.getbyte(0) || 0)) },
  ->(s) { pick(s, s.getbyte(0) || 0).to_json },
  ->(s) { JSON.generate({ s => [s, 1] }, JSON::State.new(indent: " ", space: " ")) },
  ->(s) { JSON.create_id = s[0, 16].to_s; JSON.parse(s) },

  # --- rails.c: also zero covered functions before this ---
  ->(s) { HAVE_RAILS_ENC && Oj::Rails::Encoder.new.encode(pick(s, s.getbyte(0) || 0)) },
  ->(s) {
    next unless HAVE_RAILS_ENC

    n = s.getbyte(0) || 0
    Oj::Rails::Encoder.new(indent: " " * (n & 7), circular: n[3] == 1).encode(pick(s, n))
  },
  ->(s) { Oj.dump(pick(s, s.getbyte(0) || 0), mode: :rails) },
  ->(s) { dump_all(objs(s), mode: :rails, indent: "  ") },
  ->(s) {
    if Oj::Rails.respond_to?(:use_standard_json_time_format)
      Oj::Rails.use_standard_json_time_format(s.getbyte(0).to_i.even?)
      Oj::Rails.escape_html_entities_in_json(s.getbyte(1).to_i.even?)
      Oj::Rails.time_precision = (s.getbyte(2) || 0) & 15
    end
    dump_all(objs(s), mode: :rails)
  },
  ->(s) { next unless HAVE_AS; (Oj::Rails.optimize(Hash) rescue nil); Oj.dump(pick(s, s.getbyte(0) || 0), mode: :rails) },
  ->(s) {
    # encoder_optimize / encoder_deoptimize / encoder_optimized, which are
    # methods on the encoder instance rather than the module.
    next unless HAVE_RAILS_ENC

    e = Oj::Rails::Encoder.new(indent: " " * ((s.getbyte(0) || 0) & 7))
    (e.optimize(Hash, Array, FzObj) if e.respond_to?(:optimize)) rescue nil
    r = e.encode(pick(s, s.getbyte(1) || 0))
    (e.optimized?(Hash) if e.respond_to?(:optimized?)) rescue nil
    (e.deoptimize(FzObj) if e.respond_to?(:deoptimize)) rescue nil
    r
  },
  ->(s) {
    next unless HAVE_AS

    # Oj::Rails.optimize references ActiveRecord internally, so without
    # activerecord installed these raise NameError before reaching rails.c.
    begin
      Oj::Rails.optimized?(Hash) if Oj::Rails.respond_to?(:optimized?)
      Oj::Rails.optimize(Hash, Array)
      Oj::Rails.deoptimize(FzObj)
    rescue NameError
      nil
    end
    dump_all(objs(s), mode: :rails)
  },
  ->(s) {
    next unless HAVE_AS

    (Oj::Rails.deoptimize(Hash) rescue nil)
    r = Oj.dump(pick(s, 0), mode: :rails)
    (Oj::Rails.optimize(Hash) rescue nil)
    r
  },

  # --- custom.c: the *_dump / *_load pairs ---
  ->(s) { Oj.dump(pick(s, s.getbyte(0) || 0), mode: :custom) },
  ->(s) { dump_all(objs(s), mode: :custom, indent: "  ", create_id: "^o") },
  ->(s) { roundtrip_all(objs(s), mode: :custom) },
  ->(s) { Oj.load(s, mode: :custom, create_additions: true) },
  ->(s) { Oj.dump(FzOdd.new(s), mode: :custom) },   # odd.c

  # --- dump_compat.c ---
  ->(s) { Oj.dump(pick(s, s.getbyte(0) || 0), mode: :compat) },
  ->(s) { dump_all(objs(s), mode: :compat, indent: "  ") },
  ->(s) { roundtrip_all(objs(s), mode: :compat) },

  # --- dump*.c generally, driven by an option byte ---
  ->(s) { Oj.dump(s, mode: :rails) },
  ->(s) { Oj.dump({ "k" => s, s => "v", "a" => [s, { s => s }] }, mode: :rails) },
  ->(s) { dump_all(objs(s), dump_opts(s.getbyte(0) || 0)) },
  ->(s) { Oj.dump(s, mode: :rails, escape_mode: :xss_safe) },
  ->(s) { objs(s).each { |o| Oj.to_file(FZ_FILE, o, mode: :object) rescue nil } },

  # --- string_writer.c / stream_writer.c ---
  ->(s) {
    w = Oj::StringWriter.new(indent: 2)
    w.push_object
    w.push_key(s[0, 32].to_s)
    w.push_value(s)
    w.push_array("a")
    w.push_value(1)
    w.pop
    w.pop_all
    w.to_s
  },
  ->(s) {
    w = Oj::StringWriter.new
    w.push_object
    w.push_json(s, "raw")
    w.pop_all
    w.to_s
  },
  ->(s) {
    io = StringIO.new
    w = Oj::StreamWriter.new(io, indent: 2)
    w.push_object
    w.push_value(s, "k")
    w.push_array("a")
    w.push_json(s)
    w.pop
    w.pop_all
  },

  # --- saj2.c plain (non-_loc) callbacks, reached only via arity ---
  ->(s) { p = Oj::Parser.new(:saj); p.handler = H_PLAIN; p.parse(s) },
  ->(s) { p = Oj::Parser.new(:saj); p.handler = H_PLAIN; p.file(to_file(s)) },
  ->(s) { p = Oj::Parser.new(:saj); p.handler = H_EMPTY; p.parse(s) },

  # --- dump_compat.c *_alt dumpers, active only under Oj.add_to_json ---
  ->(s) {
    Oj.add_to_json(BigDecimal, Complex, Date, DateTime, Range, Rational, Regexp, Time)
    r = dump_all(objs(s), mode: :compat)
    Oj.remove_to_json(BigDecimal, Complex, Date, DateTime, Range, Rational, Regexp, Time)
    r
  },
  ->(s) {
    Oj.add_to_json(Object)
    r = dump_all(objs(s), mode: :compat, create_id: "^o", class_cache: true)
    Oj.remove_to_json(Object)
    r
  },
  # dump_float / dump_bignum want values the fast paths do not handle
  ->(s) {
    n = s.getbyte(0) || 0
    vals = [Float::INFINITY, -Float::INFINITY, Float::NAN, 1e308 * 10,
            2**(64 + (n & 63)), -(2**(96 + (n & 31))), 1.0 / 3, 1e-320]
    dump_all(vals, mode: :compat) + dump_all(vals, mode: :rails)
  },

  # --- usual.c option getters/setters (the opt_* family) ---
  ->(s) {
    n = s.getbyte(0) || 0
    p = Oj::Parser.new(:usual)
    p.cache_keys = n[0] == 1
    p.cache_strings = (n >> 1) & 3
    p.cache_expunge = (n >> 3) & 3
    p.capacity = ((n >> 4) & 3) * 256
    p.symbol_keys = n[2] == 1
    p.class_cache = n[5] == 1
    p.create_id = n[6] == 1 ? "^o" : nil
    p.ignore_json_create = n[7] == 1
    p.omit_null = n[1] == 1
    p.array_class = n[4] == 1 ? Array : nil
    p.hash_class = n[3] == 1 ? Hash : nil
    p.missing_class = n[0] == 1 ? :auto : :ignore
    p.raise_on_empty = n[5] == 1
    # read every one back: the getters are separate functions
    [p.cache_keys, p.cache_strings, p.cache_expunge, p.capacity, p.symbol_keys,
     p.class_cache, p.create_id, p.ignore_json_create, p.omit_null,
     p.array_class, p.hash_class, p.missing_class, p.raise_on_empty]
    p.parse(s)
  },

  # --- custom.c *_load: needs documents that custom dump produced ---
  ->(s) {
    d = Oj.dump(objs(s), mode: :custom, create_id: "^o", create_additions: true) rescue nil
    d && Oj.load(d, mode: :custom, create_additions: true)
  },
  ->(s) { Oj.load(s, mode: :custom, create_additions: true, create_id: "^o") },
  ->(s) { roundtrip_all(objs(s), mode: :custom, create_id: "^o", create_additions: true) },

  # --- oj.c entry points ---
  ->(s) { io = StringIO.new; Oj.to_stream(io, objs(s), mode: :compat); io.string.bytesize },
  ->(s) {
    o = Oj.default_options
    Oj.default_options = { mode: %i[strict compat object custom rails][(s.getbyte(0) || 0) % 5] }
    r = Oj.dump(s)
    Oj.default_options = o
    r
  },
  ->(s) { Oj.to_json(pick(s, s.getbyte(0) || 0)) },

  # --- debug.c: an entire parser mode that was never instantiated ---
  ->(s) { silenced { Oj::Parser.new(:debug).parse(s) } },
  ->(s) { silenced { Oj::Parser.new(:debug).file(to_file(s)) } },

  # --- validate.c: likewise ---
  ->(s) { Oj::Parser.new(:validate).parse(s) },
  ->(s) { Oj::Parser.new(:validate).file(to_file(s)) },

  # --- parser.c: just_one, load, and the mode setters ---
  ->(s) {
    p = Oj::Parser.new(:usual)
    p.just_one = (s.getbyte(0) || 0).even?
    p.just_one
    # Parser#load takes an IO and calls readpartial on it; Parser#parse is the
    # String entry point.
    p.load(StringIO.new(s))
  },
  ->(s) { Oj::Parser.new(:saj).tap { |x| x.handler = H_PLAIN }.load(StringIO.new(s)) },

  # --- trace.c: the trace hooks ---
  ->(s) { silenced { Oj.load(s, mode: :object, trace: true) } },
  ->(s) { silenced { Oj.dump(objs(s).first(4), mode: :object, trace: true) } },

  # --- scp.c noop_* : chosen when the handler responds to nothing ---
  ->(s) { Oj.sc_parse(Object.new, s) },
  ->(s) { Oj.sc_parse(Object.new, StringIO.new(s)) },

  # --- reader.c: a real IO, not a StringIO, for the partial-read paths ---
  ->(s) {
    r, w = IO.pipe
    begin
      w.write(s)
      w.close
      Oj.load(r, mode: :strict)
    ensure
      r.close unless r.closed?
      w.close unless w.closed?
    end
  },
  ->(s) {
    r, w = IO.pipe
    begin
      w.write(s)
      w.close
      Oj.sc_parse(H, r)
    ensure
      r.close unless r.closed?
      w.close unless w.closed?
    end
  },

  # --- odd.c: register_odd / register_odd_raw ---
  ->(s) {
    c = Struct.new(:v)
    Oj.register_odd(c, c, :new, :v)
    Oj.load(Oj.dump(c.new(s), mode: :object), mode: :object)
  },
  ->(s) {
    c = Struct.new(:v)
    Oj.register_odd_raw(c, c, :new, :v)
    Oj.dump(c.new(%({"raw":#{s.bytesize}})), mode: :object)
  },

  # --- mem.c ---
  ->(s) { silenced { Oj.mem_report } },

  # --- rxclass.c: reached only through the :match_string option ---
  ->(s) {
    t = s.dup.force_encoding(Encoding::UTF_8).scrub("")
    rx = { /^tim/ => Time, Regexp.new(Regexp.escape(t[0, 6].to_s)) => String }
    Oj.load(s, mode: :compat, match_string: rx)
  },
  ->(s) {
    rx = { /./ => String, /\A\d+\z/ => Integer }
    Oj.load(s, mode: :custom, match_string: rx, create_additions: true)
  },

  # --- GC callbacks: mark_doc / mark_leaf / compact_doc / compact_leaf /
  #     free_doc_cb / string_writer_mark only run under GC, so force it while
  #     the objects are still live.
  ->(s) {
    d = Oj::Doc.open(s) { |x| x }
    w = Oj::StringWriter.new
    w.push_object
    w.push_value(s, "k")
    GC.start
    GC.compact if GC.respond_to?(:compact)
    w.pop_all
    d
  },
  ->(s) {
    doc = Oj::Doc.open(s)
    doc.size
    GC.start
    doc.close
  },

  # --- string_writer.c: reset / as_json / the unwrap path ---
  ->(s) {
    w = Oj::StringWriter.new(indent: "  ")
    w.push_object
    w.push_value(s, "k")
    w.pop_all
    a = w.to_s
    w.reset if w.respond_to?(:reset)
    b = (w.as_json if w.respond_to?(:as_json))
    [a, b]
  },

  # --- dump.c: the per-type dumpers ---
  ->(s) {
    n = s.getbyte(0) || 0
    fmt = %i[unix unix_zone xmlschema ruby][n & 3]
    dump_all([Time.at(0), Time.now, Time.at(1 << 33)],
             mode: :custom, time_format: fmt, create_id: "^o")
  },
  ->(s) { dump_all([String, Hash, Oj, FzObj, Comparable], mode: :object) },
  ->(s) { Oj.dump(FzRaw.new(s), mode: :compat) },
  ->(s) { dump_all([Float::NAN, Float::INFINITY, -Float::INFINITY], mode: %i[strict null compat rails][(s.getbyte(0) || 0) & 3]) },
  ->(s) { Oj.dump({ s => 1, "b" => nil, "c" => 2 }, mode: :compat, omit_nil: true, omit_null_byte: true) },

  # --- custom.c *_dump / *_load pairs, per object so one failure is contained ---
  ->(s) {
    n = s.getbyte(0) || 0
    o = { mode: :custom, create_id: "^o", create_additions: true,
          time_format: %i[unix unix_zone xmlschema ruby][n & 3],
          bigdecimal_as_decimal: n[2] == 1,
          bigdecimal_load: n[3] == 1 ? :bigdecimal : :float }
    roundtrip_all(objs(s), o)
  },
  ->(s) { Oj.load(s, mode: :custom, create_additions: true, create_id: "^o", bigdecimal_load: :bigdecimal) },

  # --- usual.c: create_id / symbol keys / the decimal-mode key variants ---
  ->(s) {
    n = s.getbyte(0) || 0
    p = Oj::Parser.new(:usual)
    p.create_id = "^o"
    p.class_cache = n[0] == 1
    p.ignore_json_create = n[1] == 1
    p.symbol_keys = n[2] == 1
    p.decimal = %i[auto ruby bigdecimal float][(n >> 3) & 3]
    p.missing_class = n[4] == 1 ? :auto : :ignore
    p.parse(s)
  },
  ->(s) {
    # documents whose keys are numbers of every width, for the
    # add_float_as_big_key / add_big_as_float_key / add_big_as_ruby_key trio
    n = s.getbyte(0) || 0
    doc = %({"a":1.5,"b":123456789012345678901234567890,"c":1e400,"d":#{"9" * 40},"e":0.1})
    p = Oj::Parser.new(:usual)
    p.decimal = %i[auto ruby bigdecimal float][n & 3]
    [p.parse(doc), p.parse(s)]
  },
  ->(s) {
    n = s.getbyte(0) || 0
    Oj.load(%({"^o":"FzObj","s":"x"}), mode: :object, create_id: "^o",
            class_cache: n[0] == 1, auto_define: n[1] == 1) rescue nil
    Oj.load(s, mode: :object, create_id: "^o", auto_define: n[1] == 1)
  },

  # --- round trips ---
  ->(s) { Oj.dump(Oj.load(s, mode: :strict), mode: :strict) },
  ->(s) { Oj.load(Oj.dump(Oj.load(s, mode: :object), mode: :object), mode: :object) },
].freeze
