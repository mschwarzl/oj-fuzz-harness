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

H = NullSaj.new
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
  o
end

def pick(s, i) = objs(s)[i % objs(s).size]

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
Oj.mimic_JSON

# Most of rails.c is only reachable with ActiveSupport loaded: optimize_rails
# raises "ActiveSupport not loaded" without it, and the dump_activerecord /
# dump_timewithzone / dump_actioncontroller_parameters paths need real AS
# classes. Oj::Rails::Encoder and the standalone setters still work, so cover
# what is reachable and skip the rest rather than failing to load.
HAVE_AS = begin
  require "active_support"
  require "active_support/time"
  require "oj/active_support_helper"
  Oj.optimize_rails
  true
rescue LoadError, StandardError
  false
end

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
    Oj::Rails::Encoder.new(indent: n & 7, circular: n[3] == 1).encode(pick(s, n))
  },
  ->(s) { Oj.dump(pick(s, s.getbyte(0) || 0), mode: :rails) },
  ->(s) { Oj.dump(objs(s), mode: :rails, indent: "  ") },
  ->(s) {
    if Oj::Rails.respond_to?(:use_standard_json_time_format)
      Oj::Rails.use_standard_json_time_format(s.getbyte(0).to_i.even?)
      Oj::Rails.escape_html_entities_in_json(s.getbyte(1).to_i.even?)
      Oj::Rails.time_precision = (s.getbyte(2) || 0) & 15
    end
    Oj.dump(objs(s), mode: :rails)
  },
  ->(s) { next unless HAVE_AS; Oj::Rails.optimize; Oj.dump(pick(s, s.getbyte(0) || 0), mode: :rails) },
  ->(s) {
    next unless HAVE_AS

    Oj::Rails.deoptimize
    r = Oj.dump(pick(s, 0), mode: :rails)
    Oj::Rails.optimize
    r
  },

  # --- custom.c: the *_dump / *_load pairs ---
  ->(s) { Oj.dump(pick(s, s.getbyte(0) || 0), mode: :custom) },
  ->(s) { Oj.dump(objs(s), mode: :custom, indent: "  ", create_id: "^o") },
  ->(s) { Oj.load(Oj.dump(objs(s), mode: :custom), mode: :custom) },
  ->(s) { Oj.load(s, mode: :custom, create_additions: true) },
  ->(s) { Oj.dump(FzOdd.new(s), mode: :custom) },   # odd.c

  # --- dump_compat.c ---
  ->(s) { Oj.dump(pick(s, s.getbyte(0) || 0), mode: :compat) },
  ->(s) { Oj.dump(objs(s), mode: :compat, indent: "  ") },
  ->(s) { Oj.load(Oj.dump(objs(s), mode: :compat), mode: :compat) },

  # --- dump*.c generally, driven by an option byte ---
  ->(s) { Oj.dump(s, mode: :rails) },
  ->(s) { Oj.dump({ "k" => s, s => "v", "a" => [s, { s => s }] }, mode: :rails) },
  ->(s) { Oj.dump(objs(s), dump_opts(s.getbyte(0) || 0)) },
  ->(s) { Oj.dump(s, mode: :rails, escape_mode: :xss_safe) },
  ->(s) { Oj.to_file(FZ_FILE, objs(s), mode: :object) },

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

  # --- round trips ---
  ->(s) { Oj.dump(Oj.load(s, mode: :strict), mode: :strict) },
  ->(s) { Oj.load(Oj.dump(Oj.load(s, mode: :object), mode: :object), mode: :object) },
].freeze
