# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/joinlines"
require "logstash/event"
require "insist"
require_relative '../spec_helper'

# above helper also defines a subclass of Joinlines
# called JoinlinesRspec that exposes the internal buffer
# and a Logger Mock

describe LogStash::Codecs::Joinlines do
  context "#multipatterns" do
    let(:config) { {"patterns" => "", "what" => "next", "negate" => false} }
    let(:codec) { LogStash::Codecs::Joinlines.new(config).tap {|c| c.register } }
    let(:events) { [] }
    let(:line_producer) do
      lambda do |lines|
        lines.each do |line|
          codec.decode(line) do |event|
            events << event
          end
        end
      end
    end
    
    it "should internally decode lines to (event, what) pairs" do
      config.update("patterns" => ["^\\s", "next"], "what" => ["previous", "next"], "negate" => [false, false])
      text = "hello world\n   second line\nanother first line\nnext\nowns previous\n"

      events = []
      whats = []
      codec.internal_decode(text) do |event,what|
        events.push(event)
        whats.push(what)
      end

      # Must flush to get last event
      codec.flush do |event|
        events.push(event)
        whats.push("final") # dummy
      end

      expect(events.size).to eq(3)
      expect(whats.size).to eq(3)
      expect(events[0].get("message")).to eq("hello world\n   second line")
      expect(events[1].get("message")).to eq("another first line")
      expect(events[2].get("message")).to eq("next\nowns previous")
    end

    it "should break between consecutive previous and next" do
      config.update("patterns" => ["^\\s", "next"], "what" => ["previous", "next"], "negate" => [false, false])
      lines = [ "hello world", "   second line", "next", "owns previous" ]      
      line_producer.call(lines)
      codec.flush { |e| events << e }

      expect(events.size).to eq(2)
      expect(events[0].get("message")).to eq "hello world\n   second line"
      expect(events[0].get("tags")).to include("joinlines")
      expect(events[1].get("message")).to eq "next\nowns previous"
      expect(events[1].get("tags")).to include("joinlines")
    end

    it "should stitch together consecutive next and previous" do
      config.update("patterns" => ["^\\s", "next"], "what" => ["previous", "next"], "negate" => [false, false])
      lines = [ "next", "owns previous and next", "   second line", "another first" ]      
      line_producer.call(lines)
      codec.flush { |e| events << e }

      expect(events.size).to eq(2)
      expect(events[0].get("message")).to eq "next\nowns previous and next\n   second line"
      expect(events[0].get("tags")).to include("joinlines")
      expect(events[1].get("message")).to eq "another first"
      expect(events[1].get("tags")).to be_nil
    end
  end

  context "#decode" do
    let(:config) { {"patterns" => "", "what" => "next", "negate" => false} }
    let(:codec) { LogStash::Codecs::Joinlines.new(config).tap {|c| c.register } }
    let(:events) { [] }
    let(:line_producer) do
      lambda do |lines|
        lines.each do |line|
          codec.decode(line) do |event|
            events << event
          end
        end
      end
    end

    it "should be able to handle multiline events with additional lines space-indented" do
      config.update("patterns" => "^\\s", "what" => "previous", "negate" => false)
      lines = [ "hello world", "   second line", "another first line" ]
      line_producer.call(lines)
      codec.flush { |e| events << e }

      expect(events.size).to eq(2)
      expect(events[0].get("message")).to eq "hello world\n   second line"
      expect(events[0].get("tags")).to include("joinlines")
      expect(events[1].get("message")).to eq "another first line"
      expect(events[1].get("tags")).to be_nil
    end

    it "should allow custom tag added to multiline events" do
      config.update("patterns" => "^\\s", "what" => "previous", "negate" => false, "multiline_tag" => "hurray")
      lines = [ "hello world", "   second line", "another first line" ]
      line_producer.call(lines)
      codec.flush { |e| events << e }

      expect(events.size).to eq 2
      expect(events[0].get("tags")).to include("hurray")
      expect(events[1].get("tags")).to be_nil
    end

    it "should handle new lines in messages" do
      config.update("patterns" => '\D', "what" => "previous", "negate" => false)
      lineio = StringIO.new("1234567890\nA234567890\nB234567890\n0987654321\n")
      until lineio.eof
        line = lineio.read(256) #when this is set to 36 the tests fail
        codec.decode(line) {|evt| events.push(evt)}
      end
      codec.flush { |e| events << e }
      expect(events[0].get("message")).to eq "1234567890\nA234567890\nB234567890"
      expect(events[1].get("message")).to eq "0987654321"
    end

    it "should allow grok patterns to be used" do
      config.update(
        "patterns" => "^%{NUMBER} %{TIME}",
        "negate" => true,
        "what" => "previous"
      )

      lines = [ "120913 12:04:33 first line", "second line", "third line" ]

      line_producer.call(lines)
      codec.flush { |e| events << e }

      insist { events.size } == 1
      insist { events.first.get("message") } == lines.join("\n")
    end

    context "using default UTF-8 charset" do

      it "should decode valid UTF-8 input" do
        config.update("patterns" => "^\\s", "what" => "previous", "negate" => false)
        lines = [ "foobar", "κόσμε" ]
        lines.each do |line|
          expect(line.encoding.name).to eq "UTF-8"
          expect(line.valid_encoding?).to be_truthy
          codec.decode(line) { |event| events << event }
        end

        codec.flush { |e| events << e }
        expect(events.size).to eq 2

        events.zip(lines).each do |tuple|
          expect(tuple[0].get("message")).to eq tuple[1]
          expect(tuple[0].get("message").encoding.name).to eq "UTF-8"
        end
      end

      it "should escape invalid sequences" do
        config.update("patterns" => "^\\s", "what" => "previous", "negate" => false)
        lines = [ "foo \xED\xB9\x81\xC3", "bar \xAD" ]
        lines.each do |line|
          expect(line.encoding.name).to eq "UTF-8"
          expect(line.valid_encoding?).to eq false

          codec.decode(line) { |event| events << event }
        end
        codec.flush { |e| events << e }
        expect(events.size).to eq 2

        events.zip(lines).each do |tuple|
          expect(tuple[0].get("message")).to eq tuple[1].inspect[1..-2]
          expect(tuple[0].get("message").encoding.name).to eq "UTF-8"
        end
      end

      it "decodes and joins multiple patterns" do
        config.update("patterns" => [ "^\\s", "^the following" ], "what" => [ "previous", "next" ], "negate" => [ false, false] )
        lines = [ "hello world", "   second line", "another first line", "the following message belongs to next", "I own the previous", "Another first" ]

        lines.each do |line|
          codec.decode(line) do |event|
            events << event
          end
        end

        codec.flush { |e| events << e }
  
        #expect(events.size).to eq(4)
        expect(events[0].get("message")).to eq "hello world\n   second line"
        expect(events[0].get("tags")).to include("joinlines")
        expect(events[1].get("message")).to eq "another first line"
        expect(events[1].get("tags")).to be_nil
        expect(events[2].get("message")).to eq "the following message belongs to next\nI own the previous"
        expect(events[2].get("tags")).to include("joinlines")
        expect(events[3].get("message")).to eq "Another first"
        expect(events[3].get("tags")).to be_nil
      end
    end


    context "with valid non UTF-8 source encoding" do

      it "should encode to UTF-8" do
        config.update("charset" => "ISO-8859-1", "patterns" => "^\\s", "what" => "previous", "negate" => false)
        samples = [
          ["foobar", "foobar"],
          ["\xE0 Montr\xE9al", "à Montréal"],
        ]

        # lines = [ "foo \xED\xB9\x81\xC3", "bar \xAD" ]
        samples.map{|(a, b)| a.force_encoding("ISO-8859-1")}.each do |line|
          expect(line.encoding.name).to eq "ISO-8859-1"
          expect(line.valid_encoding?).to eq true

          codec.decode(line) { |event| events << event }
        end
        codec.flush { |e| events << e }
        expect(events.size).to eq 2

        events.zip(samples.map{|(a, b)| b}).each do |tuple|
          expect(tuple[1].encoding.name).to eq "UTF-8"
          expect(tuple[0].get("message")).to eq tuple[1]
          expect(tuple[0].get("message").encoding.name).to eq "UTF-8"
        end
      end
    end

    context "with invalid non UTF-8 source encoding" do

     it "should encode to UTF-8" do
        config.update("charset" => "ASCII-8BIT", "patterns" => "^\\s", "what" => "previous", "negate" => false)
        samples = [
          ["\xE0 Montr\xE9al", "� Montr�al"],
          ["\xCE\xBA\xCF\x8C\xCF\x83\xCE\xBC\xCE\xB5", "����������"],
        ]
        events = []
        samples.map{|(a, b)| a.force_encoding("ASCII-8BIT")}.each do |line|
          expect(line.encoding.name).to eq "ASCII-8BIT"
          expect(line.valid_encoding?).to eq true

          codec.decode(line) { |event| events << event }
        end
        codec.flush { |e| events << e }
        expect(events.size).to eq 2

        events.zip(samples.map{|(a, b)| b}).each do |tuple|
          expect(tuple[1].encoding.name).to eq "UTF-8"
          expect(tuple[0].get("message")).to eq tuple[1]
          expect(tuple[0].get("message").encoding.name).to eq "UTF-8"
        end
      end

    end
  end

  context "with non closed multiline events" do
    let(:random_number_of_events) { rand(300..1000) }
    let(:sample_event) { "- Sample event" }
    let(:events) { decode_events }
    let(:unmerged_events_count) { events.collect { |event| event.get("message").split(LogStash::Codecs::Joinlines::NL).size }.inject(&:+) }

    context "break on maximum_lines" do
      let(:max_lines) { rand(10..100) }
      let(:options) {
        {
          "patterns" => "^-",
          "what" => "previous",
          "negate" => false,
          "max_lines" => max_lines,
          "max_bytes" => "2 mb"
        }
      }

      it "flushes on a maximum lines" do
        expect(unmerged_events_count).to eq(random_number_of_events)
      end

      it "tags the event" do
        expect(events.first.get("tags")).to include("joinlines_codec_max_lines_reached")
      end
    end

    context "break on maximum bytes" do
      let(:max_bytes) { rand(30..100) }
      let(:options) {
        {
          "patterns" => "^-",
          "what" => "previous",
          "negate" => false,
          "max_lines" => 20000,
          "max_bytes" => max_bytes
        }
      }

      it "flushes on a maximum bytes size" do
        expect(unmerged_events_count).to eq(random_number_of_events)
      end

      it "tags the event" do
        expect(events.first.get("tags")).to include("joinlines_codec_max_bytes_reached")
      end
    end
  end

  describe "auto flushing" do
    let(:config) { {"patterns" => "", "what" => "next", "negate" => false} }
    let(:events) { [] }
    let(:lines) do
      { "en.log" => ["hello world", " second line", " third line"],
        "fr.log" => ["Salut le Monde", " deuxième ligne", " troisième ligne"],
        "de.log" => ["Hallo Welt"] }
    end
    let(:listener_class) { Jlc::LineListener }
    let(:auto_flush_interval) { 2 }

    let(:line_producer) do
      lambda do |path|
        #create a listener that holds upstream state
        listener = listener_class.new(events, codec, path)
        lines[path].each do |data|
          listener.accept(data)
        end
      end
    end

    let(:codec) do
      Jlc::JoinlinesRspec.new(config).tap {|c| c.register}
    end

    before :each do
      expect(LogStash::Codecs::Joinlines).to receive(:logger).and_return(Jlc::JoinlinesLogTracer.new).at_least(:once)
    end

    context "when auto_flush_interval is not set" do
      it "does not build any events" do
        config.update("patterns" => "^\\s", "what" => "previous", "negate" => false)
        line_producer.call("en.log")
        sleep auto_flush_interval + 0.1
        expect(events.size).to eq(0)
        expect(codec.buffer_size).to eq(3)
      end
    end

    context "when the auto_flush raises an exception" do
      let(:errmsg) { "OMG, Daleks!" }
      let(:listener_class) { Jlc::LineErrorListener }

      it "does not build any events, logs an error and the buffer data remains" do
        config.update("patterns" => "^\\s", "what" => "previous", "negate" => false,
          "auto_flush_interval" => auto_flush_interval)
        line_producer.call("en.log")
        sleep(auto_flush_interval + 0.2)
        msg, args = codec.logger.trace_for(:error)
        expect(msg).to eq("Joinlines: flush downstream error")
        expect(args[:exception].message).to eq(errmsg)
        expect(events.size).to eq(0)
        expect(codec.buffer_size).to eq(3)
      end
    end

    def assert_produced_events(key, sleeping)
      line_producer.call(key)
      sleep(sleeping)
      yield
      #expect(codec).to have_an_empty_buffer
    end

    context "mode: previous, when there are pauses between multiline file writes" do
      it "auto-flushes events from the accumulated lines to the queue" do
        config.update("patterns" => "^\\s", "what" => "previous", "negate" => false,
          "auto_flush_interval" => auto_flush_interval)

        assert_produced_events("en.log", auto_flush_interval + 0.1) do
          expect(events[0]).to match_path_and_line("en.log", lines["en.log"])
        end

        line_producer.call("fr.log")
        #next line(s) come before auto-flush i.e. assert its buffered
        sleep(auto_flush_interval - 0.3)
        expect(codec.buffer_size).to eq(3)
        expect(events.size).to eq(1)

        assert_produced_events("de.log", auto_flush_interval + 0.1) do
          # now the events are generated
          expect(events[1]).to match_path_and_line("fr.log", lines["fr.log"])
          expect(events[2]).to match_path_and_line("de.log", lines["de.log"])
        end
      end
    end

    context "mode: next, when there are pauses between multiline file writes" do

      let(:lines) do
        { "en.log" => ["hello world++", "second line++", "third line"],
          "fr.log" => ["Salut le Monde++", "deuxième ligne++", "troisième ligne"],
          "de.log" => ["Hallo Welt"] }
      end

      it "auto-flushes events from the accumulated lines to the queue" do
        config.update("patterns" => "\\+\\+$", "what" => "next", "negate" => false,
          "auto_flush_interval" => auto_flush_interval)

        assert_produced_events("en.log", auto_flush_interval + 0.1) do
          # wait for auto_flush
          expect(events[0]).to match_path_and_line("en.log", lines["en.log"])
        end

        expect(codec).to have_an_empty_buffer

        assert_produced_events("de.log", auto_flush_interval - 0.3) do
          # this file is read before auto-flush, thus last event is not flushed yet
          # This differs from logstash-codec-multiline because of not emitting
          # last received event even if not matched
          expect(events.size).to eq(1)
        end

        codec.flush { |event| events << event } # flushing here releases the event
        expect(events.size).to eq(2)
        expect(events[1]).to match_path_and_line(nil, lines["de.log"]) # but path is not set when emitted by flush
        expect(codec).to have_an_empty_buffer

        assert_produced_events("fr.log", auto_flush_interval + 0.1) do
          # wait for auto_flush
          expect(events[2]).to match_path_and_line("fr.log", lines["fr.log"])
        end
      end
    end
  end
end
