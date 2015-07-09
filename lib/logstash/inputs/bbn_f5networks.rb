# encoding: utf-8
#####################################################################################
# Copyright 2015 BAFFIN BAY NETWORKS
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#####################################################################################

# Logstash specific dependencies
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/filters/grok"
require "logstash/filters/date"

# ES dependencies
require "elasticsearch"

# BBN dependencies
require "logstash/inputs/modules/bbn_syslog"
require "logstash/inputs/modules/bbn_cef"
require "logstash/inputs/modules/bbn_common"

# Other dependencies
require "socket"
require "date"
require "concurrent_ruby"
require "json"
require "logger"
require "hashie"

class LogStash::Inputs::F5Networks < LogStash::Inputs::Base

  config_name "bbn_f5networks"

  default :codec, "plain"

  # IP address to bind to input plugin
  config :log_collector_ip, :validate => :string, :default => "0.0.0.0"

  # Port to bind to input plugin has to be greater then 1024
  config :log_collector_port, :validate => :number, :default => 1514

  # Protocol to use UDP/TCP or both
  config :log_collector_protocol, :validate => :array, :default => [ "udp" ]

  # MLP Support allows you to make an attack entry out of an Attack Sampled message
  config :mlp_support, :validate => :number, :default => 0

  # Store the original log message together with the event
  config :store_original_payload, :validate => :boolean, :default => true

  # Default UTC Offset
  config :default_utc_offset, :validate => :string, :default => "0"

  # Explicit UTC offset per IP
  config :explicit_utc_offset, :validate => :hash, :default => ["any", "0"]

  # Default health string sent from BIG-IP
  config :default_health_string, :validate => :string, :default => "default send string"

  # Explicit health string per IP
  config :explicit_health_string, :validate => :hash, :default => ["any", "default send string"]


  public
  def initialize(params)

    super

    @shutdown_requested = Concurrent::AtomicBoolean.new(false)
    BasicSocket.do_not_reverse_lookup = true

  end

  public
  def register

    require "thread_safe"


    @tcp_sockets = ThreadSafe::Array.new
    @tcp = @udp = nil

  end

  def run(queue)

    # TODO: We need to make sure we start UDP listener before the TCP listener if both are in the config variable, for
    # now we leave it without validation as we can control the order in the .conf file...

    log_collector_protocol.each do |protocol|

      if protocol == "udp"

        udp_thread = Thread.new(queue) do |queue|
          server(:udp, queue)
        end

      elsif protocol == "tcp"

        tcp_thread = Thread.new(queue) do |queue|
          server(:tcp, queue)
        end

        tcp_thread.join

      end

    end

  end

  private
  def server(protocol, queue)

    self.send("#{protocol}_listener", queue)

  rescue => e
    if @shutdown_requested.false?
      @logger.warn("listener died",
                   :protocol => protocol,
                   :address => "#{@log_collector_ip}:#{@log_collector_port}",
                   :exception => e,
                   :backtrace => e.backtrace
      )

      sleep(5)

      retry

    end

  end

  private
  def udp_listener(queue)

    @logger.info("Starting f5network udp listener", :address => "#{@log_collector_ip}:#{@log_collector_port}")

    @udp.close if @udp
    @udp = UDPSocket.new(Socket::AF_INET)
    @udp.bind(@log_collector_ip, @log_collector_port)

    while true
      payload, client = @udp.recvfrom(9000)
      decode(client[3], queue, payload)
    end

  ensure

    close_udp

  end

  private
  def tcp_listener(queue)

    @logger.info("Starting f5network tcp listener", :address => "#{@log_collector_ip}:#{@log_collector_port}")

    @tcp = TCPServer.new(@log_collector_ip, @log_collector_port)

    loop do
      socket = @tcp.accept
      @tcp_sockets << socket

      break if @shutdown_requested.true?

      Thread.new(queue, socket) do |queue, socket|
        tcp_receiver(queue, socket)
      end

    end

  ensure

    close_tcp

  end

  def tcp_receiver(queue, socket)

    ip, port = socket.peeraddr[3], socket.peeraddr[1]
    @logger.info("new connection", :client => "#{ip}:#{port}")
    LogStash::Util::set_thread_name("input|f5networks|tcp|#{ip}:#{port}}")

    socket.each { |line| decode(ip, queue, line) }


      # Catch connection reset exceptions, we don't want them to be passed up to the tcp_listener
  rescue Errno::ECONNRESET

  ensure
    @tcp_sockets.delete(socket)
    socket.close rescue nil

  end

  private
  def decode(host, queue, data)

    drop_health_string = default_health_string

    if explicit_health_string.has_key?("any")

      drop_health_string = explicit_health_string["any"]

    elsif explicit_health_string.length >= 1

      explicit_health_string.each do |key,value|

        if host == key

          drop_health_string = value

        end

      end

    end

    if drop_health_string == data
      return
    end

    event = Hash.new
    event["message"] = data
    event["host"] = host

    response = Hash.new()
    response = parse(event)

    response.each do |key, value|

      output = LogStash::Event.new(value)
      decorate(output)

      queue << output

    end

      # Catch decode related exceptions, not related to the socket
  rescue => e

    @logger.error("Error decoding data",
                  :data => line.inspect,
                  :exception => e,
                  :backtrace => e.backtrace)

  end

  public
  def teardown

    @shutdown_requested.make_true
    close_udp
    close_tcp
    finished

  end

  private
  def close_udp

    if @udp
      @udp.close_read rescue nil
      @udp.close_write rescue nil
    end

    @udp = nil

  end

  private
  def close_tcp

    @tcp_sockets.each do |socket|
      socket.close rescue nil
    end

    @tcp.close if @tcp rescue nil
    @tcp = nil

  end

  public
  def parse(event)

    response = Hash.new()

    event["mlp_support"] = mlp_support

    event["utc_offset"] = default_utc_offset

    if explicit_utc_offset.has_key?("any")

      event["utc_offset"] = explicit_utc_offset["any"]

    elsif explicit_utc_offset.length >= 1

      explicit_utc_offset.each do |key,value|

        if event["host"] == key

          event["utc_offset"] = value

        end

      end

    end

    # First validate the message
    # Support Syslog/Standard and Syslog/CEF

    message = event["message"]

    if message[0..4] == "<134>"

      event["remote_log_format"] = "Syslog"

      response = BBNSyslog.parse_syslog(event)

    elsif message[0..4] == "CEF:0"

      event["remote_log_format"] = "CEF"

      response = BBNCef.parse_cef(event)

    else

      # Unsupported syslog source, for future implementation

      event["remote_log_format"] = "Unknown"

    end

    return response

  end

end # class LogStash::Inputs::F5Networks
