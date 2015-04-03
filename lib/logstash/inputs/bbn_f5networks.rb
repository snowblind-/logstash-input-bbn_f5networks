##########################################################################################
# Copyright (C) 2015 Buffin Bay Networks, Inc - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Devops <devops-github@baffinbaynetworks.com>, March 2015
##########################################################################################

# Logstash specific dependencies
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/filters/grok"
require "logstash/filters/date"

# Other dependencies
require "socket"
require "date"
require "concurrent_ruby"


class LogStash::Inputs::F5Networks < LogStash::Inputs::Base

  config_name "bbn_f5networks"

	default :codec, "plain"

	# IP address to bind to input plugin
	config :log_collector_ip, :validate => :string, :default => "0.0.0.0"
	# Port to bind to input plugin  
	config :log_collector_port, :validate => :number, :default => 514
  # Protocol to use UDP/TCP or both
  config :log_collector_protocol, :validate => :array, :default => [ "udp" ]
	# Timezone string should be "UTC" = +00.00
	config :timezone, :validate => :string, :default => "UTC"
  config :locale, :validate => :string

	public
  	def initialize(params)

    	super
    	
    	@shutdown_requested = Concurrent::AtomicBoolean.new(false)
    	BasicSocket.do_not_reverse_lookup = true
  	
  	end

	public
	def register

		require "thread_safe"

    @grok_filter = LogStash::Filters::Grok.new(
        "overwrite" => "message",
      	"match" => { "message" => "<%{POSINT:priority}>%{SYSLOGLINE}" },
      	"tag_on_failure" => ["_grokparsefailure_sysloginput"],
    )

    @date_filter = LogStash::Filters::Date.new(
        "match" => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss", "ISO8601"],
      	"locale" => @locale,
      	"timezone" => @timezone,
    )

    @grok_filter.register
    @date_filter.register

    @tcp_sockets = ThreadSafe::Array.new
    @tcp = @udp = nil
	
	end

	def run(queue)

    # TODO: We need to make sure we start UDP listener before the TCP listener if both are in the config variable, for
    # now we leave it without validation as we can control the order in the .conf file.

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
    
    @codec.decode(data) do |event|
      decorate(event)
      event["host"] = host
      parse_event(event)
      queue << event
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
  
  # Following RFC3164 where sane, we'll try to parse a received message
  # as if you were relaying a syslog message to it.
  # If the message cannot be recognized (see @grok_filter), we'll
  # treat it like the whole event["message"] is correct and try to fill
  # the missing pieces (host, priority, etc)
  public
  def parse_event(event)

    puts event
    
    @grok_filter.filter(event)

    if event["tags"].nil? || !event["tags"].include?(@grok_filter.tag_on_failure)
      # Per RFC3164, priority = (facility * 8) + severity
      #                       = (facility << 3) & (severity)
      priority = event["priority"].to_i rescue 13
      severity = priority & 7   # 7 is 111 (3 bits)
      facility = priority >> 3
      event["priority"] = priority
      event["severity"] = severity
      event["facility"] = facility

      event["timestamp"] = event["timestamp8601"] if event.include?("timestamp8601")
      @date_filter.filter(event)
    else
      @logger.info? && @logger.info("NOT SYSLOG", :message => event["message"])

      # RFC3164 says unknown messages get pri=13
      priority = 13
      event["priority"] = 13
      event["severity"] = 5   # 13 & 7 == 5
      event["facility"] = 1   # 13 >> 3 == 1
    end

    # Apply severity and facility metadata if
    # use_labels => true
    if @use_labels
      facility_number = event["facility"]
      severity_number = event["severity"]

      if @facility_labels[facility_number]
        event["facility_label"] = @facility_labels[facility_number]
      end

      if @severity_labels[severity_number]
        event["severity_label"] = @severity_labels[severity_number]
      end
    end
	end
  
end # class LogStash::Inputs::Example
