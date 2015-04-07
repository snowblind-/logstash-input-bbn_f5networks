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
require "json"


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
      queue << event.to_json

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
  def parse_event(event)

    @cef_hash = Hash.new
    cef_dyn_hash = Hash.new

    message = event["message"]

    if message[0..4] == "<134>"

      # Syslog format

      cef_data = message
      cef_data.delete! '"'

      cef_data.scan(/[a-zA-Z0-9_]+[=]+[a-zA-Z0-9:_\/\.\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/) do |cef_record|

        cef_entry = cef_record.split("=")

        # Device Host Name, FQDN
        if cef_entry[0] == "hostname" then @cef_hash["bigip_hostname"] = cef_entry[1]

          # Device IP
        elsif cef_entry[0] == "bigip_mgmt_ip" then @cef_hash["bigip_ip"] = cef_entry[1]

          # Remote time
        elsif cef_entry[0] == "date_time" then @cef_hash["bigip_time"] = cef_entry[1]

          # Device module
        elsif cef_entry[0] == "device_product" then @cef_hash["module"] = cef_entry[1]

          # Device Vendor
        elsif cef_entry[0] == "device_vendor" then @cef_hash["vendor"] = cef_entry[1]

          # Device Version
        elsif cef_entry[0] == "device_version" then @cef_hash["version"] = cef_entry[1]

          # Action
        elsif cef_entry[0] == "action" then @cef_hash["mitigation_method"] = cef_entry[1]

          # BIG-IP Route Domain
        elsif cef_entry[0] == "route_domain" then @cef_hash["route_domain"] = cef_entry[1]

          # Destination VLAN
        elsif cef_entry[0] == "vlan" then @cef_hash["destination_vlan"] = cef_entry[1]

          # Partition
        elsif cef_entry[0] == "partition_name" then @cef_hash["partition"] = cef_entry[1]

          # Context Name
        elsif cef_entry[0] == "context_name" then @cef_hash["context_name"] = cef_entry[1]

          # Belongs to TCP Flow ID
        elsif cef_entry[0] == "flow_id" then @cef_hash["tcp_flow_id"] = cef_entry[1]

          # Source IP
        elsif cef_entry[0] == "source_ip" then @cef_hash["attack_source_ip"] = cef_entry[1]

          # Source Port
        elsif cef_entry[0] == "source_port" then @cef_hash["attack_source_port"] = cef_entry[1]

          # Destination IP
        elsif cef_entry[0] == "dest_ip" then @cef_hash["attack_destination_ip"] = cef_entry[1]

          # Destination Port
        elsif cef_entry[0] == "dest_port" then @cef_hash["attack_destination_port"] = cef_entry[1]

          # Attack Name
        elsif cef_entry[0] == "dos_attack_name" then @cef_hash["attack_name"] = cef_entry[1]

          # Attack ID
        elsif cef_entry[0] == "dos_attack_id" then @cef_hash["attack_id"] = cef_entry[1]

          # Attack Event
        elsif cef_entry[0] == "dos_attack_event" then @cef_hash["attack_event"] = cef_entry[1]

          # Attack Type
        elsif cef_entry[0] == "errdefs_msg_name" then @cef_hash["attack_type"] = cef_entry[1]

          # Attack Type ID, we don't collect this so do next
        elsif cef_entry[0] == "errdefs_msgno" then next

          # Attack Severity
        elsif cef_entry[0] == "severity" then @cef_hash["attack_severity"] = cef_entry[1]

          # Packet Dropped
        elsif cef_entry[0] == "dos_packets_dropped" then @cef_hash["packet_dropped"] = cef_entry[1]

          # Packet Received
        elsif cef_entry[0] == "dos_packets_received" then @cef_hash["packet_received"] = cef_entry[1]

        else

            # Unknown cef_entry

        end

      end

    elsif message[0..2] == "CEF"

      # CEF format

      spl_message = message.split("|")

      @cef_hash["vendor"] = spl_message[1]
      @cef_hash["module"] = spl_message[2]
      @cef_hash["version"] = spl_message[3]
      @cef_hash["attack"] = spl_message[5]
      cef_data = spl_message[7]

      cef_data.scan(/[a-zA-Z0-9]+[=]+[a-zA-Z0-9:_\-\/\.\s]*(?=\s[a-zA-Z0-9]+[=]|$)/) do |cef_record|

        cef_entry = cef_record.split("=")

        if @cef_hash["module"] == "Advanced Firewall Module"


            # Device Host Name, FQDN
          if cef_entry[0] == "dvchost" then @cef_hash["bigip_hostname"] = cef_entry[1]

            # Device IP
          elsif cef_entry[0] == "dvc" then @cef_hash["bigip_ip"] = cef_entry[1]

            # Remote time
          elsif cef_entry[0] == "rt" then @cef_hash["bigip_time"] = cef_entry[1]

            # Action
          elsif cef_entry[0] == "act" then @cef_hash["mitigation_method"] = cef_entry[1]

            # Attack Source IP
          elsif cef_entry[0] == "src" then @cef_hash["attack_source_ip"] = cef_entry[1]

            # Attack Source Port
          elsif cef_entry[0] == "spt" then @cef_hash["attack_source_port"] = cef_entry[1]

            # Attack Destination IP
          elsif cef_entry[0] == "dst" then @cef_hash["attack_destination_ip"] = cef_entry[1]

            # Attack Destination Port
          elsif cef_entry[0] == "dpt" then @cef_hash["attack_destination_port"] = cef_entry[1]

            # BIG-IP Route Domain
          elsif cef_entry[0] == "F5RouteDomain" then @cef_hash["route_domain"] = cef_entry[1]

            # Belongs to TCP Flow ID
          elsif cef_entry[0] == "F5FlowID" then @cef_hash["tcp_flow_id"] = cef_entry[1]

          else

            # Dynamic CEF Entries

            cef_dyn_hash[cef_entry[0]] = cef_entry[1]

          end

        elsif @cef_hash["module"] == "ASM"

          if cef_entry[0] == "dvchost" then @cef_hash["bigip_hostname"] = cef_entry[1]

            # Device IP
          elsif cef_entry[0] == "dvc" then @cef_hash["bigip_ip"] = cef_entry[1]

            # Remote time
          elsif cef_entry[0] == "rt" then @cef_hash["remote_time"] = cef_entry[1]

            # Action
          elsif cef_entry[0] == "act" then @cef_hash["mitigation_method"] = cef_entry[1]

            # Attack Source IP
          elsif cef_entry[0] == "src" and cef_entry[1] != nil then @cef_hash["attack_source_ip"] = cef_entry[1]

          else

            # Dynamic CEF Entries

            cef_dyn_hash[cef_entry[0]] = cef_entry[1]

          end

        else

        end

      end

      # Need to loop through the cef_dyn_hash

      if cef_dyn_hash.length > 0

        cef_dyn2_hash = Hash.new

        cef_dyn_hash.keys.sort

        none_label_key = ""
        none_label_value = ""

        cef_dyn_hash.each do |key,value|

          if key !~ /Label/

            none_label_key = key
            if value != nil
              none_label_value = value
            end

            next

          end

          if key.include? "Label"

            if (none_label_key + "Label") == key

              cef_dyn2_hash[value] = none_label_value

              none_label_key = ""
              none_label_value = ""

              next

            end

          end

        end

        if cef_dyn2_hash.has_key?("source_address") and cef_dyn2_hash["source_address"] == ""

          if @cef_hash.has_key?("attack_source_ip") and @cef_hash["attack_source_ip"] != ""

            cef_dyn2_hash["source_address"] = @cef_hash["attack_source_ip"]

          else

            cef_dyn2_hash.delete("source_address")

          end

        end

        if cef_dyn2_hash.has_key?("destination_address") and cef_dyn2_hash["destination_address"] == ""

          if @cef_hash.has_key?("attack_destination_ip") and @cef_hash["attack_destination_ip"] != ""

            cef_dyn2_hash["destination_address"] = @cef_hash["attack_destination_ip"]

          end

        end

        @cef_hash.merge!(cef_dyn2_hash)

      end

    else

      # Unknown data format

    end

    return @cef_hash

	end
  
end # class LogStash::Inputs::F5Networks
