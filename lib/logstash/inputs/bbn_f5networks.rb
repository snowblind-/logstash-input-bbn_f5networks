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
  # The default health string from BIG-IP
  config :default_health_string, :validate => :string, :default => "default send string"
  # Use local geoip filter or BIG-IP geoip data in log message
  #config :local_geo_location, :validate => :boolean, :default => true
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

    @codec.decode(data) do |event|

      # In case BIG-IP is sending health status messages to the same port
      if data == default_health_string then
        next
      end

      parsed_event = parse_event(event)

      if parsed_event.has_key?("parser_error_no") || parsed_event.empty?
        next
      end

      new_event = LogStash::Event.new(parsed_event)
      decorate(new_event)
      queue << new_event

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

    @cef_hash = {"device_vendor"=>"n/a", "device_module"=>"n/a", "device_version"=>"n/a", "device_hostname"=>"n/a", "device_ip"=>"n/a", "device_time"=>"n/a", "bigip_dos_policy"=>"n/a", "bigip_policy_apply_date"=>"n/a", "bigip_virtual_server"=>"n/a", "bigip_route_domain"=>"n/a", "bigip_partition"=>"n/a", "flow_table_id"=>"n/a", "traffic_stat_type"=>"n/a", "traffic_stat_count"=>0, "cookie_challenge_issued"=>0, "cookie_challenge_passed"=>0, "cookie_flow_accepted"=>0, "cookie_flow_rejected"=>0, "attack_name"=>"n/a", "attack_id"=>0, "attack_status"=>"n/a", "attack_detection_rate"=>"n/a", "attack_drop_rate"=>"n/a", "attack_detection_method"=>"n/a", "attack_mitigation_method"=>"n/a", "attack_mitigation_action"=>"n/a", "attack_geo_location_local"=>"n/a", "attack_geo_location_remote"=>"n/a", "attack_source_ip"=>"n/a", "attack_source_port"=>0, "attack_source_vlan"=>"n/a", "attack_destination_ip"=>"n/a", "attack_destination_port"=>0, "attack_destination_vlan"=>"n/a", "attack_request_resource"=>"n/a", "attack_severity"=>0, "attack_category"=>"n/a", "attack_event_count"=>0, "attack_ongoing"=>0, "unknown_key_value_pairs"=>"n/a"}

    message = event["message"]

    if message[0..4] == "<134>"

      # Syslog format

      @cef_hash["raw_log_format"] = "Syslog/Standard"

      cef_data = message
      cef_data.delete! '"'

      cef_data.scan(/[a-zA-Z0-9_]+[=]+[a-zA-Z0-9:_\/\.\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/) do |cef_record|

        cef_entry = cef_record.split("=")

        ## GENERAL DEVICE INFO

        # Device vendor
        if cef_entry[0] == "device_vendor" and cef_entry[1] != nil then @cef_hash["device_vendor"] = cef_entry[1]

          # Device module
        elsif cef_entry[0] == "device_product" and cef_entry[1] != nil then @cef_hash["device_module"] = cef_entry[1]

          # Device Version
        elsif cef_entry[0] == "device_version" and cef_entry[1] != nil then @cef_hash["device_version"] = cef_entry[1]

          # Device Hostname, FQDN
        elsif cef_entry[0] == "hostname" and cef_entry[1] != nil then @cef_hash["device_hostname"] = cef_entry[1]

          # Device IP
        elsif cef_entry[0] == "bigip_mgmt_ip" and cef_entry[1] != nil then @cef_hash["device_ip"] = cef_entry[1]

          # Remote time
        elsif cef_entry[0] == "date_time" and cef_entry[1] != nil then @cef_hash["device_time"] = cef_entry[1]


          ## F5 SPECIFIC INFO

          # BIG-IP Route Domain
        elsif cef_entry[0] == "route_domain" and cef_entry[1] != nil then @cef_hash["bigip_route_domain"] = cef_entry[1]

          # BIG-IP Partition
        elsif cef_entry[0] == "partition_name" and cef_entry[1] != nil then @cef_hash["bigip_partition"] = cef_entry[1]

          # BIG-IP Virtual Server
        elsif cef_entry[0] == "context_name" and cef_entry[1] != nil then @cef_hash["bigip_virtual_server"] = cef_entry[1]

          ## FLOW TABLE ID

          # Flow Table ID for Session
        elsif cef_entry[0] == "flow_id" and cef_entry[1] != nil then @cef_hash["flow_table_id"] = cef_entry[1]


          ## ATTACK INFO

          # Attack Name
        elsif cef_entry[0] == "dos_attack_name" and cef_entry[1] != nil then @cef_hash["attack_name"] = cef_entry[1]

          # Attack ID
        elsif cef_entry[0] == "dos_attack_id" and cef_entry[1] != nil then @cef_hash["attack_id"] = cef_entry[1]

          # Attack Status, Attack Started, Attack Sampled, Attack Stopped
        elsif cef_entry[0] == "dos_attack_event" and cef_entry[1] != nil then @cef_hash["attack_status"] = cef_entry[1]

          # Packet Received
        elsif cef_entry[0] == "dos_packets_received" and cef_entry[1] != nil then @cef_hash["attack_detection_rate"] = cef_entry[1]

          # Packet Dropped
        elsif cef_entry[0] == "dos_packets_dropped" and cef_entry[1] != nil then @cef_hash["attack_drop_rate"] = cef_entry[1]

          # Action
        elsif cef_entry[0] == "action" and cef_entry[1] != nil then @cef_hash["attack_mitigation_action"] = cef_entry[1]

          # Source IP
        elsif cef_entry[0] == "source_ip" and cef_entry[1] != nil then @cef_hash["attack_source_ip"] = cef_entry[1]

          # Source Port
        elsif cef_entry[0] == "source_port" and cef_entry[1] != nil then @cef_hash["attack_source_port"] = cef_entry[1]

          # Destination IP
        elsif cef_entry[0] == "dest_ip" and cef_entry[1] != nil then @cef_hash["attack_destination_ip"] = cef_entry[1]

          # Destination Port
        elsif cef_entry[0] == "dest_port" and cef_entry[1] != nil then @cef_hash["attack_destination_port"] = cef_entry[1]

          # Destination VLAN
        elsif cef_entry[0] == "vlan" and cef_entry[1] != nil then @cef_hash["attack_destination_vlan"] = cef_entry[1]

          # Attack Severity
        elsif cef_entry[0] == "severity" and cef_entry[1] != nil then @cef_hash["attack_severity"] = cef_entry[1]

          # Attack Category e.g Network DoS Event
        elsif cef_entry[0] == "errdefs_msg_name" and cef_entry[1] != nil then @cef_hash["attack_category"] = cef_entry[1]

          # Traffic Stats entries
        elsif cef_entry[0] == "traffic_stat_type" and cef_entry[1] != nil then @cef_hash["traffic_stat_type"] = cef_entry[1]

        elsif cef_entry[0] == "traffic_stat_cnt" and cef_entry[1] != nil then @cef_hash["traffic_stat_count"] = cef_entry[1]

        elsif cef_entry[0] == "cookie_challenge_issued" and cef_entry[1] != nil then @cef_hash["cookie_challenge_issued"] = cef_entry[1]

        elsif cef_entry[0] == "cookie_challenge_passed" and cef_entry[1] != nil then @cef_hash["cookie_challenge_passed"] = cef_entry[1]

        elsif cef_entry[0] == "cookie_flow_accepted" and cef_entry[1] != nil then @cef_hash["cookie_flow_accepted"] = cef_entry[1]

        elsif cef_entry[0] == "cookie_flow_rejected" and cef_entry[1] != nil then @cef_hash["cookie_flow_rejected"] = cef_entry[1]

          # Attack Type ID, we don't collect this so do next
        elsif cef_entry[0] == "errdefs_msgno" then next

        else

          # Unknown cef_entry, log it so we know what we miss
          @logger.info("Unexpected field in event[message]", :unknown_cef_entry => "#{cef_entry[0]}:#{cef_entry[1]}")

        end

      end

      if @cef_hash["attack_name"] == "n/a" and @cef_hash["attack_status"] == "TCP Syncookie"

        @cef_hash["attack_name"] = "TCP SYN flood"

        @cef_hash["attack_status"] = @cef_hash["attack_mitigation_action"]

        @cef_hash["attack_mitigation_action"] = "Cryptographic SYN Cookie"

      end

      if @cef_hash["attack_category"] == "Traffic Statistics"

        @cef_hash["attack_name"] = @cef_hash["attack_category"]

        @cef_hash["attack_category"] = "Network DoS Event"

      end

      if @cef_hash["attack_mitigation_action"] == "Drop" and @cef_hash["attack_name"] != "Flood attack" and @cef_hash["attack_name"] != "Sweep attack"

        @cef_hash["attack_mitigation_method"] = "Device-Wide Rate Limiting"

      elsif @cef_hash["attack_mitigation_action"] == "Allow" and @cef_hash["attack_name"] != "Flood attack" and @cef_hash["attack_name"] != "Sweep attack"

        @cef_hash["attack_mitigation_method"] = "Device-Wide Detection"

      elsif @cef_hash["attack_mitigation_action"] == "Drop" and @cef_hash["attack_name"] == "Flood attack"

        @cef_hash["attack_mitigation_method"] = "Source-IP Rate Limiting"

      elsif @cef_hash["attack_mitigation_action"] == "Allow" and @cef_hash["attack_name"] == "Flood attack"

        @cef_hash["attack_mitigation_method"] = "Source-IP Detection"

      elsif @cef_hash["attack_mitigation_action"] == "Drop" and @cef_hash["attack_name"] == "Sweep attack"

        @cef_hash["attack_mitigation_method"] = "Source-IP Rate Limiting"

      elsif @cef_hash["attack_mitigation_action"] == "Allow" and @cef_hash["attack_name"] == "Sweep attack"

        @cef_hash["attack_mitigation_method"] = "Source-IP Detection"

      end

    elsif message[0..2] == "CEF"

      # CEF format

      @cef_hash["raw_log_format"] = "Syslog/CEF"

      cef_dyn_hash = Hash.new

      spl_message = message.split("|")

      @cef_hash["device_vendor"] = spl_message[1]
      @cef_hash["device_module"] = spl_message[2]
      @cef_hash["device_version"] = spl_message[3]

      if @cef_hash["device_module"] == "Advanced Firewall Module"

        @cef_hash["attack_name"] = spl_message[5]

      elsif @cef_hash["device_module"] == "ASM"

        @cef_hash["attack_name"] = spl_message[4]
        @cef_hash["attack_mitigation_method"] = spl_message[5]

      end

      if spl_message.count == 8
        cef_data = spl_message[7]
      else
        return @cef_hash.clear
      end

      cef_data.scan(/[a-zA-Z0-9]+[=]+[a-zA-Z0-9:_\-\/\.\s]*(?=\s[a-zA-Z0-9]+[=]|$)/) do |cef_record|

        cef_entry = cef_record.split("=")

        if @cef_hash["device_module"] == "Advanced Firewall Module"


          @cef_hash["attack_category"] = "Network DoS Event"

          # Device Hostname, FQDN
          if cef_entry[0] == "dvchost" and cef_entry[1] != nil then @cef_hash["device_hostname"] = cef_entry[1]

            # Device IP
          elsif cef_entry[0] == "dvc" and cef_entry[1] != nil then @cef_hash["device_ip"] = cef_entry[1]

            # Device time
          elsif cef_entry[0] == "rt" and cef_entry[1] != nil then @cef_hash["device_time"] = cef_entry[1]

            # BIG-IP Route Domain
          elsif cef_entry[0] == "F5RouteDomain" and cef_entry[1] != nil then @cef_hash["bigip_route_domain"] = cef_entry[1]

            # Belongs to TCP Flow ID
          elsif cef_entry[0] == "F5FlowID" and cef_entry[1] != nil then @cef_hash["flow_table_id"] = cef_entry[1]

            # Action
          elsif cef_entry[0] == "act" and cef_entry[1] != nil then @cef_hash["attack_mitigation_action"] = cef_entry[1]

            # Attack Source IP
          elsif cef_entry[0] == "src" and cef_entry[1] != nil then @cef_hash["attack_source_ip"] = cef_entry[1]

            # Attack Source Port
          elsif cef_entry[0] == "spt" and cef_entry[1] != nil then @cef_hash["attack_source_port"] = cef_entry[1]

            # Attack Destination IP
          elsif cef_entry[0] == "dst" and cef_entry[1] != nil then @cef_hash["attack_destination_ip"] = cef_entry[1]

            # Attack Destination Port
          elsif cef_entry[0] == "dpt" and cef_entry[1] != nil then @cef_hash["attack_destination_port"] = cef_entry[1]

          else

            # Dynamic CEF Entries

            cef_dyn_hash[cef_entry[0]] = cef_entry[1]

          end

        elsif @cef_hash["device_module"] == "ASM"

          @cef_hash["attack_category"] = "Application DoS Event"

          # Device Hostname, FQDN
          if cef_entry[0] == "dvchost" and cef_entry[1] != nil then @cef_hash["device_hostname"] = cef_entry[1]

            # Device IP
          elsif cef_entry[0] == "dvc" and cef_entry[1] != nil then @cef_hash["device_ip"] = cef_entry[1]

            # Device time
          elsif cef_entry[0] == "rt" and cef_entry[1] != nil then @cef_hash["device_time"] = cef_entry[1]

            # Action
          elsif cef_entry[0] == "act" and cef_entry[1] != nil then @cef_hash["attack_mitigation_action"] = cef_entry[1]

            # Attack Source IP
          elsif cef_entry[0] == "src" and cef_entry[1] != nil then @cef_hash["attack_source_ip"] = cef_entry[1]

            # Attack Source IP
          elsif cef_entry[0] == "request" and cef_entry[1] != nil then @cef_hash["attack_request_resource"] = cef_entry[1]

          else

            # Dynamic CEF Entries

            cef_dyn_hash[cef_entry[0]] = cef_entry[1]

          end

        else

          # Unknown module name

          @cef_hash.clear
          @cef_hash["parser_error_no"] = 101
          @cef_hash["parser_error_description"] = "Unknown module name in CEF descriptor"

          # Log the first 32 characters
          @logger.info("Unknown module name in CEF descriptor", :unknown_cef_module => "{module}:#{@cef_hash["module"]}")

          return @cef_hash

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

        if @cef_hash["device_module"] == "Advanced Firewall Module"

          # Structure the dynamic CEF labels to fit the normalization objects

          cef_dyn2_hash.each do |key,value|

            if key == "dos_packets_received" and value != nil then @cef_hash["attack_detection_rate"] = value

            elsif key == "dos_packets_dropped" and value != nil then @cef_hash["attack_drop_rate"] = value

            elsif key == "virtual_name" and value != nil then @cef_hash["bigip_virtual_server"] = value

            elsif key == "vlan" and value != nil then @cef_hash["attack_destination_vlan"] = value

            elsif key == "attack_id" and value != nil then @cef_hash["attack_id"] = value

            elsif key == "attack_status" and value != nil then @cef_hash["attack_status"] = value

            elsif key == "context_name" and value != nil then @cef_hash["bigip_virtual_server"] = value

            elsif key == "traffic_stat_type" and value != nil then @cef_hash["attack_status"] = value

            elsif key == "traffic_stat_type" and value != nil then @cef_hash["traffic_stat_type"] = value

            elsif key == "traffic_stat_cnt" and value != nil then @cef_hash["traffic_stat_count"] = value

            elsif key == "cookie_challenge_issued" and value != nil then @cef_hash["cookie_challenge_issued"] = value

            elsif key == "cookie_challenge_passed" and value != nil then @cef_hash["cookie_challenge_passed"] = value

            elsif key == "cookie_flow_accepted" and value != nil then @cef_hash["cookie_flow_accepted"] = value

            elsif key == "cookie_flow_rejected" and value != nil then @cef_hash["cookie_flow_rejected"] = value

            else

              # Unknown key/value pairs or key's we don't care about normalizing

            end

          end

          if @cef_hash["attack_name"] == "n/a" and @cef_hash["attack_status"] == "TCP Syncookie"

            @cef_hash["attack_name"] = "TCP SYN flood"

            @cef_hash["attack_status"] = @cef_hash["attack_mitigation_action"]

            @cef_hash["attack_mitigation_action"] = "Cryptographic SYN Cookie"

          end

          if @cef_hash["attack_mitigation_action"] == "Drop" and @cef_hash["attack_name"] != "Flood attack" and @cef_hash["attack_name"] != "Sweep attack"

            @cef_hash["attack_mitigation_method"] = "Device-Wide Rate Limiting"

          elsif @cef_hash["attack_mitigation_action"] == "Allow" and @cef_hash["attack_name"] != "Flood attack" and @cef_hash["attack_name"] != "Sweep attack"

            @cef_hash["attack_mitigation_method"] = "Device-Wide Detection"

          elsif @cef_hash["attack_mitigation_action"] == "Drop" and @cef_hash["attack_name"] == "Flood attack"

            @cef_hash["attack_mitigation_method"] = "Source-IP Rate Limiting"

          elsif @cef_hash["attack_mitigation_action"] == "Allow" and @cef_hash["attack_name"] == "Flood attack"

            @cef_hash["attack_mitigation_method"] = "Source-IP Detection"

          elsif @cef_hash["attack_mitigation_action"] == "Drop" and @cef_hash["attack_name"] == "Sweep attack"

            @cef_hash["attack_mitigation_method"] = "Source-IP Rate Limiting"

          elsif @cef_hash["attack_mitigation_action"] == "Allow" and @cef_hash["attack_name"] == "Sweep attack"

            @cef_hash["attack_mitigation_method"] = "Source-IP Detection"

          end

        elsif @cef_hash["device_module"] == "ASM"

          # Structure the dynamic CEF labels to fit the normalization objects

          puts cef_dyn2_hash

          cef_dyn2_hash.each do |key,value|

            if key == "geo_location" and value != nil then @cef_hash["attack_geo_location_remote"] = value

            elsif key == "attack_status" and value != nil then @cef_hash["attack_status"] = value

            elsif key == "attack_id" and value != nil then @cef_hash["attack_id"] = value

            elsif key == "policy_apply_date" and value != nil then @cef_hash["bigip_policy_apply_date"] = value

            elsif key == "Virtual Server" and value != nil then @cef_hash["bigip_virtual_server"] = value

            elsif key == "policy_name" and value != nil then @cef_hash["bigip_dos_policy"] = value

            elsif key == "detection_mode" and value != nil then @cef_hash["attack_detection_method"] = value

            elsif key == "detection_average" and value != nil then @cef_hash["attack_detection_rate"] = value

            elsif key == "dropped_requests" and value != nil then @cef_hash["attack_drop_rate"] = value

            else

              # Unknown key/value pairs or key's we don't care about normalizing

            end

          end

        end

      end

      if @cef_hash.has_key?("attack_detection_method") and @cef_hash["attack_detection_method"] == "TPS Increased"

        # HTTP Flood (by TPS)

        @cef_hash["mitigation_method"] = @cef_hash["attack"]
        @cef_hash["detection_method"] = @cef_hash["detection_mode"]

        @cef_hash["attack_name"] = "HTTP Flood"

        # Clean up the hash entries in cef_dyn2_hash has so they don't get merged into cef_hash

        @cef_hash.delete("attack")
        @cef_hash.delete("detection_mode")

      elsif @cef_hash.has_key?("detection_mode") and @cef_hash["detection_mode"] == "Latency Increased"

        # HTTP Latency Symptom
        @cef_hash["mitigation_method"] = @cef_hash["attack"]
        @cef_hash["detection_method"] = @cef_hash["detection_mode"]

        @cef_hash["attack_name"] = "HTTP Response Latency"

        # Clean up the hash entries in cef_dyn2_hash has so they don't get merged into cef_hash

        @cef_hash.delete("attack")
        @cef_hash.delete("detection_mode")

      end

    else

      # Unknown data format
      @cef_hash.clear
      @cef_hash["parser_error_no"] = 100
      @cef_hash["parser_error_description"] = "Unknown log format"

      # Log the first 32 characters
      @logger.info("Unknown log format", :unknown_log_format => "{message}:#{message[0..31]}")

      # Return the cef_hash hash containing the parser_error_no and description
      return @cef_hash

    end

    return @cef_hash

  end

end # class LogStash::Inputs::F5Networks
