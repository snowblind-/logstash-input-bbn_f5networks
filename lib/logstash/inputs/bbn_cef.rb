class BBNCef

  def self.parse_cef(event)

    @response = Hash.new()
    cef_message = Hash.new()
    cef_dynamic_message = Hash.new()

    client = Elasticsearch::Client.new

    message = event["message"]

    spl_cef = message.split("|")

    cef_message["device_vendor"] = spl_cef[1]
    cef_message["device_module"] = spl_cef[2]
    cef_message["device_version"] = spl_cef[3]

    if cef_message["device_module"] == "Advanced Firewall Module"

      cef_message["attack_name"] = spl_cef[5]

    elsif cef_message["device_module"] == "ASM"

      cef_message["attack_name"] = spl_cef[4]
      cef_message["attack_mitigation_method"] = spl_cef[5]

    end

    if spl_cef.count == 8

      cef_data = spl_cef[7]

    else

      return @response

    end

    cef_data.scan(/[a-zA-Z0-9]+[=]+[a-zA-Z0-9:_\-\/\.\s]*(?=\s[a-zA-Z0-9]+[=]|$)/) do |cef_record|

      cef_entry = cef_record.split("=")

      if cef_message["device_module"] == "Advanced Firewall Module"

        cef_message["attack_category"] = "Network DoS Event"

        if cef_entry[0] == "dvchost" and cef_entry[1] != nil then cef_message["device_hostname"] = cef_entry[1]

        elsif cef_entry[0] == "dvc" and cef_entry[1] != nil then cef_message["device_ip"] = cef_entry[1]

        elsif cef_entry[0] == "rt" and cef_entry[1] != nil then cef_message["device_time"] = cef_entry[1]

        elsif cef_entry[0] == "F5RouteDomain" and cef_entry[1] != nil then cef_message["virtual_routing_table"] = cef_entry[1]

        elsif cef_entry[0] == "F5FlowID" and cef_entry[1] != nil then cef_message["flow_table_id"] = cef_entry[1]

        elsif cef_entry[0] == "act" and cef_entry[1] != nil then cef_message["attack_mitigation_action"] = cef_entry[1]

        elsif cef_entry[0] == "src" and cef_entry[1] != nil then cef_message["attack_source_ip"] = cef_entry[1]

        elsif cef_entry[0] == "spt" and cef_entry[1] != nil then cef_message["attack_source_port"] = cef_entry[1]

        elsif cef_entry[0] == "dst" and cef_entry[1] != nil then cef_message["attack_destination_ip"] = cef_entry[1]

        elsif cef_entry[0] == "dpt" and cef_entry[1] != nil then cef_message["attack_destination_port"] = cef_entry[1]

        else

          # The rest is CEF Dynamic Labels, collect and parse later
          cef_dynamic_message[cef_entry[0]] = cef_entry[1]

        end

      elsif cef_message["device_module"] == "ASM"

        cef_message["attack_category"] = "Application DoS Event"

        if cef_entry[0] == "dvchost" and cef_entry[1] != nil then cef_message["device_hostname"] = cef_entry[1]

        elsif cef_entry[0] == "dvc" and cef_entry[1] != nil then cef_message["device_ip"] = cef_entry[1]

        elsif cef_entry[0] == "rt" and cef_entry[1] != nil then cef_message["device_time"] = cef_entry[1]

        elsif cef_entry[0] == "act" and cef_entry[1] != nil then cef_message["attack_mitigation_action"] = cef_entry[1]

        elsif cef_entry[0] == "src" and cef_entry[1] != nil then cef_message["attack_source_ip"] = cef_entry[1]

        elsif cef_entry[0] == "request" and cef_entry[1] != nil then cef_message["attack_request_resource"] = cef_entry[1]

        else

          # The rest is CEF Dynamic Labels, collect and parse later
          cef_dynamic_message[cef_entry[0]] = cef_entry[1]

        end

      else

        # Unknown module name
        cef_message.clear

        # Not sure when we would end up here
        BBNCommon.logger("Error", "parse_cef", "Unknown module name in CEF message")

        return @response

      end

    end

    # Need to loop through the cef_dynamic_message
    if cef_dynamic_message.length > 0

      cef_dynamic2_message = Hash.new

      cef_dynamic_message.keys.sort

      none_label_key = ""
      none_label_value = ""

      cef_dynamic_message.each do |key,value|

        if key !~ /Label/

          none_label_key = key
          if value != nil
            none_label_value = value
          end

          next

        end

        if key.include? "Label"

          if (none_label_key + "Label") == key

            cef_dynamic2_message[value] = none_label_value

            none_label_key = ""
            none_label_value = ""

            next

          end

        end

      end

      if cef_message["device_module"] == "Advanced Firewall Module"

        # Structure the dynamic CEF labels to fit the normalization objects

        cef_dynamic2_message.each do |key,value|

          if key == "dos_packets_received" and value != nil then cef_message["attack_detection_rate"] = value.to_i

          elsif key == "dos_packets_dropped" and value != nil then cef_message["attack_drop_rate"] = value.to_i

          elsif key == "virtual_name" and value != "" then cef_message["virtual_context"] = value

          elsif key == "vlan" and value != nil then cef_message["attack_destination_vlan"] = value

          elsif key == "attack_id" and value != nil then cef_message["attack_id"] = value

          elsif key == "attack_status" and value != nil then cef_message["attack_status"] = value

          elsif key == "traffic_stat_type" and value != nil then cef_message["traffic_stat_type"] = value

          elsif key == "traffic_stat_cnt" and value != nil then cef_message["traffic_stat_counter"] = value

          elsif key == "cookie_challenge_issued" and value != nil then cef_message["cookie_challenge_issued"] = value

          elsif key == "cookie_challenge_passed" and value != nil then cef_message["cookie_challenge_passed"] = value

          elsif key == "cookie_flow_accepted" and value != nil then cef_message["cookie_flow_accepted"] = value

          elsif key == "cookie_flow_rejected" and value != nil then cef_message["cookie_flow_rejected"] = value

          elsif key == "query_name" and value != nil then cef_message["attack_dns_query_name"] = value

          elsif key == "query_type" and value != nil then cef_message["attack_dns_query_type"] = value

          elsif key == "dos_attack_name" and value != nil then cef_message["tmp_attack_name"] = value

          elsif key == "destination_address" and value != "" then cef_message["attack_destination_ip"] = value

          elsif key == "source_address" and value != "" then cef_message["attack_source_ip"] = value

          else

            BBNCommon.logger("INFO", "parse_cef:AFM", "Unknown key/value pairs or key we dont normalizing for AFM #{key} = #{value}")

          end

        end

        if cef_message["attack_name"] == "DNS Event" and cef_message.has_key?("attack_dns_query_type")

          cef_message["attack_category"] = cef_message["attack_name"]

          if cef_message.has_key?("tmp_attack_name")

            cef_message["attack_name"] = cef_message["tmp_attack_name"]

            cef_message.delete("tmp_attack_name")

          end

          if cef_message.has_key?("virtual_context")

            cef_message["attack_mitigation_method"] = "Virtual Server Rate Limiting"

          end

        end

        if cef_message.has_key?("attack_name") and cef_message["attack_status"] == "TCP Syncookie"

          cef_message["attack_name"] = "TCP SYN flood"

          cef_message["attack_status"] = cef_message["attack_mitigation_action"]

          cef_message["attack_mitigation_action"] = "Cryptographic SYN Cookie"

          cef_message["attack_mitigation_method"] = "Virtual Server SYN Cookie"

        end

        if cef_message["attack_mitigation_action"] == "Drop" and cef_message["attack_category"] != "DNS Event" and cef_message["attack_name"] != "Flood attack" and cef_message["attack_name"] != "Sweep attack"

          cef_message["attack_mitigation_method"] = "Device-Wide Rate Limiting"

        elsif cef_message["attack_mitigation_action"] == "Allow" and cef_message["attack_category"] != "DNS Event" and cef_message["attack_name"] != "Flood attack" and cef_message["attack_name"] != "Sweep attack"

          cef_message["attack_mitigation_method"] = "Device-Wide Detection"

        elsif cef_message["attack_mitigation_action"] == "Drop" and cef_message["attack_name"] == "Flood attack"

          cef_message["attack_mitigation_method"] = "Source-IP Rate Limiting"

        elsif cef_message["attack_mitigation_action"] == "Allow" and cef_message["attack_name"] == "Flood attack"

          cef_message["attack_mitigation_method"] = "Source-IP Detection"

        elsif cef_message["attack_mitigation_action"] == "Drop" and cef_message["attack_name"] == "Sweep attack"

          cef_message["attack_mitigation_method"] = "Source-IP Rate Limiting"

        elsif cef_message["attack_mitigation_action"] == "Allow" and cef_message["attack_name"] == "Sweep attack"

          cef_message["attack_mitigation_method"] = "Source-IP Detection"

        end

        if cef_message["attack_status"] == "Attack Started"

          start_hash = {
              "customer_id" => 0,
              "device_vendor" => "",
              "device_module" => "",
              "device_version" => "",
              "device_hostname" => "",
              "device_ip" => "",
              "device_time" => "",
              "device_utc_offset" => event["utc_offset"],
              "virtual_context" => "",
              "virtual_routing_table" => "",
              "administration_partition" => "",
              "flow_table_id" => "",
              "attack_mlp" => 0,
              "attack_name" => "",
              "attack_id" => 0,
              "attack_type" => 1,
              "attack_status" => "",
              "attack_severity" => 0,
              "attack_category" => "",
              "attack_ongoing" => 1,
              "attack_start_date" => "",
              "unknown_key_value_pair" => "",
              "record_type" => "attacks",
              "remote_log_format" => "CEF",
              "remote_log_payload" => message
          }

          # Construct the start_hash
          cef_message.each do |key,value|

            if key == "device_vendor" and value != nil then start_hash["device_vendor"] = value

            elsif key == "device_module" and value != nil then start_hash["device_module"] = value

            elsif key == "device_version" and value != nil then start_hash["device_version"] = value

            elsif key == "device_hostname" and value != nil then start_hash["device_hostname"] = value

            elsif key == "device_ip" and value != nil then start_hash["device_ip"] = value

            elsif key == "device_time" and value != nil then start_hash["device_time"] = value

            elsif key == "virtual_context" and value != "" then start_hash["virtual_context"] = value

            elsif key == "virtual_routing_table" and value != nil then start_hash["virtual_routing_table"] = value

            elsif key == "administration_partition" and value != nil then start_hash["administration_partition"] = value

            elsif key == "flow_table_id" and value != nil then start_hash["flow_table_id"] = value

            elsif key == "attack_name" and value != nil then start_hash["attack_name"] = value

            elsif key == "attack_id" and value != nil then start_hash["attack_id"] = value

            elsif key == "attack_status" and value != nil then start_hash["attack_status"] = value

            elsif key == "attack_severity" and value != nil then start_hash["attack_severity"] = value

            elsif key == "attack_category" and value != nil then start_hash["attack_category"] = value

            end

          end

          if start_hash["device_time"] != ""

            start_hash["device_time"] = BBNCommon.to_utc(start_hash["device_time"], event["utc_offset"])
            start_hash["attack_start_date"] = start_hash["device_time"]

          end

          @response["start_hash"] = start_hash

        elsif cef_message["attack_status"] == "Attack Sampled"

          sample_hash = {
              "customer_id" => 0,
              "attack_id" => 0,
              "attack_type" => 1,
              "device_time" => "",
              "device_utc_offset" => event["utc_offset"],
              "attack_status" => "",
              "attack_detection_rate" => 0,
              "attack_detection_matrix" => "TPS",
              "attack_drop_rate" => 0,
              "attack_drop_matrix" => "TPS",
              "attack_mitigation_method" => "",
              "attack_mitigation_action" => "",
              "attack_request_resource" => "",
              "attack_dns_query_name" => "",
              "attack_dns_query_type" => "",
              "attack_source_ip" => "",
              "attack_source_port" => "",
              "attack_source_vlan" => "",
              "attack_destination_ip" => "",
              "attack_destination_port" => "",
              "attack_destination_vlan" => "",
              "record_type" => "attack_mitigation_stats",
              "remote_log_format" => "CEF",
              "remote_log_payload" => message
          }

          cef_message.each do |key,value|

            if key == "device_time" and value != nil then sample_hash["device_time"] = value

            #elsif key == "device_module" and value != nil then sample_hash["device_module"] = value

            #elsif key == "device_version" and value != nil then sample_hash["device_version"] = value

            #elsif key == "device_hostname" and value != nil then sample_hash["device_hostname"] = value

            #elsif key == "device_ip" and value != nil then sample_hash["device_ip"] = value

            elsif key == "device_time" and value != nil then sample_hash["device_time"] = value

            elsif key == "virtual_context" and value != "" then sample_hash["virtual_context"] = value

            #elsif key == "virtual_routing_table" and value != nil then sample_hash["virtual_routing_table"] = value

            #elsif key == "administration_partition" and value != nil then sample_hash["administration_partition"] = value

            #elsif key == "flow_table_id" and value != nil then sample_hash["flow_table_id"] = value

            elsif key == "attack_name" and value != nil then sample_hash["attack_name"] = value

            elsif key == "attack_id" and value != nil then sample_hash["attack_id"] = value

            elsif key == "attack_status" and value != nil then sample_hash["attack_status"] = value

            elsif key == "attack_severity" and value != nil then sample_hash["attack_severity"] = value

            elsif key == "attack_category" and value != nil then sample_hash["attack_category"] = value

            elsif key == "attack_detection_rate" and value != nil then sample_hash["attack_detection_rate"] = value.to_i

            elsif key == "attack_detection_matrix" and value != nil then sample_hash["attack_detection_matrix"] = value

            elsif key == "attack_drop_rate" and value != nil then sample_hash["attack_drop_rate"] = value.to_i

            elsif key == "attack_drop_matrix" and value != nil then sample_hash["attack_drop_matrix"] = value

            elsif key == "attack_mitigation_method" and value != nil then sample_hash["attack_mitigation_method"] = value

            elsif key == "attack_mitigation_action" and value != nil then sample_hash["attack_mitigation_action"] = value

            elsif key == "attack_request_resource" and value != nil then sample_hash["attack_request_resource"] = value

            elsif key == "attack_dns_query_name" and value != nil then sample_hash["attack_dns_query_name"] = value

            elsif key == "attack_dns_query_type" and value != nil then sample_hash["attack_dns_query_type"] = value

            elsif key == "attack_source_ip" and value != nil then sample_hash["attack_source_ip"] = value

            elsif key == "attack_source_port" and value != nil then sample_hash["attack_source_port"] = value

            elsif key == "attack_source_vlan" and value != nil then sample_hash["attack_source_vlan"] = value

            elsif key == "attack_destination_ip" and value != nil then sample_hash["attack_destination_ip"] = value

            elsif key == "attack_destination_port" and value != nil then sample_hash["attack_destination_port"] = value

            elsif key == "attack_destination_vlan" and value != nil then sample_hash["attack_destination_vlan"] = value

            end

          end

          if sample_hash["device_time"] != ""

            sample_hash["device_time"] = BBNCommon.to_utc(sample_hash["device_time"], event["utc_offset"])

          end

          if sample_hash.has_key?("virtual_context") and sample_hash["virtual_context"] != ""

            sample_hash["attack_mitigation_method"] = "Virtual Server Rate Limiting"

            sample_hash.delete("virtual_context")

          else

            if sample_hash["attack_mitigation_action"] == "Drop" and sample_hash["attack_category"] != "DNS Event" and sample_hash["attack_name"] != "Flood attack" and sample_hash["attack_name"] != "Sweep attack"

              sample_hash["attack_mitigation_method"] = "Device-Wide Rate Limiting"

            elsif sample_hash["attack_mitigation_action"] == "Allow" and sample_hash["attack_category"] != "DNS Event" and sample_hash["attack_name"] != "Flood attack" and sample_hash["attack_name"] != "Sweep attack"

              sample_hash["attack_mitigation_method"] = "Device-Wide Detection"

            elsif sample_hash["attack_mitigation_action"] == "Drop" and sample_hash["attack_name"] == "Flood attack"

              sample_hash["attack_mitigation_method"] = "Source-IP Rate Limiting"

            elsif sample_hash["attack_mitigation_action"] == "Allow" and sample_hash["attack_name"] == "Flood attack"

              sample_hash["attack_mitigation_method"] = "Source-IP Detection"

            elsif sample_hash["attack_mitigation_action"] == "Drop" and sample_hash["attack_name"] == "Sweep attack"

              sample_hash["attack_mitigation_method"] = "Source-IP Rate Limiting"

            elsif sample_hash["attack_mitigation_action"] == "Allow" and sample_hash["attack_name"] == "Sweep attack"

              sample_hash["attack_mitigation_method"] = "Source-IP Detection"

            end

          end

          #if sample_hash["attack_name"] == "" and sample_hash["attack_status"] == "TCP Syncookie"

          #  sample_hash["attack_name"] = "TCP SYN flood"

          #  sample_hash["attack_status"] = sample_hash["attack_mitigation_action"]

          #  sample_hash["attack_mitigation_action"] = "Cryptographic SYN Cookie"

          #  sample_hash["attack_mitigation_method"] = "Virtual Server SYN Cookie"

          #end

          #if sample_hash["attack_category"] == "Traffic Statistics"

          #  sample_hash["attack_name"] = sample_hash["attack_category"]

          #  sample_hash["attack_category"] = "Network DoS Event"

          #end

          @response["sample_hash"] = sample_hash


        elsif cef_message["attack_status"] == "Attack Stopped"

          stopped_hash = {
              "customer_id" => 0,
              "device_time" => "",
              "attack_id" => 0
          }

          record = nil
          entry = nil

          message.scan(/[a-zA-Z0-9_]+[=]+[a-zA-Z0-9:_\/\.\-\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/) do |record|

            entry = record.split("=")

            if entry[0] == "date_time" and entry[1] != nil then stopped_hash["device_time"] = entry[1]

            elsif entry[0] == "dos_attack_id" and entry[1] != nil then stopped_hash["attack_id"] = entry[1]

            end

          end

          if stopped_hash["device_time"] != ""

            stopped_hash["device_time"] = BBNCommon.to_utc(stopped_hash["device_time"], event["utc_offset"])

          end

          if stopped_hash["attack_id"] != 0

            begin

              rsp = client.search index: "bbn", type: "attacks", body: { query: { match: { attack_id: stopped_hash["attack_id"] } } }

              #rescue => e

            end

            mash = Hashie::Mash.new rsp

            if mash.has_key?("hits")

              if mash.hits.has_key?("total")

                if mash.hits.total == 1

                  begin

                    client.update index: "bbn", type: "attacks", id: mash.hits.hits.first._id, refresh: 1,
                                  body: { doc: { attack_ongoing: 0, attack_end_date: stopped_hash["device_time"] } }

                    #rescue => e

                  end

                elsif mash.hits.total > 1

                  # This means we have more then one attacks with same attack_id needs to be logged
                  BBNCommon.logger("INFO", "parse_cef", "more then one attack with attack_id: #{stopped_hash["attack_id"]}")

                elsif mash.hits.total < 1

                  # Did not return anything for attack_id needs to be logged
                  BBNCommon.logger("INFO", "parse_cef", "No attack with attack_id: #{stopped_hash["attack_id"]}")

                end

              else

                # Not sure when we would end up here
                BBNCommon.logger("INFO", "parse_cef", "got response data from ES but missing total _key for attack_id: #{stopped_hash["attack_id"]}")

              end

            else

              # Not sure when we would end up here
              BBNCommon.logger("INFO", "parse_cef", "Missing hits so therefore can not have total for attack_id: #{stopped_hash["attack_id"]}")

            end

          end

        end

      elsif cef_message["device_module"] == "ASM"

        # Structure the dynamic CEF labels to fit the normalization objects

        cef_dynamic2_message.each do |key,value|

          if key == "geo_location" and value != "" then cef_message["attack_geo_location_remote"] = value

          elsif key == "attack_status" and value != nil then cef_message["attack_status"] = value

          elsif key == "attack_id" and value != nil then cef_message["attack_id"] = value

          elsif key == "policy_apply_date" and value != nil then cef_message["policy_apply_date"] = value

          elsif key == "Virtual Server" and value != "" then cef_message["virtual_context"] = value

          elsif key == "policy_name" and value != nil then cef_message["policy_name"] = value

          elsif key == "detection_mode" and value != nil then cef_message["attack_detection_method"] = value

          elsif key == "detection_average" and value != nil then cef_message["attack_detection_rate"] = value.to_i

          elsif key == "dropped_requests" and value != nil then cef_message["attack_drop_rate"] = value.to_i

          else

            # Unknown key/value pairs or key's we don't care about normalizing
            BBNCommon.logger("DEBUG", "parse_cef", "Unknown key/value pairs or key's we dont care about normalizing for ASM #{key} = #{value}")

          end

        end

        if cef_message.has_key?("attack_detection_method") and cef_message["attack_detection_method"] == "TPS Increased"

          cef_message["attack_name"] = "HTTP Flood"


        elsif cef_message.has_key?("attack_detection_method") and cef_message["attack_detection_method"] == "Latency Increased"

          cef_message["attack_name"] = "HTTP Server Response Latency"

        end

        if cef_message["attack_status"] == "Attack started"

          start_hash = {
              "customer_id" => 0,
              "device_vendor" => "",
              "device_module" => "",
              "device_version" => "",
              "device_hostname" => "",
              "device_ip" => "",
              "device_time" => "",
              "device_utc_offset" => event["utc_offset"],
              "virtual_context" => "",
              "virtual_routing_table" => "",
              "administration_partition" => "",
              "flow_table_id" => "",
              "attack_mlp" => 0,
              "attack_name" => "",
              "attack_id" => 0,
              "attack_type" => 1,
              "attack_status" => "",
              "attack_severity" => 0,
              "attack_category" => "",
              "attack_ongoing" => 1,
              "attack_start_date" => "",
              "unknown_key_value_pair" => "",
              "record_type" => "attacks",
              "remote_log_format" => "CEF",
              "remote_log_payload" => message
          }

          sample_hash = {
              "customer_id" => 0,
              "attack_id" => 0,
              "attack_type" => 1,
              "device_time" => "",
              "device_utc_offset" => event["utc_offset"],
              "attack_status" => "",
              "attack_detection_rate" => 0,
              "attack_detection_matrix" => "TPS",
              "attack_detection_method" => "",
              "attack_drop_rate" => 0,
              "attack_drop_matrix" => "TPS",
              "attack_mitigation_method" => "",
              "attack_mitigation_action" => "",
              "attack_request_resource" => "",
              "attack_source_ip" => "",
              "record_type" => "attack_mitigation_stats",
              "remote_log_format" => "CEF",
              "remote_log_payload" => message
          }

          # Construct the start_hash and sample_hash all in one
          cef_message.each do |key,value|

            if key == "device_vendor" and value != nil then start_hash["device_vendor"] = value

            elsif key == "device_module" and value != nil then start_hash["device_module"] = value

            elsif key == "device_version" and value != nil then start_hash["device_version"] = value

            elsif key == "device_hostname" and value != nil then start_hash["device_hostname"] = value

            elsif key == "device_ip" and value != nil then start_hash["device_ip"] = value

            elsif key == "device_time" and value != nil then start_hash["device_time"] = value

            elsif key == "virtual_context" and value != "" then start_hash["virtual_context"] = value

            elsif key == "attack_name" and value != nil then start_hash["attack_name"] = value

            elsif key == "attack_id" and value != nil then start_hash["attack_id"] = value and sample_hash["attack_id"] = value

            elsif key == "attack_status" and value != nil then start_hash["attack_status"] = value

            elsif key == "attack_category" and value != nil then start_hash["attack_category"] = value

            elsif key == "attack_detection_rate" and value != nil then sample_hash["attack_detection_rate"] = value.to_i

            elsif key == "attack_detection_matrix" and value != nil then sample_hash["attack_detection_matrix"] = value

            elsif key == "attack_detection_method" and value != nil then sample_hash["attack_detection_method"] = value

            elsif key == "attack_drop_rate" and value != nil then sample_hash["attack_drop_rate"] = value.to_i

            elsif key == "attack_mitigation_method" and value != nil then sample_hash["attack_mitigation_method"] = value

            elsif key == "attack_mitigation_action" and value != nil then sample_hash["attack_mitigation_action"] = value

            elsif key == "attack_request_resource" and value != nil then sample_hash["attack_request_resource"] = value

            elsif key == "attack_source_ip" and value != nil then sample_hash["attack_source_ip"] = value

            end

          end

          if start_hash["device_time"] != ""

            start_hash["device_time"] = BBNCommon.to_utc(start_hash["device_time"], event["utc_offset"])
            start_hash["attack_start_date"] = start_hash["device_time"]

            sample_hash["device_time"] = start_hash["device_time"]

          end

          sample_hash["attack_status"] = "Mitigation stats"

          if start_hash.has_key?("virtual_context")

            vc = start_hash["virtual_context"]

            record = vc.scan(/\w+/)

            start_hash["administration_partition"] = record[0]

          end

          @response["start_hash"] = start_hash
          @response["sample_hash"] = sample_hash

        elsif cef_message["attack_status"] == "Mitigation stats"

          sample_hash = {
              "customer_id" => 0,
              "attack_id" => 0,
              "attack_type" => 1,
              "device_time" => "",
              "device_utc_offset" => event["utc_offset"],
              "attack_status" => "",
              "attack_detection_rate" => 0,
              "attack_detection_matrix" => "TPS",
              "attack_detection_method" => "",
              "attack_drop_rate" => 0,
              "attack_drop_matrix" => "TPS",
              "attack_mitigation_method" => "",
              "attack_mitigation_action" => "",
              "attack_request_resource" => "",
              "attack_source_ip" => "",
              "record_type" => "attack_mitigation_stats",
              "remote_log_format" => "CEF",
              "remote_log_payload" => message
          }

          # Construct the start_hash and sample_hash all in one
          cef_message.each do |key,value|

            if key == "attack_id" and value != nil then sample_hash["attack_id"] = value

            elsif key == "device_time" and value != nil then sample_hash["device_time"] = value

            elsif key == "attack_status" and value != nil then sample_hash["attack_status"] = value

            elsif key == "attack_detection_rate" and value != nil then sample_hash["attack_detection_rate"] = value.to_i

            elsif key == "attack_detection_matrix" and value != nil then sample_hash["attack_detection_matrix"] = value

            elsif key == "attack_detection_method" and value != nil then sample_hash["attack_detection_method"] = value

            elsif key == "attack_drop_rate" and value != nil then sample_hash["attack_drop_rate"] = value.to_i

            elsif key == "attack_mitigation_method" and value != nil then sample_hash["attack_mitigation_method"] = value

            elsif key == "attack_mitigation_action" and value != nil then sample_hash["attack_mitigation_action"] = value

            elsif key == "attack_request_resource" and value != nil then sample_hash["attack_request_resource"] = value

            elsif key == "attack_source_ip" and value != nil then sample_hash["attack_source_ip"] = value

            end

          end

          if sample_hash["device_time"] != ""

            sample_hash["device_time"] = BBNCommon.to_utc(sample_hash["device_time"], event["utc_offset"])
            sample_hash["attack_start_date"] = sample_hash["device_time"]

          end

          @response["sample_hash"] = sample_hash

        elsif cef_message["attack_status"] == "Mitigation changed"

          puts message

        elsif cef_message["attack_status"] == "Attack ended"

          stopped_hash = {
              "customer_id" => 0,
              "device_time" => "",
              "attack_id" => 0
          }

          cef_message.each do |key,value|

            if key == "attack_id" and value != nil then stopped_hash["attack_id"] = value

            elsif key == "device_time" and value != nil then stopped_hash["device_time"] = value

            end

          end

          if stopped_hash["device_time"] != ""

            stopped_hash["device_time"] = BBNCommon.to_utc(stopped_hash["device_time"], event["utc_offset"])

          end

          if stopped_hash["attack_id"] != 0

            begin

              rsp = client.search index: "bbn", type: "attacks", body: { query: { match: { attack_id: stopped_hash["attack_id"] } } }

              #rescue => e

            end

            mash = Hashie::Mash.new rsp

            if mash.has_key?("hits")

              if mash.hits.has_key?("total")

                if mash.hits.total == 1

                  begin

                    client.update index: "bbn", type: "attacks", id: mash.hits.hits.first._id, refresh: 1,
                                  body: { doc: { attack_ongoing: 0, attack_end_date: stopped_hash["device_time"] } }

                    #rescue => e

                  end

                elsif mash.hits.total > 1

                  # This means we have more then one attacks with same attack_id needs to be logged
                  BBNCommon.logger("INFO", "parse_cef:asm:attack_ended", "more then one attack with attack_id: #{stopped_hash["attack_id"]}")

                elsif mash.hits.total < 1

                  # Did not return anything for attack_id needs to be logged
                  BBNCommon.logger("INFO", "parse_cef:asm:attack_ended", "No attack with attack_id: #{stopped_hash["attack_id"]}")

                end

              else

                # Not sure when we would end up here
                BBNCommon.logger("INFO", "parse_cef:asm:attack_ended", "got response data from ES but missing total _key for attack_id: #{stopped_hash["attack_id"]}")

              end

            else

              # Not sure when we would end up here
              BBNCommon.logger("INFO", "parse_cef:asm:attack_ended", "Missing hits so therefore can not have total for attack_id: #{stopped_hash["attack_id"]}")

            end

          end

        end

      end

    end


    return @response

  end

end




