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

class BBNSyslog

  def self.parse_syslog(event)

    @response = Hash.new()
    client = Elasticsearch::Client.new

    message = event["message"]
    message.delete! '"'

    record = message.scan(/dos_attack_event=+[a-zA-Z0-9:_\/\.\-\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/)
    entry = record.to_s.split("=")

    if (entry[0].delete! '["') == "dos_attack_event" and (entry[1].delete! '"]') != nil

        # Attack Statistic for Ongoing Attack
      if entry[1] == "Attack Sampled"

        # Define sample_hash and fill the obvious ans set defaults
        sample_hash = {

            "remote_log_format" => "Syslog/Standard",
            "remote_log_payload" => message,
            "attack_id" => 0,
            "attack_status" => "",
            "attack_detection_rate" => 0,
            "attack_detection_matrix" => "",
            "attack_drop_rate" => 0,
            "attack_drop_matrix" => "",
            "attack_mitigation_method" => "",
            "attack_mitigation_action" => "",

            # If a L7DoS Event
            "attack_request_resource" => "",

            # If DNS DoS Event
            "attack_dns_query_name" => "",
            "attack_dns_query_type" => "",

            "attack_source_ip" => "",
            "attack_source_port" => "",
            "attack_source_vlan" => "",
            "attack_destination_ip" => "",
            "attack_destination_port" => "",
            "attack_destination_vlan" => "",
            "device_time" => "",
            "record_type" => "mitigation_stats"

        }

        record = nil
        entry = nil

        message.scan(/[a-zA-Z0-9_]+[=]+[a-zA-Z0-9:_\/\.\-\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/) do |record|

          entry = record.split("=")

          if entry[0] == "dos_attack_id" and entry[1] != nil then sample_hash["attack_id"] = entry[1]

          elsif entry[0] == "dos_attack_event" and entry[1] != nil then sample_hash["attack_status"] = entry[1]

          elsif entry[0] == "dos_packets_received" and entry[1] != nil then sample_hash["attack_detection_rate"] = entry[1]

          elsif entry[0] == "dos_packets_dropped" and entry[1] != nil then sample_hash["attack_drop_rate"] = entry[1]

          elsif entry[0] == "action" and entry[1] != nil then sample_hash["attack_mitigation_action"] = entry[1]

          elsif entry[0] == "dns_query_name" and entry[1] != nil then sample_hash["attack_dns_query_name"] = entry[1]

          elsif entry[0] == "dns_query_type" and entry[1] != nil then sample_hash["attack_dns_query_type"] = entry[1]

          elsif entry[0] == "source_ip" and entry[1] != nil then sample_hash["attack_source_ip"] = entry[1]

          elsif entry[0] == "source_port" and entry[1] != nil then sample_hash["attack_source_port"] = entry[1]

          elsif entry[0] == "dest_ip" and entry[1] != nil then sample_hash["attack_destination_ip"] = entry[1]

          elsif entry[0] == "dest_port" and entry[1] != nil then sample_hash["attack_destination_port"] = entry[1]

          elsif entry[0] == "vlan" and entry[1] != nil then sample_hash["attack_destination_vlan"] = entry[1]

          elsif entry[0] == "date_time" and entry[1] != nil then sample_hash["device_time"] = entry[1]

          elsif entry[0] == "context_name" and entry[1] != nil then sample_hash["bigip_virtual_server"] = entry[1]

          elsif entry[0] == "errdefs_msg_name" and entry[1] != nil then sample_hash["attack_category"] = entry[1]

          end

        end

        if sample_hash["attack_category"] == "DNS Event" and sample_hash["attack_dns_query_type"] != ""

          if sample_hash["bigip_virtual_server"] != ""

            sample_hash["attack_mitigation_method"] = "Virtual Server Rate Limiting"

          end

        end

        if sample_hash["attack_name"] == "" and sample_hash["attack_status"] == "TCP Syncookie"

          sample_hash["attack_name"] = "TCP SYN flood"

          sample_hash["attack_status"] = sample_hash["attack_mitigation_action"]

          sample_hash["attack_mitigation_action"] = "Cryptographic SYN Cookie"

          sample_hash["attack_mitigation_method"] = "Virtual Server SYN Cookie"

        end

        if sample_hash["attack_category"] == "Traffic Statistics"

          sample_hash["attack_name"] = sample_hash["attack_category"]

          sample_hash["attack_category"] = "Network DoS Event"

        end

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

        begin

          rsp = client.search index: "bbn", type: "attacks", body: { query: { match: { attack_id: sample_hash["attack_id"] } } }

          #rescue => e

        end

        mash = Hashie::Mash.new rsp

        if mash.has_key?("hits")

          if mash.hits.has_key?("total")

            if mash.hits.total == 1

              sample_counter = mash.hits.hits.first._source.attack_sample_counter
              sample_counter += 1

              src_ip = mash.hits.hits.first._source.attack_source_ip
              src_port = mash.hits.hits.first._source.attack_source_port
              dst_ip = mash.hits.hits.first._source.attack_destination_ip
              dst_port = mash.hits.hits.first._source.attack_destination_port

              if mash.hits.hits.first._source.attack_source_ip != sample_hash["attack_source_ip"]

                if mash.hits.hits.first._source.attack_source_ip == "multiple"

                  src_ip = "multiple"

                elsif mash.hits.hits.first._source.attack_source_ip == ""

                  src_ip = sample_hash["attack_source_ip"]

                end

              end

              if sample_hash["attack_source_port"].is_number? and mash.hits.hits.first._source.attack_source_port != sample_hash["attack_source_port"]

                if mash.hits.hits.first._source.attack_source_port == "multiple"

                  src_port = "multiple"

                elsif mash.hits.hits.first._source.attack_source_port == ""

                  src_port = sample_hash["attack_source_port"]

                end

              end

              if mash.hits.hits.first._source.attack_destination_ip != sample_hash["attack_destination_ip"]

                if mash.hits.hits.first._source.attack_destination_ip == "multiple"

                  dst_ip = "multiple"

                elsif mash.hits.hits.first._source.attack_destination_ip == ""

                  dst_ip = sample_hash["attack_destination_ip"]

                end

              end

              if sample_hash["attack_destination_port"].is_number? and mash.hits.hits.first._source.attack_destination_port != sample_hash["attack_destination_port"]

                if mash.hits.hits.first._source.attack_destination_port == "multiple"

                  dst_port = "multiple"

                elsif mash.hits.hits.first._source.attack_destination_port == ""

                  dst_port = sample_hash["attack_destination_port"]

                end

              end

              if sample_hash.has_key?("attack_mitigation_method")

                attack_mitigation_method = sample_hash["attack_mitigation_method"]

              else

                attack_mitigation_method = "Unknown"

              end

              begin

                client.update index: "bbn", type: "attacks", id: mash.hits.hits.first._id, refresh: 1,
                              body: { doc: { attack_event_counter: sample_counter, attack_source_ip: src_ip,
                              attack_source_port: src_port, attack_destination_ip: dst_ip, attack_destination_port: dst_port,
                              attack_mitigation_method: attack_mitigation_method} }

                #rescue => e

              end

              if sample_counter == 1

                mitigation_hash = Hash.new()
                mitigation_hash["attack_id"] = sample_hash["attack_id"]
                mitigation_hash["attack_mitigation_method"] = sample_hash["attack_mitigation_method"]
                mitigation_hash["device_time"] = sample_hash["device_time"]
                mitigation_hash["record_type"] = "mitigations"

                @response["mitigation_hash"] = mitigation_hash

              elsif sample_counter > 1

                # We need to verify that the mitigation_method has not changed, else create a new mitigation record
                # with the changed mitigation method, we do this based on device_time and latest known method

                begin

                  rsp = client.search index: "bbn", type: "mitigations", body: { query: { match: { attack_id: sample_hash["attack_id"] } } }

                  m = Hashie::Mash.new rsp

                  # First check how many mitigation methods we have for _id
                  if m.has_key?("hits")

                    if m.hits.has_key?("total")

                      if m.hits.total >= 1

                        mTotal =  m.hits.total - 1

                        # Verify that the mitigation method for the last device_time entry has not changed

                        if m.hits.hits[mTotal]._source.attack_mitigation_method != sample_hash["attack_mitigation_method"]

                          # Mitigation method changed so we need to update it

                          mitigation_hash = Hash.new()
                          mitigation_hash["attack_id"] = sample_hash["attack_id"]
                          mitigation_hash["attack_mitigation_method"] = sample_hash["attack_mitigation_method"]
                          mitigation_hash["device_time"] = sample_hash["device_time"]

                          @response["mitigation_hash"] = mitigation_hash

                        end

                      else

                        BBNCommon.logger("INFO", "attack_sampled", "sample_counter reported > 1 but did fine =< 1 when searching ES for attack_id: #{sample_hash["attack_id"]}")

                      end

                    end

                  end

                end

              end

            elsif mash.hits.total > 1

              # This means we have more then one attacks with same attack_id needs to be logged. This could potentially
              # happen when the Attack Start message has not reached elasticsearch just yet but we are processing a
              # attack sample message and therefor creating a new attacks entry using the attack sample data.

              # If this occurs we should delete the attack_mlp message once discovered

              BBNCommon.logger("INFO", "attack_sampled", "More then one entry in attacks with the same attack_id: #{sample_hash["attack_id"]}")

            elsif mash.hits.total < 1

              # Did not return anything for attack_id. This can occur if we have a midstream pick up of the logs
              # We need to created the attacks entry using attack sample data and set attack_mlp to 1 if config
              # attack_mlp is set to 1

              BBNCommon.logger("INFO", "attack_sampled", "No attack entry found for attack_id: #{sample_hash["attack_id"]}")

              if event["mlp_support"] == 1

                BBNCommon.logger("INFO", "attack_sampled", "Creating an MLP attack entry based on Attack Sampled message for attack_id: #{sample_hash["attack_id"]}")

                start_hash = {
                    "remote_log_format" => "Syslog/Standard",
                    "remote_log_payload" => message,
                    "customer_id" => 0,
                    "device_vendor" => "",
                    "device_module" => "",
                    "device_version" => "",
                    "device_hostname" => "",
                    "device_ip" => "",
                    "device_time" => "",
                    "device_utc_offset" => "",
                    "bigip_dos_policy" => "",
                    "bigip_virtual_server" => "",
                    "bigip_route_domain" => "",
                    "bigip_partition" => "",
                    "bigip_flow_table_id" => "",
                    "attack_name" => "",
                    "attack_id" => 0,
                    "attack_mlp" => 1,
                    "attack_status" => "Attack Started",
                    "attack_severity" => 0,
                    "attack_category" => "",
                    "attack_event_counter" => 1,
                    "attack_ongoing" => 1,
                    "attack_source_ip" => "",
                    "attack_source_port" => "",
                    "attack_destination_ip" => "",
                    "attack_destination_port" => "",
                    "attack_start_date" => "",
                    "unknown_key_value_pair" => "",
                    "record_type" => "attacks"
                }

                record = nil
                entry = nil

                message.scan(/[a-zA-Z0-9_]+[=]+[a-zA-Z0-9:_\/\.\-\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/) do |record|

                  entry = record.split("=")

                  if entry[0] == "device_vendor" and entry[1] != nil then start_hash["device_vendor"] = entry[1]

                  elsif entry[0] == "device_product" and entry[1] != nil then start_hash["device_module"] = entry[1]

                  elsif entry[0] == "device_version" and entry[1] != nil then start_hash["device_version"] = entry[1]

                  elsif entry[0] == "hostname" and entry[1] != nil then start_hash["device_hostname"] = entry[1]

                  elsif entry[0] == "bigip_mgmt_ip" and entry[1] != nil then start_hash["device_ip"] = entry[1]

                  elsif entry[0] == "date_time" and entry[1] != nil then start_hash["device_time"] = entry[1]

                  elsif entry[0] == "context_name" and entry[1] != nil then start_hash["bigip_virtual_server"] = entry[1]

                  elsif entry[0] == "route_domain" and entry[1] != nil then start_hash["bigip_route_domain"] = entry[1]

                  elsif entry[0] == "partition_name" and entry[1] != nil then start_hash["bigip_partition"] = entry[1]

                  elsif entry[0] == "flow_id" and entry[1] != nil then start_hash["bigip_flow_table_id"] = entry[1]

                  elsif entry[0] == "dos_attack_name" and entry[1] != nil then start_hash["attack_name"] = entry[1]

                  elsif entry[0] == "dos_attack_id" and entry[1] != nil then start_hash["attack_id"] = entry[1]

                  elsif entry[0] == "severity" and entry[1] != nil then start_hash["attack_severity"] = entry[1]

                  elsif entry[0] == "errdefs_msg_name" and entry[1] != nil then start_hash["attack_category"] = entry[1]

                  elsif entry[0] == "date_time" and entry[1] != nil then start_hash["attack_started"] = entry[1]

                  end

                end

                start_hash["attack_source_ip"] = sample_hash["attack_source_ip"]
                start_hash["attack_source_port"] = sample_hash["attack_source_port"]
                start_hash["attack_destination_ip"] = sample_hash["attack_destination_ip"]
                start_hash["attack_destination_port"] = sample_hash["attack_destination_port"]

                if sample_hash.has_key?("attack_mitigation_method")

                  start_hash["attack_mitigation_method"] = sample_hash["attack_mitigation_method"]

                end

                start_hash["attack_start_date"] = start_hash["device_time"]

                @response["start_hash"] = start_hash

                mitigation_hash = Hash.new()
                mitigation_hash["attack_id"] = sample_hash["attack_id"]
                mitigation_hash["attack_mitigation_method"] = sample_hash["attack_mitigation_method"]
                mitigation_hash["device_time"] = sample_hash["device_time"]

                @response["mitigation_hash"] = mitigation_hash

              else

                return @response

              end


            end

          else

            # Not sure when we would end up here
            BBNCommon.logger("INFO", "attack_sampled", "Got response data from ES but missing total _key for attack_id: #{sample_hash["attack_id"]}")

          end

        else

          # Not sure when we would end up here
          BBNCommon.logger("INFO", "attack_sampled", "Missing hits so therefore can not have total for attack_id: #{sample_hash["attack_id"]}")

        end

        @response["sample_hash"] = sample_hash

        # Attack Started
      elsif entry[1] == "Attack Started"

        # Define start_hash and fill the obvious and set defaults
        start_hash = {
            "remote_log_format" => "Syslog/Standard",
            "remote_log_payload" => message,
            "customer_id" => 0,
            "device_vendor" => "",
            "device_module" => "",
            "device_version" => "",
            "device_hostname" => "",
            "device_ip" => "",
            "device_time" => "",
            "device_utc_offset" => "",
            "bigip_dos_policy" => "",
            "bigip_virtual_server" => "",
            "bigip_route_domain" => "",
            "bigip_partition" => "",
            "bigip_flow_table_id" => "",
            "attack_name" => "",
            "attack_id" => 0,
            "attack_mlp" => 0,
            "attack_status" => "",
            "attack_severity" => 0,
            "attack_category" => "",
            "attack_event_counter" => 0,
            "attack_ongoing" => 1,
            "attack_start_date" => "",
            "unknown_key_value_pair" => "",
            "record_type" => "attacks"
        }

        record = nil
        entry = nil

        # Loop through the syslog message to get the rest
        message.scan(/[a-zA-Z0-9_]+[=]+[a-zA-Z0-9:_\/\.\-\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/) do |record|

          entry = record.split("=")

          if entry[0] == "device_vendor" and entry[1] != nil then start_hash["device_vendor"] = entry[1]

          elsif entry[0] == "device_product" and entry[1] != nil then start_hash["device_module"] = entry[1]

          elsif entry[0] == "device_version" and entry[1] != nil then start_hash["device_version"] = entry[1]

          elsif entry[0] == "hostname" and entry[1] != nil then start_hash["device_hostname"] = entry[1]

          elsif entry[0] == "bigip_mgmt_ip" and entry[1] != nil then start_hash["device_ip"] = entry[1]

          elsif entry[0] == "date_time" and entry[1] != nil then start_hash["device_time"] = entry[1]

          elsif entry[0] == "context_name" and entry[1] != nil then start_hash["bigip_virtual_server"] = entry[1]

          elsif entry[0] == "route_domain" and entry[1] != nil then start_hash["bigip_route_domain"] = entry[1]

          elsif entry[0] == "partition_name" and entry[1] != nil then start_hash["bigip_partition"] = entry[1]

          elsif entry[0] == "flow_id" and entry[1] != nil then start_hash["bigip_flow_table_id"] = entry[1]

          elsif entry[0] == "dos_attack_name" and entry[1] != nil then start_hash["attack_name"] = entry[1]

          elsif entry[0] == "dos_attack_id" and entry[1] != nil then start_hash["attack_id"] = entry[1]

          elsif entry[0] == "dos_attack_event" and entry[1] != nil then start_hash["attack_status"] = entry[1]

          elsif entry[0] == "severity" and entry[1] != nil then start_hash["attack_severity"] = entry[1]

          elsif entry[0] == "errdefs_msg_name" and entry[1] != nil then start_hash["attack_category"] = entry[1]

          elsif entry[0] == "date_time" and entry[1] != nil then start_hash["attack_started"] = entry[1]

          end

        end

        start_hash["attack_start_date"] = start_hash["device_time"]

        @response["start_hash"] = start_hash

        # Attack Stopped
      elsif entry[1] == "Attack Stopped"

        stopped_hash = {
          "device_time" => "",
          "attack_id" => 0
        }

        record = nil
        entry = nil

        message.scan(/[a-zA-Z0-9_]+[=]+[a-zA-Z0-9:_\/\.\-\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/) do |record|

          entry = record.split("=")

          # Collect data

          if entry[0] == "date_time" and entry[1] != nil then stopped_hash["device_time"] = entry[1]

          elsif entry[0] == "dos_attack_id" and entry[1] != nil then stopped_hash["attack_id"] = entry[1]

          end

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
                BBNCommon.logger("INFO", "attack_stopped", "more then one attack with attack_id: #{stopped_hash["attack_id"]}")

              elsif mash.hits.total < 1

                # Did not return anything for attack_id needs to be logged
                BBNCommon.logger("INFO", "attack_stopped", "No attack with attack_id: #{stopped_hash["attack_id"]}")

              end

            else

              # Not sure when we would end up here
              BBNCommon.logger("INFO", "attack_stopped", "got response data from ES but missing total _key for attack_id: #{stopped_hash["attack_id"]}")

            end

          else

            # Not sure when we would end up here
            BBNCommon.logger("INFO", "attack_stopped", "Missing hits so therefore can not have total for attack_id: #{stopped_hash["attack_id"]}")

          end

        end

        # SYNCheck Activated
      elsif entry[1] == "TCP Syncookie"

        syncookie_hash = {
            "remote_log_format" => "Syslog/Standard",
            "remote_log_payload" => message,
            "customer_id" => 0,
            "device_vendor" => "",
            "device_module" => "",
            "device_version" => "",
            "device_hostname" => "",
            "device_ip" => "",
            "device_time" => "",
            "device_utc_offset" => "",
            "bigip_dos_policy" => "",
            "bigip_virtual_server" => "",
            "bigip_route_domain" => "",
            "bigip_partition" => "",
            "bigip_flow_table_id" => "",
            "attack_name" => "",
            "attack_id" => 0,
            "attack_status" => "",
            "attack_severity" => 0,
            "attack_category" => "",
            "attack_event_counter" => 0,
            "attack_ongoing" => 0,
            "attack_start_date" => "",
            "unknown_key_value_pair" => ""
        }

        record = nil
        entry = nil

        # Loop through the syslog message to get the rest
        message.scan(/[a-zA-Z0-9_]+[=]+[a-zA-Z0-9:_\/\.\-\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/) do |record|

          entry = record.split("=")

          if entry[0] == "device_vendor" and entry[1] != nil then syncookie_hash["device_vendor"] = entry[1]

          elsif entry[0] == "device_product" and entry[1] != nil then syncookie_hash["device_module"] = entry[1]

          elsif entry[0] == "device_version" and entry[1] != nil then syncookie_hash["device_version"] = entry[1]

          elsif entry[0] == "hostname" and entry[1] != nil then syncookie_hash["device_hostname"] = entry[1]

          elsif entry[0] == "bigip_mgmt_ip" and entry[1] != nil then syncookie_hash["device_ip"] = entry[1]

          elsif entry[0] == "date_time" and entry[1] != nil then syncookie_hash["device_time"] = entry[1]

          elsif entry[0] == "action" and entry[1] != nil then syncookie_hash["attack_mitigation_action"] = entry[1]

          elsif entry[0] == "context_name" and entry[1] != nil then syncookie_hash["bigip_virtual_server"] = entry[1]

          elsif entry[0] == "route_domain" and entry[1] != nil then syncookie_hash["bigip_route_domain"] = entry[1]

          elsif entry[0] == "partition_name" and entry[1] != nil then syncookie_hash["bigip_partition"] = entry[1]

          elsif entry[0] == "flow_id" and entry[1] != nil then syncookie_hash["bigip_flow_table_id"] = entry[1]

          elsif entry[0] == "dos_attack_event" and entry[1] != nil then syncookie_hash["attack_status"] = entry[1]

          elsif entry[0] == "severity" and entry[1] != nil then syncookie_hash["attack_severity"] = entry[1]

          elsif entry[0] == "errdefs_msg_name" and entry[1] != nil then syncookie_hash["attack_category"] = entry[1]

          end

          syncookie_hash["attack_name"] = "TCP SYN flood"

          syncookie_hash["attack_status"] = syncookie_hash["attack_mitigation_action"]

          syncookie_hash["attack_mitigation_action"] = "Cryptographic SYN Cookie"

          syncookie_hash["attack_mitigation_method"] = "Per Virtual Server SYN Cookie"

        end

      else

        # Unknown DoS Event
        BBNCommon.logger("INFO", "Unknown", "Unknown DoS Event: #{message}")

      end

    else

      record = nil
      record = message.scan(/errdefs_msg_name=+[a-zA-Z0-9:_\/\.\-\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/)

      entry = record.to_s.split("=")

      if (entry[0].delete! '["') == "errdefs_msg_name" and (entry[1].delete! '"]') == "Traffic Statistics"

        # Traffic statistics

        # Can be either:
        # traffic_stat_type="Cryptographic SYN Cookie"
        # traffic_stat_type="Reaped Flow"
        # traffic_stat_type="Active Flow"
        # traffic_stat_type="Missed Flow"

      end

    end

    return @response

  end

end