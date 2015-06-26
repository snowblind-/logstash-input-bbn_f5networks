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

      if entry[1] == "Attack Sampled"

        sample_hash = {
            "customer_id" => 0,
            "attack_id" => 0,
            "attack_type" => 1,
            "device_time" => "",
            "device_utc_offset" => event["utc_offset"],
            "attack_status" => "",
            "attack_detection_rate" => 0,
            "attack_detection_matrix" => "PPS",
            "attack_drop_rate" => 0,
            "attack_drop_matrix" => "PPS",
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
            "remote_log_format" => "Syslog",
            "remote_log_payload" => message
        }

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

          elsif entry[0] == "context_name" and entry[1] != "" then sample_hash["virtual_context"] = entry[1]

          elsif entry[0] == "errdefs_msg_name" and entry[1] != nil then sample_hash["attack_category"] = entry[1]

          end

        end

        if sample_hash["device_time"] != ""

          sample_hash["device_time"] = BBNCommon.to_utc(sample_hash["device_time"], event["utc_offset"])

        end

        if sample_hash.has_key?("virtual_context") and sample_hash["virtual_context"] != ""

          sample_hash["attack_mitigation_method"] = "Virtual Server Rate Limiting"

          if sample_hash["attack_category"] == "DNS Event"

            sample_hash["attack_detection_matrix"] = "QPS"
            sample_hash["attack_drop_matrix"] = "QPS"

          end

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

        if sample_hash.has_key?("attack_name")
          sample_hash.delete("attack_name")
        end

        if sample_hash.has_key?("attack_category")
          sample_hash.delete("attack_category")
        end

        @response["sample_hash"] = sample_hash

        # Attack Started
      elsif entry[1] == "Attack Started"

        # Define start_hash and fill the obvious and set defaults
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
            "remote_log_format" => "Syslog",
            "remote_log_payload" => message
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

          elsif entry[0] == "context_name" and entry[1] != nil then start_hash["virtual_context"] = entry[1]

          elsif entry[0] == "route_domain" and entry[1] != nil then start_hash["virtual_routing_table"] = entry[1]

          elsif entry[0] == "partition_name" and entry[1] != nil then start_hash["administration_partition"] = entry[1]

          elsif entry[0] == "flow_id" and entry[1] != "0000000000000000" then start_hash["flow_table_id"] = entry[1]

          elsif entry[0] == "dos_attack_name" and entry[1] != nil then start_hash["attack_name"] = entry[1]

          elsif entry[0] == "dos_attack_id" and entry[1] != nil then start_hash["attack_id"] = entry[1]

          elsif entry[0] == "dos_attack_event" and entry[1] != nil then start_hash["attack_status"] = entry[1]

          elsif entry[0] == "severity" and entry[1] != nil then start_hash["attack_severity"] = entry[1]

          elsif entry[0] == "errdefs_msg_name" and entry[1] != nil then start_hash["attack_category"] = entry[1]

          end

        end

        if start_hash["device_time"] != ""

          start_hash["device_time"] = BBNCommon.to_utc(start_hash["device_time"], event["utc_offset"])

        end

        start_hash["attack_start_date"] = start_hash["device_time"]

        @response["start_hash"] = start_hash

        # Attack Stopped
      elsif entry[1] == "Attack Stopped"

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
            "remote_log_format" => "Syslog",
            "remote_log_payload" => message,
            "customer_id" => 0,
            "device_vendor" => "",
            "device_module" => "",
            "device_version" => "",
            "device_hostname" => "",
            "device_ip" => "",
            "device_time" => "",
            "device_utc_offset" => event["utc_offset"],
            "policy_name" => "",
            "virtual_context" => "",
            "virtual_routing_table" => "",
            "administration_partition" => "",
            "flow_table_id" => "",
            "attack_name" => "",
            "attack_id" => 0,
            "attack_type" => 1,
            "attack_mlp" => 0,
            "attack_status" => "",
            "attack_severity" => 0,
            "attack_category" => "",
            "attack_event_counter" => 0,
            "attack_ongoing" => 0,
            "attack_start_date" => "",
            "attack_end_date" => "",
            "unknown_key_value_pair" => "",
            "record_type" => "attacks"
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

          elsif entry[0] == "context_name" and entry[1] != nil then syncookie_hash["virtual_context"] = entry[1]

          elsif entry[0] == "route_domain" and entry[1] != nil then syncookie_hash["virtual_routing_table"] = entry[1]

          elsif entry[0] == "partition_name" and entry[1] != nil then syncookie_hash["administration_partition"] = entry[1]

          elsif entry[0] == "flow_id" and entry[1] != nil then syncookie_hash["flow_table_id"] = entry[1]

          elsif entry[0] == "dos_attack_event" and entry[1] != nil then syncookie_hash["attack_status"] = entry[1]

          elsif entry[0] == "severity" and entry[1] != nil then syncookie_hash["attack_severity"] = entry[1]

          elsif entry[0] == "errdefs_msg_name" and entry[1] != nil then syncookie_hash["attack_category"] = entry[1]

          end

        end

        syncookie_hash["attack_name"] = "TCP SYN flood"
        syncookie_hash["attack_status"] = syncookie_hash["attack_mitigation_action"]
        syncookie_hash["attack_mitigation_action"] = "Cryptographic SYN Cookie"
        syncookie_hash["attack_mitigation_method"] = "Per Virtual Server SYN Cookie"

        if syncookie_hash["device_time"] != ""

          syncookie_hash["device_time"] = BBNCommon.to_utc(syncookie_hash["device_time"], event["utc_offset"])

        end

        syncookie_hash["attack_start_date"] = syncookie_hash["device_time"]
        syncookie_hash["attack_end_date"] = syncookie_hash["device_time"]

        @response["syncookie_hash"] = syncookie_hash

      else

        # Unknown DoS Event
        BBNCommon.logger("INFO", "Unknown", "Unknown DoS Event: #{message}")

      end

    else

      record = nil
      record = message.scan(/errdefs_msg_name=+[a-zA-Z0-9:_\/\.\-\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/)

      entry = record.to_s.split("=")

      if (entry[0].delete! '["') == "errdefs_msg_name" and (entry[1].delete! '"]') == "Traffic Statistics"

        record = message.scan(/traffic_stat_type=+[a-zA-Z0-9:_\/\.\-\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/)
        entry = record.to_s.split("=")

        if (entry[0].delete! '["') == "traffic_stat_type" and (entry[1].delete! '"]') != nil

          if entry[1] == "Cryptographic SYN Cookie"

            trafficstats_hash = {
                "remote_log_format" => "Syslog",
                "remote_log_payload" => message,
                "device_utc_offset" => event["utc_offset"],
                "device_hostname" => "",
                "device_ip" => "",
                "virtual_context" => "",
                "device_time" => "",
                "device_module" => "",
                "device_vendor" => "",
                "device_version" => "",
                "administration_partition" => "",
                "traffic_stat_type" => "",
                "cookie_challenge_issued" => "",
                "cookie_challenge_passed" => "",
                "cookie_flow_accepted" => "",
                "cookie_flow_rejected" => "",
                "record_type" => "traffic_stats"
            }

            record = nil
            entry = nil

            # Loop through the syslog message to get the rest
            message.scan(/[a-zA-Z0-9_]+[=]+[a-zA-Z0-9:_\/\.\-\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/) do |record|

              entry = record.split("=")

              if entry[0] == "hostname" and entry[1] != nil then trafficstats_hash["device_hostname"] = entry[1]

              elsif entry[0] == "bigip_mgmt_ip" and entry[1] != nil then trafficstats_hash["device_ip"] = entry[1]

              elsif entry[0] == "context_name" and entry[1] != nil then trafficstats_hash["virtual_context"] = entry[1]

              elsif entry[0] == "date_time" and entry[1] != nil then trafficstats_hash["device_time"] = entry[1]

              elsif entry[0] == "device_product" and entry[1] != nil then trafficstats_hash["device_module"] = entry[1]

              elsif entry[0] == "device_vendor" and entry[1] != nil then trafficstats_hash["device_vendor"] = entry[1]

              elsif entry[0] == "device_version" and entry[1] != nil then trafficstats_hash["device_version"] = entry[1]

              elsif entry[0] == "partition_name" and entry[1] != nil then trafficstats_hash["administration_partition"] = entry[1]

              elsif entry[0] == "traffic_stat_type" and entry[1] != nil then trafficstats_hash["traffic_stat_type"] = entry[1]

              elsif entry[0] == "cookie_challenge_issued" and entry[1] != nil then trafficstats_hash["cookie_challenge_issued"] = entry[1]

              elsif entry[0] == "cookie_challenge_passed" and entry[1] != nil then trafficstats_hash["cookie_challenge_passed"] = entry[1]

              elsif entry[0] == "cookie_flow_accepted" and entry[1] != nil then trafficstats_hash["cookie_flow_accepted"] = entry[1]

              elsif entry[0] == "cookie_flow_rejected" and entry[1] != nil then trafficstats_hash["cookie_flow_rejected"] = entry[1]

              end

            end

            trafficstats_hash["device_time"] = BBNCommon.to_utc(trafficstats_hash["device_time"],event["utc_offset"])

            @response["trafficstats_hash"] = trafficstats_hash

          elsif entry[1] == "Reaped Flow"

            trafficstats_hash = {
                "remote_log_format" => "Syslog",
                "remote_log_payload" => message,
                "device_utc_offset" => event["utc_offset"],
                "device_hostname" => "",
                "device_ip" => "",
                "virtual_context" => "",
                "device_time" => "",
                "device_module" => "",
                "device_vendor" => "",
                "device_version" => "",
                "administration_partition" => "",
                "traffic_stat_type" => "",
                "traffic_stat_counter" => "",
                "record_type" => "traffic_stats"
            }

            record = nil
            entry = nil

            # Loop through the syslog message to get the rest
            message.scan(/[a-zA-Z0-9_]+[=]+[a-zA-Z0-9:_\/\.\-\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/) do |record|

              entry = record.split("=")

              if entry[0] == "hostname" and entry[1] != nil then trafficstats_hash["device_hostname"] = entry[1]

              elsif entry[0] == "bigip_mgmt_ip" and entry[1] != nil then trafficstats_hash["device_ip"] = entry[1]

              elsif entry[0] == "context_name" and entry[1] != nil then trafficstats_hash["virtual_context"] = entry[1]

              elsif entry[0] == "date_time" and entry[1] != nil then trafficstats_hash["device_time"] = entry[1]

              elsif entry[0] == "device_product" and entry[1] != nil then trafficstats_hash["device_module"] = entry[1]

              elsif entry[0] == "device_vendor" and entry[1] != nil then trafficstats_hash["device_vendor"] = entry[1]

              elsif entry[0] == "device_version" and entry[1] != nil then trafficstats_hash["device_version"] = entry[1]

              elsif entry[0] == "partition_name" and entry[1] != nil then trafficstats_hash["administration_partition"] = entry[1]

              elsif entry[0] == "traffic_stat_type" and entry[1] != nil then trafficstats_hash["traffic_stat_type"] = entry[1]

              elsif entry[0] == "traffic_stat_cnt" and entry[1] != nil then trafficstats_hash["traffic_stat_counter"] = entry[1]

              end

            end

            trafficstats_hash["device_time"] = BBNCommon.to_utc(trafficstats_hash["device_time"],event["utc_offset"])

            @response["trafficstats_hash"] = trafficstats_hash

          elsif entry[1] == "Active Flow"

            trafficstats_hash = {
                "remote_log_format" => "Syslog",
                "remote_log_payload" => message,
                "device_utc_offset" => event["utc_offset"],
                "device_hostname" => "",
                "device_ip" => "",
                "virtual_context" => "",
                "device_time" => "",
                "device_module" => "",
                "device_vendor" => "",
                "device_version" => "",
                "administration_partition" => "",
                "traffic_stat_type" => "",
                "traffic_stat_counter" => "",
                "record_type" => "traffic_stats"
            }

            record = nil
            entry = nil

            # Loop through the syslog message to get the rest
            message.scan(/[a-zA-Z0-9_]+[=]+[a-zA-Z0-9:_\/\.\-\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/) do |record|

              entry = record.split("=")

              if entry[0] == "hostname" and entry[1] != nil then trafficstats_hash["device_hostname"] = entry[1]

              elsif entry[0] == "bigip_mgmt_ip" and entry[1] != nil then trafficstats_hash["device_ip"] = entry[1]

              elsif entry[0] == "context_name" and entry[1] != nil then trafficstats_hash["virtual_context"] = entry[1]

              elsif entry[0] == "date_time" and entry[1] != nil then trafficstats_hash["device_time"] = entry[1]

              elsif entry[0] == "device_product" and entry[1] != nil then trafficstats_hash["device_module"] = entry[1]

              elsif entry[0] == "device_vendor" and entry[1] != nil then trafficstats_hash["device_vendor"] = entry[1]

              elsif entry[0] == "device_version" and entry[1] != nil then trafficstats_hash["device_version"] = entry[1]

              elsif entry[0] == "partition_name" and entry[1] != nil then trafficstats_hash["administration_partition"] = entry[1]

              elsif entry[0] == "traffic_stat_type" and entry[1] != nil then trafficstats_hash["traffic_stat_type"] = entry[1]

              elsif entry[0] == "traffic_stat_cnt" and entry[1] != nil then trafficstats_hash["traffic_stat_counter"] = entry[1]

              end

            end

            trafficstats_hash["device_time"] = BBNCommon.to_utc(trafficstats_hash["device_time"],event["utc_offset"])

            @response["trafficstats_hash"] = trafficstats_hash

          elsif entry[1] == "Missed Flow"

            trafficstats_hash = {
                "remote_log_format" => "Syslog",
                "remote_log_payload" => message,
                "device_utc_offset" => event["utc_offset"],
                "device_hostname" => "",
                "device_ip" => "",
                "virtual_context" => "",
                "device_time" => "",
                "device_module" => "",
                "device_vendor" => "",
                "device_version" => "",
                "administration_partition" => "",
                "traffic_stat_type" => "",
                "traffic_stat_counter" => "",
                "record_type" => "traffic_stats"
            }

            record = nil
            entry = nil

            # Loop through the syslog message to get the rest
            message.scan(/[a-zA-Z0-9_]+[=]+[a-zA-Z0-9:_\/\.\-\s]*(?=\s[a-zA-Z0-9_]+[=]|\])/) do |record|

              entry = record.split("=")

              if entry[0] == "hostname" and entry[1] != nil then trafficstats_hash["device_hostname"] = entry[1]

              elsif entry[0] == "bigip_mgmt_ip" and entry[1] != nil then trafficstats_hash["device_ip"] = entry[1]

              elsif entry[0] == "context_name" and entry[1] != nil then trafficstats_hash["virtual_context"] = entry[1]

              elsif entry[0] == "date_time" and entry[1] != nil then trafficstats_hash["device_time"] = entry[1]

              elsif entry[0] == "device_product" and entry[1] != nil then trafficstats_hash["device_module"] = entry[1]

              elsif entry[0] == "device_vendor" and entry[1] != nil then trafficstats_hash["device_vendor"] = entry[1]

              elsif entry[0] == "device_version" and entry[1] != nil then trafficstats_hash["device_version"] = entry[1]

              elsif entry[0] == "partition_name" and entry[1] != nil then trafficstats_hash["administration_partition"] = entry[1]

              elsif entry[0] == "traffic_stat_type" and entry[1] != nil then trafficstats_hash["traffic_stat_type"] = entry[1]

              elsif entry[0] == "traffic_stat_cnt" and entry[1] != nil then trafficstats_hash["traffic_stat_counter"] = entry[1]

              end

            end

            trafficstats_hash["device_time"] = BBNCommon.to_utc(trafficstats_hash["device_time"],event["utc_offset"])

            @response["trafficstats_hash"] = trafficstats_hash

          end

        end

      end

    end

    return @response

  end

end
