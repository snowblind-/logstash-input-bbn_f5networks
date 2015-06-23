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

class BBNCommon

  def self.logger(loglevel, function, message)

    logger = Logger.new("/var/log/bbn/logstash-plugins/bbn_f5networks.log", "daily")
    logger.progname = "logstash-input-bbn_f5networks"

    if loglevel == "INFO"

      logger.info("#{ function } reported the following message: #{ message }")

    elsif loglevel == "WARN"

      logger.warn("#{ function } reported the following message: #{ message }")

    elsif loglevel == "ERROR"

      logger.error("#{ function } reported the following message: #{ message }")

    elsif loglevel == "DEBUG"

      logger.debug("#{ function } reported the following message: #{ message }")

    else

      # Unknown log level, do nothing, just return for now
      logger.close
      return

    end

    logger.close

  end

  def self.to_utc(dt,offset)

    tdt = DateTime.parse(dt)

    ndt = DateTime.new(tdt.year,tdt.month,tdt.day,tdt.hour,tdt.min,tdt.sec,offset)

    return ndt

  end

end

class Object
  def is_number?
    self.to_f.to_s == self.to_s || self.to_i.to_s == self.to_s
  end
end