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

Gem::Specification.new do |s|
  s.name = 'logstash-input-bbn_f5networks'
  s.version = '0.2.0'
  s.licenses = ['Apache License (2.0)']
  s.summary = "Logstash plugin used to recive and parse DDoS event from F5 BIG-IP"
  s.description = " N/A "
  s.authors = ["Baffin Bay Networks"]
  s.email = 'devops-github@buffinbaynetworks.com'
  s.homepage = "http://www.buffinbaynetworks.com"
  s.require_paths = ["lib"]

  # Files
  s.files = `git ls-files`.split($\)
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "input" }

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core', '= 1.5.0'
  s.add_runtime_dependency 'logstash-codec-plain'
  s.add_runtime_dependency 'stud'
  s.add_development_dependency 'logstash-devutils'
end
