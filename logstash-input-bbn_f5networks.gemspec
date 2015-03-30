##########################################################################################
# Copyright (C) 2015 Buffin Bay Networks, Inc - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited
# Proprietary and confidential
# Written by Devops <devops-github@baffinbaynetworks.com>, March 2015
##########################################################################################

Gem::Specification.new do |s|
  s.name = 'logstash-input-bbn_f5networks'
  s.version = '0.1.0'
  s.licenses = ['Copyright (C) 2015 Buffin Bay Networks, Inc - All Rights Reserved']
  s.summary = "Logstash plugin used to recive and parse DDoS event from F5 BIG-IP"
  s.description = " N/A "
  s.authors = ["Baffin Bay Networks"]
  s.email = 'devops-github@buffinbaynetworks.com'
  s.homepage = "http://www.buffinbaynetworks.com/plugins/logstash"
  s.require_paths = ["lib"]

  # Files
  s.files = `git ls-files`.split($\)
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "input" }

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core', '= 1.5.0.rc2'
  s.add_runtime_dependency 'logstash-codec-plain'
  s.add_runtime_dependency 'stud'
  s.add_development_dependency 'logstash-devutils'
end
