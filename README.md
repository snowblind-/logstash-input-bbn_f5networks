# logstash-input-bbn_f5networks
Logstash plugin used to receive and parse DDoS event from F5 BIG-IP via Syslog and CEF

## Installing a test system
Easiest way to test the plugin would be to install a Ubuntu server.

## Installing dependencies
The following dependencies needs to be installed via apt-get

  sudo apt-get install git openjdk-7-jdk

## Install latest version of JRuby
All plugin development for Logstash is done with JRuby. Install the latest version of JRuby (currently 1.7.19), can be found here: https://s3.amazonaws.com/jruby.org/downloads/1.7.19/jruby-bin-1.7.19.tar.gz 
  
Extract the file and put the entire directory in /usr/local/lib/.

<i>
  devops-github@devsrv10:~$ ls -la /usr/local/lib<br>
  total 20<br>
  drwxr-xr-x  5 root root  4096 Mar 22 05:56 .<br>
  drwxr-xr-x 10 root root  4096 Mar 22 05:43 ..<br>
  drwxr-xr-x  7 root root  4096 Jan 29 09:35 jruby-1.7.19<br>
</i>

Next step would be to add JRUBY_HOME and JRUBY_HOME/bin into your PATH environment variable.

Edit /etc/environment and add the following line to the top of the file <i>JRUBY_HOME="/usr/local/lib/jruby-1.7.19"</i>

Then create a file called jrubyenvvar.sh in <i>/etc/profile.d/</i> and add the following line <i>export PATH=$PATH:$JRUBY_HOME/bin</i>

After that restart your server. Once server comes back up verify the <i>PATH</i> changes by typing <i>export</i>. You should see the output containing the following:

<i>
  devops-github@devsrv10:~$ export<br>
  declare -x HOME="/home/devops-github"<br>
  declare -x JRUBY_HOME="/usr/local/lib/jruby-1.7.19"<br>
  ...<br>
  declare -x PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/lib/jruby-1.7.19/bin"<br>
  ...<br>
</i>

To be able to run the pre-compiled JRuby binaries in super-user mode you need to add them to the /usr/bin/ path manually (or any other secure_path on your system).

Simplest way would be to create a sym link to the original file from /usr/bin/

<i>
  devops-github@devsrv10:~$ sudo ln -s /usr/local/lib/jruby-1.7.19/bin/jruby /usr/bin/  <br>
  devops-github@devsrv10:~$ sudo ln -s /usr/local/lib/jruby-1.7.19/bin/gem /usr/bin/    <br>
  devops-github@devsrv10:~$ sudo ln -s /usr/local/lib/jruby-1.7.19/bin/jgem /usr/bin/   <br>
</i>

At this point you should be able to execute the jruby binary directly from the commandline without using the full path.

<i>
  devops-github@devsrv10:~$ jruby -v  <br>
  jruby 1.7.19 (1.9.3p551) 2015-01-29 20786bd on OpenJDK 64-Bit Server VM 1.7.0_75-b13 +jit [linux-amd64] <br>
</i>

Once you verified that <i>jruby, gem and jgem</i> runs without any errors you need to <i>install bundler and rspec via gem</i>. Run the following commands to install the two packets.

<i>
  devops-github@devsrv10:~$ sudo gem install bundler  <br>
  devops-github@devsrv10:~$ sudo gem install rspec    <br>
</i>

## Installing Logstash
Then install >= logstash-1.5.0.

The most current Logstash release can be found at: https://www.elastic.co/downloads/logstash

<i>
  devops-github@devsrv10:~$ sudo dpkg -i <u>path-to-logstash_<_verison_>>.deb</u> <br>
</i>

Logstash installs itself in /opt/logstash with binaries found in <i>/opt/logstash/bin/</i> and Gemfile found at <i>/opt/logstash/Gemfile</i>. This file is important and we will be covered later in the README file under "Configure Logstash Access to Plugin".

## Clone the latest repository of the plugin (master)
The lastes version of the plugin is easiest obtained by cloning the repository using git. When prompt for username and password type in your GitHub credentials.

<i>
  devops-github@devsrv10:~$ pwd<br>
  /home/devops-github<br>
  <br>
  devops-github@devsrv10:~$ git clone https://github.com/bbn-github/logstash-input-bbn_f5networks.git<br>
  Cloning into 'logstash-input-bbn_f5networks'...<br>
  remote: Counting objects: 702, done.<br>
  remote: Compressing objects: 100% (23/23), done.<br>
  remote: Total 702 (delta 10), reused 0 (delta 0), pack-reused 675<br>
  Receiving objects: 100% (702/702), 97.94 KiB | 0 bytes/s, done.<br>
  Resolving deltas: 100% (296/296), done.<br>
  Checking connectivity... done.<br>
</i>

This will install a directory with the sourcecode in your current directory

<i>
  devops-github@devsrv10:~$ ls -la<br>
  total 168180<br>
  drwxr-xr-x 9 devops-github devops-github    4096 Mar 30 02:13 .<br>
  drwxr-xr-x 3 root     root                  4096 Mar 22 05:46 ..<br>
  ...<br>
  drwxrwxr-x 5 devops-github devops-github    4096 Mar 30 02:14 logstash-input-bbn_f5networks<br>
  ...<br>
</i>


Move into the logstash-input-bbn_f5networks directory and install the bundle dependencies.

<i>
  devops-github@devsrv10:~/logstash-input-bbn_f5networks$ bundle install<br>
</i>

This will install the necessary gem dependencies for the plugin.

Test the dependencies by running the following command

<i>
  devops-github@devsrv10:~/logstash-input-bbn_f5networks$ bundle exec rspec<br>
</i>

If you don't get any errors running the two commands above you are finshed with the plugin installation.

## Configure Logstash Access to Plugin
The current version (RC3) of Logstash 1.5.0 has a problem with the plugin binary which stops you from installing the binary in the way it was intended to. We have been told that this will work in the GA release. Until then we have to run the plugin in the same way we do during developmemnt.

Edit Logstash Gem file and add the following line to the file right after the gemspec line.

<i>
  gem "logstash-input-bbn_f5networks", :path => "/home/devops-github/logstash-input-bbn_f5networks"
</i>

Save and exit the file and run the followoing command to have Logstash read in the new Gemfile.

<i>
  devops-github@devsrv10:~/logstash-input-bbn_f5networks$ sudo /opt/logstash/bin/plugin --no-verify<br>
</i>

## Creating a config file for Logstash
At this point you are ready to run Lostash with the new plugin.

Create a configuration file for Logstash by creating a file in the follwoing directory

devops-github@devsrv10:~/logstash-input-bbn_f5networks$ sudo vi /etc/logstash/conf.d/bbn.conf 

Add the follwoing configuration to the file

<i>
input {<br>

	# Using two plugins written by Baffin Bay Networks<br>
	# More info and documentatio on https://github.com/bbn-github<br><br>

	# Parsing Syslog/CEF log messages from F5 BIG-IP<br>
	bbn_f5networks {<br>
		log_collector_ip => "172.16.21.41"<br>
		log_collector_port => 1514<br>
        log_collector_protocol => [ "udp", "tcp" ]<br>
		mlp_support => 1<br><br>
	
		# We need to normalize time for events between  different<br>
		# devices. This is done by specifying the offset from UTC time per<br>
		# remote device IP. IP is eqaul the management IP of the BIG-IP even<br>
		# if a self IP is used for HSL logging.<br>
		explicit_utc_offset => ["172.16.21.40","+2"]<br><br>

		# This is a global configured value, applies to all remote BIG-IP's<br>
		default_health_string => "default send string"<br><br>

		# Overrides the global default_health_string for induvidual BIG-IP's<br>
		#remote_health_string => ["172.16.21.40"=>"default_health_string"]<br>
	}<br>
}<br><br>

filter {<br>

	mutate {<br>
   		remove_field => [ "@version" ]<br>
		remove_field => [ "@timestamp" ]<br>
  	}<br><br>

    # If you want to add geo location data to th events you need to<br>
    # download the goelitecity database and put it in /opt/logstash/<br>
	if [record_type] == "attack_mitigation_stats" {<br><br>

		if [attack_source_ip] != "" {<br><br>
			
			geoip {<br>
    				source => "attack_source_ip"<br>
    				target => "geoip"<br>
    				database =>"/opt/logstash/GeoLiteCity.dat"<br>
    				add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]<br>
    				add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]<br>
  			}<br><br>

			mutate {<br>
    				convert => [ "[geoip][coordinates]", "float" ]<br>
  			}<br><br>

		}<br><br>

	}<br><br>

}<br><br>

output {<br><br>

	# Only used for debug; in the case yu need to debug don't start logstash in daemon mode<br>
        # #sudo /opt/logstash/bin/logstash -f /etc/logstash/conf.d/bbn.conf<br>
        #stdout {<br>
        #       codec => rubydebug<br>
        #}<br><br>

	# Store data in elasticsearch<br>
	if [record_type] == "attack_mitigation_stats" {<br>
		 stdout {<br>
                        codec => rubydebug<br>
                }<br>
		elasticsearch {<br>
			host=>"localhost"<br>
			index=>"bbn"<br>
			document_type=>"attack_mitigation_stats"<br>
		}<br><br>

	 } else if [record_type] == "attacks" {<br>
        	stdout {<br>
                	codec => rubydebug<br>
        	}<br><br>

	       elasticsearch {<br>
                        host=>"localhost"<br>
                        index=>"bbn"<br>
                        document_type=>"attacks"<br>
                }<br><br>
        
	} else if [record_type] == "attack_mitigation_methods" {<br>
		 stdout {<br>
                        codec => rubydebug<br>
                }<br>
		elasticsearch {<br>
			host=>"localhost"<br>
			index=>"bbn"<br>
			document_type=>"attack_mitigation_methods"<br>
		}<br><br>

	} else if [record_type] == "traffic_stats" {<br>
                stdout {<br>
                        codec => rubydebug<br>
                }<br><br>

               elasticsearch {<br>
                        host=>"localhost"<br>
                        index=>"bbn"<br>
                        document_type=>"traffic_stats"<br>
                }<br><br>

	} else {<br>
		stdout {<br>
                	codec => rubydebug<br>
                }<br>
        }<br>
}<br>
</i>

This will setup a udp_listener and a tcp_listener for port 1514 on IP 172.16.21.41. Change the IP to reflect an IP on your system that you want the listener to use.

The default_health_string is what the BIG-IP sends during health check of the pool member used for hsl. We don't care about that packet and will drop it early in the parsing.

The output used by the configuration is stdout with rubydebug codec. It's just for testing. Select a desired output plugin if different from above.

Save and exit the file.


## Bulding the Elasticsearch index and define types

The f5networks plugin are using a predefined set of indexes and types. It's a good practice to define them in advance to make sure that the types are
correct and and defined and don't colide with other field names of different types.

We use the following indexes and types and be added to Elasticseach by running the below curl commands.

curl -XPUT 'http://localhost:9200/bbn/'

curl -XPUT "http://localhost:9200/bbn/_mapping/attacks" -d '
	{
		"attacks" : {
            "_source" : { "enabled" : "true" },
            "_timestamp" : { "enabled" : "true", "path" : "device_utc_time", "format" : "yyyy-MM-dd'\''T'\''HH:mm:ss'\''+'\''HH:mm" },
            "properties" : {
                "customer_id" : { "type" : "integer", "store" : "false" },
                "device_vendor" : { "type" : "string", "store" : "false" },
                "device_module" : { "type" : "string", "store" : "false" },
                "device_version" : { "type" : "string", "store" : "false" },
                "device_hostname" : { "type" : "string", "store" : "false" },
                "device_ip" : { "type" : "ip", "store" : "false" },
                "device_utc_time" : { "type" : "date", "format" : "yyyy-MM-dd'\''T'\''HH:mm:ss'\''+'\''HH:mm", "store" : "false" },
                "device_utc_offset" : { "type" : "byte", "store" : "false", "default" : 0 },
                "policy_name" : { "type" : "string", "store" : "false" },
                "policy_apply_date" : { "type" : "date", "format" : "yyyy-MM-dd'\''T'\''HH:mm:ss'\''+'\''HH:mm", "store" : "false" },
                "virtual_context" : { "type" : "string", "store" : "false" },
                "virtual_routing_table" : { "type" : "integer", "store" : "false", "default" : 0 },
                "administration_partition" : { "type" : "string", "store" : "false" },
                "flow_table_id" : { "type" : "string", "store" : "false" },
                "attack_mlp" : { "type" : "boolean", "store" : "false", "default" : 0 },
                "attack_name" : { "type" : "string", "store" : "false" },
                "attack_id" : { "type" : "long", "store" : "false" },
                "attack_type" : { "type" : "string", "store" : "false" },
                "attack_status" : { "type" : "string", "store" : "false" },
                "attack_severity" : { "type" : "byte", "store" : "false" },
                "attack_category" : { "type" : "string", "store" : "false" },
                "attack_event_counter" : { "type" : "integer", "store" : "false", "default" : 0 },
                "attack_ongoing" : { "type" : "boolean", "store" : "false" },
                "attack_mitigation_method" : { "type" : "string", "store" : "false", "default" : "Unknown" },
                "attack_source_ip" : { "type" : "string", "store" : "false", "default" : "0.0.0.0" },
                "attack_source_port" : { "type" : "string", "store" : "false", "default" : "0" },
                "attack_destination_ip" : { "type" : "string", "store" : "false", "default" : "0.0.0.0" },
                "attack_destination_port" : { "type" : "string", "store" : "false", "default" : "0" },
                "attack_start_date" : { "type" : "date", "format" : "yyyy-MM-dd'\''T'\''HH:mm:ss'\''+'\''HH:mm" },
                "attack_end_date" : { "type" : "date", "format" : "yyyy-MM-dd'\''T'\''HH:mm:ss'\''+'\''HH:mm" },
                "unknown_key_value_pair" : { "type" : "string", "store" : "false" },
                "forward_for" : { "type" : "ip", "store" : "false" },
				"forward_utc_time" : { "type" : "date", "format" : "yyyy-MM-dd'\''T'\''HH:mm:ss'\''+'\''HH:mm", "store" : "false" },
                "record_type" : { "type" : "string", "store" : "false" },
                "remote_log_format" : { "type" : "string", "store" : "false" },
                "remote_log_payload" : { "type" : "string", "store" : "false" }
            }
        }
    }'

curl -XPUT "http://localhost:9200/bbn/_mapping/attack_mitigation_methods" -d '
	{
		"attack_mitigation_methods" : {
        	"_source" : { "enabled" : "true" },
        	"_timestamp" : { "enabled" : "true", "path" : "device_utc_time", "format" : "yyyy-MM-dd'\''T'\''HH:mm:ss'\''+'\''HH:mm" },	
        	"properties" : {
        		"customer_id" : { "type" : "integer", "store" : "false" },
        		"device_utc_time" : { "type" : "date", "format" : "yyyy-MM-dd'\''T'\''HH:mm:ss'\''+'\''HH:mm", "store" : "false" },
        		"device_utc_offset" : { "type" : "byte", "store" : "false", "default" : 0 },
        		"attack_id" : { "type" : "long", "store" : "false" },
        		"attack_type" : { "type" : "string", "store" : "false" },
        		"attack_mitigation_method" : { "type" : "string", "store" : "false" },
        		"attack_mitigation_action" : { "type" : "string", "store" : "false" },
        		"forward_for" : { "type" : "ip", "store" : "false" },
				"forward_utc_time" : { "type" : "date", "format" : "yyyy-MM-dd'\''T'\''HH:mm:ss'\''+'\''HH:mm", "store" : "false" },
        		"record_type" : { "type" : "string", "store" : "false" }
        	}
        }
    }'
    
curl -XPUT "http://localhost:9200/bbn/_mapping/attack_mitigation_stats" -d '
	{
		"attack_mitigation_stats": {
        	"_source" : { "enabled" : "true" },
        	"_timestamp" : { "enabled" : "true", "path" : "device_utc_time", "format" : "yyyy-MM-dd'\''T'\''HH:mm:ss'\''+'\''HH:mm" },
        	"properties" : {
        		"customer_id" : { "type" : "integer", "store" : "false" },
        		"device_utc_time" : { "type" : "date", "format" : "yyyy-MM-dd'\''T'\''HH:mm:ss'\''+'\''HH:mm", "default" : "1970-01-01T00:00:00", "store" : "false" },
        		"device_utc_offset" : { "type" : "byte", "store" : "false", "default" : 0 },
        		"attack_id" : { "type" : "long", "store" : "false" },
        		"attack_type" : { "type" : "string", "store" : "false" },
        		"attack_status" : { "type" : "string", "store" : "false" },
        		"attack_severity" : { "type" : "integer", "store" : "false" },
        		"attack_detection_rate" : { "type" : "integer", "store" : "false" },
                "attack_detection_matrix" : { "type" : "string", "store" : "false" },
                "attack_detection_method" : { "type" : "string", "store" : "false" },
                "attack_drop_rate" : { "type" : "integer", "store" : "false" },
                "attack_drop_matrix" : { "type" : "string", "store" : "false" },
                "attack_mitigation_method" : { "type" : "string", "store" : "false" },
        		"attack_mitigation_action" : { "type" : "string", "store" : "false" },
        		"attack_request_resource" : { "type" : "string", "store" : "false" },
        		"attack_dns_query_name" : { "type" : "string", "store" : "false" },
                "attack_dns_query_type" : { "type" : "string", "store" : "false" },
                "attack_source_ip" : { "type" : "string", "store" : "false" },
                "attack_source_port" : { "type" : "string", "store" : "false" },
                "attack_source_vlan" : { "type" : "string", "store" : "false" },
                "attack_destination_ip" : { "type" : "string", "store" : "false" },
                "attack_destination_port" : { "type" : "string", "store" : "false" },
                "attack_destination_vlan" : { "type" : "string", "store" : "false" },
                "forward_for" : { "type" : "ip", "store" : "false" },
				"forward_utc_time" : { "type" : "date", "format" : "yyyy-MM-dd'\''T'\''HH:mm:ss'\''+'\''HH:mm", "store" : "false" },
        		"record_type" : { "type" : "string", "store" : "false" },
        		"remote_log_format" : { "type" : "string", "store" : "false" },
        		"remote_log_payload" : { "type" : "string", "store" : "false" }
        	}
        }
	}'

curl -XPUT "http://localhost:9200/bbn/_mapping/traffic_stats" -d '
	{
		"traffic_stats": {
        	"_source" : { "enabled" : "true" },
        	"_timestamp" : { "enabled" : "true", "path" : "device_utc_time", "format" : "yyyy-MM-dd'\''T'\''HH:mm:ss'\''+'\''HH:mm" },
        	"properties" : {
        		"customer_id" : { "type" : "integer", "store" : "false" },
        		"device_utc_time" : { "type" : "date", "format" : "yyyy-MM-dd'\''T'\''HH:mm:ss'\''+'\''HH:mm", "store" : "false" },
        		"device_utc_offset" : { "type" : "byte", "store" : "false", "default" : 0 },
        		"device_vendor" : { "type" : "string", "store" : "false" },
                "device_module" : { "type" : "string", "store" : "false" },
                "device_version" : { "type" : "string", "store" : "false" },
                "device_hostname" : { "type" : "string", "store" : "false" },
                "device_ip" : { "type" : "ip", "store" : "false" },
                "virtual_context" : { "type" : "string", "store" : "false" },
                "traffic_stat_type" : { "type" : "string", "store" : "false" },
                "traffic_stat_counter" : { "type" : "integer", "store" : "false" },
                "cookie_challenge_issued" : { "type" : "integer", "store" : "false" },
                "cookie_challenge_passed" : { "type" : "integer", "store" : "false" },
                "cookie_flow_accepted" : { "type" : "integer", "store" : "false" },
                "cookie_flow_rejected" : { "type" : "integer", "store" : "false" },
                "forward_for" : { "type" : "ip", "store" : "false" },
				"forward_utc_time" : { "type" : "date", "format" : "yyyy-MM-dd'\''T'\''HH:mm:ss'\''+'\''HH:mm", "store" : "false" },
                "record_type" : { "type" : "string", "store" : "false" },
                "remote_log_format" : { "type" : "string", "store" : "false" },
                "remote_log_payload" : { "type" : "string", "store" : "false" }
			}
		}
	}'


## Run Logstash with your new plugin and insert the data to Elasticseach

To execute Logstash with your newly added configuration run the following command

<i>
  devops-github@devsrv10:~/logstash-input-bbn_f5networks$ sudo /opt/logstash/bin/logstash -f /etc/logstash/conf.d/bbn.conf<br>
</i>
