# logstash-input-bbn_f5networks
Recives log messages from F5 BIG-IP over Syslog/CEF and parses them and output json blobs

## Installing a test system
Easist way to test the plugin would be to install a Ubuntu server.

## Installing dependencies
The following dependencies needs to be installed via apt-get

  sudo apt-get install git openjdk-7-jdk

## Install latest version of JRuby
All plugin development for logstash is done with JRuby. Install the latest version of JRuby (currently 1.7.19), can be found here: https://s3.amazonaws.com/jruby.org/downloads/1.7.19/jruby-bin-1.7.19.tar.gz 
  
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

Then create a file called jrubyenvvar.sh in <i>/etc/profile.d/</i> and add the follwoing line <i>export PATH=$PATH:$JRUBY_HOME/bin</i>

After that restart your server. Once server comes back up verify the <i>PATH</i> changes by typing <i>export</i>. You should see the output containg the foloowing:

<i>
  devops-github@devsrv10:~$ export<br>
  declare -x HOME="/home/devops-github"<br>
  declare -x JRUBY_HOME="/usr/local/lib/jruby-1.7.19"<br>
  ...<br>
  declare -x PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/lib/jruby-1.7.19/bin"<br>
  ...<br>
</i>

To be able to run the pre-compiled JRuby binaries in super-user mode you need to add them to the /usr/bin/ path manually (or any other secure_path on your system).

Simpliest way would be to create a sym link to the original file from /usr/bin/

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

Once you verified that <i>jruby, gem and jgem</i> runs without any errors you need to <i>install bundler and rspec via gem</i>. Run the follwoing commands to install the two packets.

<i>
  devops-github@devsrv10:~$ sudo gem install bundler  <br>
  devops-github@devsrv10:~$ sudo gem install rspec    <br>
</i>

## Installing Logstash
Then install >= logstash-1.5.0rc3. The plugin has been developed with this specific release of logstash.

The above logstash release can be found at: http://download.elasticsearch.org/logstash/logstash/packages/debian/logstash_1.5.0.rc3-1_all.deb

<i>
  devops-github@devsrv10:~$ sudo dpkg -i <u>path-to-logstash_1.5.0.rc3-1_all.deb</u> <br>
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
  Username for 'https://github.com':<br>
  Password for 'https://bbn-github@github.com':<br>
  remote: Counting objects: 317, done.<br>
  remote: Compressing objects: 100% (165/165), done.<br>
  remote: Total 317 (delta 82), reused 0 (delta 0), pack-reused 90<br>
  Receiving objects: 100% (317/317), 44.67 KiB | 0 bytes/s, done.<br>
  Resolving deltas: 100% (111/111), done.<br>
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

This will install the nessesary gem dependencies for the plugin.

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
        	bbn_f5networks {
        		log_collector_ip => "172.16.21.41"
        		log_collector_port => 1514
        		log_collector_protocol => [ "udp", "tcp" ]
        		default_health_string => "default send string"
        	}<br>
}<br>
<br>
output {<br>
        stdout {<br>
                codec => rubydebug<br>
        }<br>
}<br>
</i>

This will setup a udp_listener for port 6343 on IP 172.16.21.41. Change the IP to reflect an IP on your system that you want the listener to use.

The output used by the configuration is stdout with rubydebug codec. It's just for testing. Select a desired output plugin if different from above.

Save and exit the file.

To execute Logstash with the configuration run the following command

<i>
  devops-github@devsrv10:~/logstash-input-bbn_f5networks$ sudo /opt/logstash/bin/logstash -f /etc/logstash/conf.d/bbn.conf<br>
</i>
