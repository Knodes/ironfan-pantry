#
# Cookbook Name::       elasticsearch
# Description::         Finalizes the config, writes out the config files
# Recipe::              config
# Author::              GoTime, modifications by Infochimps
#
# Copyright 2010, GoTime
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

node[:elasticsearch][:keystore_password] = node[:keystore][:password]

template "/etc/elasticsearch/logging.yml" do
  source        "logging.yml.erb"
  mode          0644
end

template "/etc/elasticsearch/elasticsearch.in.sh" do
  source        "elasticsearch.in.sh.erb"
  mode          0644
  variables     :elasticsearch => node[:elasticsearch]
end

node[:elasticsearch][:seeds] = discover_all(:elasticsearch, :datanode).map(&:private_ip)
Chef::Log.warn("No elasticsearch seeds!") if node[:elasticsearch][:seeds].empty?
template "/etc/elasticsearch/elasticsearch.yml" do
  source        "elasticsearch.yml.erb"
  owner         "elasticsearch"
  group         "elasticsearch"
  mode          0644
  variables     ({
    :elasticsearch      => node[:elasticsearch],
    :aws                => node[:aws]
  })
end

%w[jetty-es-auth jetty-gzip jetty-hash-auth jetty-restrict-all jetty-restrict-writes jetty-ssl jetty-strong-ssl jetty].each do |jetty_conf|
  template File.join("/etc/elasticsearch", "#{jetty_conf}.xml") do
    source "#{jetty_conf}.xml.erb"
    owner "elasticsearch"
    group "elasticsearch"
    mode "0644"
  end
end

file "/etc/elasticsearch/keystore" do
  owner "elasticsearch"
  group "elasticsearch"
  mode "0600"
  action :create
  content Base64.decode64(data_bag_item('tls_keys', 'keystore')['keystore_base64'])
end

template "/etc/elasticsearch/realm.properties" do
  variables ({
               :users => node[:elasticsearch][:users],
             })
  source "realm.properties.erb"
  owner "elasticsearch"
  group "elasticsearch"
  mode "0600"
end

# FIXME: This should be in server as a subscription, but that isn't supported by the
#   new syntax, and the old syntax requires that the subscription only occur after
#   the declaration of its target (which will fail since config happens last.)
if ( node.elasticsearch.is_datanode && ( node.elasticsearch.server.run_state != 'stop') )
  template "/etc/elasticsearch/elasticsearch.yml" do
    notifies      :restart, "service[elasticsearch]"
  end
end

