#!/usr/bin/env oo-ruby
#--
# Copyright 2013 Red Hat, Inc.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#++
#
# Test the OpenShift frontend_httpd model
#
require 'test_helper'
require 'openshift-origin-node/model/frontend_httpd'
require 'test/unit'
require 'fileutils'
require 'mocha'

class FrontendHttpServerModelTest < Test::Unit::TestCase

  class FauxApacheDB < Hash
    READER = 1
    WRITER = 1
    WRCREAT = 1
    NEWDB = 1

    def update_block
      deletions = []
      updates = {}
      self.each do |k, v|
        yield(deletions, updates, k, v)
      end
      self.delete_if { |k, v| deletions.include?(k) }
      self.update(updates)
    end
  end

  def setup
    @container_uuid = '0123456789abcdef'
    @container_name = 'frontendtest'
    @namespace = 'frontendtest'
    
    @gear_base_dir = "/tmp/frontend_httpd_test"

    @http_conf_dir = "/tmp/frontend_httpd_test/.httpd.d"

    @cloud_domain = "example.com"

    @ip = "127.0.0.1"
    @port = 8080


    @sts_max_age = 15768000

    @fqdn = "#{@container_name}-#{@namespace}.#{@cloud_domain}"

    @test_alias = "foo.example.com"

    @test_ssl_path = "#{@http_conf_dir}/#{@container_uuid}_#{@namespace}_#{@test_alias}"

    @test_ssl_key_passphrase = "test passphrase"
    @test_ssl_cert = "SSL Cert"
    @test_ssl_key = "SSL Key"
    @test_ssl_key_decrypted = "SSL Key Decrypted"

    syslog_mock = mock('Syslog') do
      stubs(:opened?).returns(true)
      stubs(:open).returns(nil)
      stubs(:alert).returns(nil)
      stubs(:debug).returns(nil)
    end
    Syslog.stubs(:new).returns(syslog_mock)

    @config_mock = mock('OpenShift::Config')
    @config_mock.stubs(:get).with("GEAR_BASE_DIR").returns(@gear_base_dir)
    @config_mock.stubs(:get).with("OPENSHIFT_HTTP_CONF_DIR").returns(@http_conf_dir)
    @config_mock.stubs(:get).with("CLOUD_DOMAIN").returns(@cloud_domain)
    OpenShift::Config.stubs(:new).returns(@config_mock)

    @container_info_db = FauxApacheDB.new
    @container_info_db_full = { @container_uuid => { "container_name" => @container_name, "namespace" => @namespace } }
    OpenShift::ContainerInfoDB.stubs(:open).yields(@container_info_db)

    @apache_db_nodes = FauxApacheDB.new
    @apache_db_nodes_full = { @fqdn => "#{@ip}:#{@port}" }
    OpenShift::ApacheDBNodes.stubs(:open).yields(@apache_db_nodes)

    @apache_db_aliases = FauxApacheDB.new
    @apache_db_aliases_full = { @test_alias => @fqdn }
    OpenShift::ApacheDBAliases.stubs(:open).yields(@apache_db_aliases)

    @apache_db_idler = FauxApacheDB.new
    @apache_db_idler_full = { @fqdn => @container_uuid }
    OpenShift::ApacheDBIdler.stubs(:open).yields(@apache_db_idler)

    @apache_db_sts = FauxApacheDB.new
    @apache_db_sts_full = { @fqdn => @sts_max_age }
    OpenShift::ApacheDBSTS.stubs(:open).yields(@apache_db_sts)

    @nodejs_db_routes = FauxApacheDB.new
    @nodejs_db_routes_full = {
      @fqdn => {
        "endpoints" => [ "#{@ip}:#{@port}" ],
        "limits"    => {
          "connections" => 5,
          "bandwidth"   => 100
        }
      },
      @test_alias => {
        "endpoints" => [ "#{@ip}:#{@port}" ],
        "alias" => @fqdn,
        "limits"    => {
          "connections" => 5,
          "bandwidth"   => 100
        }
      }
    }
    OpenShift::NodeJSDBRoutes.stubs(:open).yields(@nodejs_db_routes)
  end

  def set_dbs_empty
    @container_info_db.replace({})
    @apache_db_nodes.replace({})
    @apache_db_aliases.replace({})
    @apache_db_idler.replace({})
    @apache_db_sts.replace({})
    @nodejs_db_routes.replace({})
  end

  def check_dbs_empty
    assert @container_info_db.empty?, "ContainerInfoDB not empty"
    assert @apache_db_nodes.empty?, "ApacheDBNodes not empty"
    assert @apache_db_aliases.empty?, "ApacheDBAliases not empty"
    assert @apache_db_idler.empty?, "ApacheDBIdler not empty"
    assert @apache_db_sts.empty?, "ApacheDBSTS not empty"
    assert @nodejs_db_routes.empty?, "NodeJSDBRoutes not empty"
  end

  def check_dbs_not_empty
    assert (not @container_info_db.empty?), "ContainerInfoDB empty"
    assert (not @apache_db_nodes.empty?), "ApacheDBNodes empty"
    assert (not @apache_db_aliases.empty?), "ApacheDBAliases empty"
    assert (not @apache_db_idler.empty?), "ApacheDBIdler empty"
    assert (not @apache_db_sts.empty?), "ApacheDBSTS empty"
    assert (not @nodejs_db_routes.empty?), "NodeJSDBRoutes empty"
  end

  def set_dbs_full
    @container_info_db.replace(@container_info_db_full)
    @apache_db_nodes.replace(@apache_db_nodes_full)
    @apache_db_aliases.replace(@apache_db_aliases_full)
    @apache_db_idler.replace(@apache_db_idler_full)
    @apache_db_sts.replace(@apache_db_sts_full)
    @nodejs_db_routes.replace(@nodejs_db_routes_full)
  end

  def check_dbs_full
    assert_equal @container_info_db_full, @container_info_db, "ContainerInfoDB not properly set"
    assert_equal @apache_db_nodes_full, @apache_db_nodes, "ApacheDBNodes not properly set"
    assert_equal @apache_db_aliases_full, @apache_db_aliases, "ApacheDBAliases not properly set"
    assert_equal @apache_db_idler_full, @apache_db_idler, "ApacheDBIdler not properly set"
    assert_equal @apache_db_sts_full, @apache_db_sts, "ApacheDBSTS not properly set"
    assert_equal @nodejs_db_routes_full, @nodejs_db_routes, "NodeJSDBRoutes not properly set"
  end

  def test_clean_server_name
    frontend = OpenShift::FrontendHttpServer.new(@container_uuid, @container_name, @namespace)
    
    assert_equal "#{@test_alias}", frontend.clean_server_name("#{@test_alias}")
    assert_equal "#{@test_alias}", frontend.clean_server_name("#{@test_alias}".upcase)
    assert_raise OpenShift::FrontendHttpServerNameException do
      frontend.clean_server_name("../../../../../../../etc/passwd")
    end
  end

  def test_create
    set_dbs_empty

    frontend = OpenShift::FrontendHttpServer.new(@container_uuid, @container_name, @namespace)
    frontend.create

    assert_equal @container_info_db_full, @container_info_db, "Failed to populate ContainerInfoDB"
  end

  def test_create_initialized
    set_dbs_full

    frontend = nil
    assert_nothing_raised do
      frontend = OpenShift::FrontendHttpServer.new(@container_uuid)
    end

    assert_equal @container_name, frontend.container_name
    assert_equal @namespace, frontend.namespace
  end

  def test_initialize_uncreated
    set_dbs_empty

    assert_raise OpenShift::FrontendHttpServerException do
      frontend = OpenShift::FrontendHttpServer.new(@container_uuid)
    end
  end


  def test_destroy
    set_dbs_full

    Dir.stubs(:glob).returns(["foo.conf"]).once
    FileUtils.stubs(:rm_rf).once

    frontend = OpenShift::FrontendHttpServer.new(@container_uuid, @container_name, @namespace)
    OpenShift::Utils.expects(:oo_spawn).returns(["", "", 0])
    frontend.destroy

    check_dbs_empty
  end


  def test_update
    set_dbs_full

    frontend = OpenShift::FrontendHttpServer.new(@container_uuid, @container_name, @namespace)
    frontend.update_name("newname")
    frontend.update_namespace("newnamespace")

    new_fqdn = "newname-newnamespace.#{@cloud_domain}"

    assert_equal "newname", frontend.container_name
    assert_equal "newnamespace", frontend.namespace
    assert_equal new_fqdn, frontend.fqdn

    check_dbs_not_empty

    assert_equal "newname", @container_info_db[@container_uuid]["container_name"]
    assert_equal  "newnamespace", @container_info_db[@container_uuid]["namespace"]

    assert_equal @apache_db_nodes_full[@fqdn], @apache_db_nodes[new_fqdn]

    assert_equal new_fqdn, @apache_db_aliases[@test_alias]

    assert_equal @container_uuid, @apache_db_idler[new_fqdn]

    assert_equal @sts_max_age, @apache_db_sts[new_fqdn]

    assert_equal @nodejs_db_routes_full[@fqdn], @nodejs_db_routes[new_fqdn]

  end

  def test_connections
    set_dbs_empty

    connections = [ ["", "#{@ip}:#{@port}", { "websocket" => 1, "connections" => 1, "bandwidth" => 2 }],
                    ["/nosocket", "#{@ip}:#{@port}",{}],
                    ["/gone", "", { "gone" => 1 }],
                    ["/forbidden", "", { "forbidden" => 1 }],
                    ["/noproxy", "", { "noproxy" => 1 }],
                    ["/redirect", "/dest", { "redirect" => 1 }],
                    ["/file", "/dest.html", { "file" => 1 }],
                    ["/tohttps", "/dest", { "tohttps" => 1 }] ]

    frontend = OpenShift::FrontendHttpServer.new(@container_uuid, @container_name, @namespace)
    frontend.create
    frontend.connect(connections)

    assert (not @container_info_db.empty?), "ContainerInfoDB empty"
    assert (not @apache_db_nodes.empty?), "ApacheDBNodes empty"
    assert (not @nodejs_db_routes.empty?), "NodeJSDBRoutes empty"

    assert_equal "#{@ip}:#{@port}", @apache_db_nodes[@fqdn]
    assert_equal "#{@ip}:#{@port}", @apache_db_nodes[@fqdn +"/nosocket"]
    assert_equal "GONE", @apache_db_nodes[@fqdn +"/gone"]
    assert_equal "FORBIDDEN", @apache_db_nodes[@fqdn +"/forbidden"]
    assert_equal "NOPROXY", @apache_db_nodes[@fqdn +"/noproxy"]
    assert_equal "REDIRECT:/dest", @apache_db_nodes[@fqdn +"/redirect"]
    assert_equal "FILE:/dest.html", @apache_db_nodes[@fqdn +"/file"]
    assert_equal "TOHTTPS:/dest", @apache_db_nodes[@fqdn +"/tohttps"]

    assert_equal ["#{@ip}:#{@port}"], @nodejs_db_routes[@fqdn]["endpoints"]
    assert_equal 1, @nodejs_db_routes[@fqdn]["limits"]["connections"]
    assert_equal 2, @nodejs_db_routes[@fqdn]["limits"]["bandwidth"]

    @apache_db_nodes["unrelated"]="1"

    assert_equal connections, frontend.connections

    @apache_db_nodes.delete("unrelated")

    frontend.disconnect("", "/nosocket", "/gone", "/forbidden", "/noproxy", "/redirect", "/file", "/tohttps")
    assert @apache_db_nodes.empty?
    assert @nodejs_db_routes.empty?
  end

  def test_idle
    set_dbs_empty

    frontend = OpenShift::FrontendHttpServer.new(@container_uuid, @container_name, @namespace)
    frontend.create

    frontend.idle
    assert_equal @container_uuid, @apache_db_idler[@fqdn]

    assert frontend.idle?

    frontend.unidle
    assert @apache_db_idler.empty?
  end

  def test_sts
    set_dbs_empty

    frontend = OpenShift::FrontendHttpServer.new(@container_uuid, @container_name, @namespace)
    frontend.create

    frontend.sts(@sts_max_age)
    assert_equal @sts_max_age, @apache_db_sts[@fqdn]

    assert_equal @sts_max_age, frontend.get_sts

    frontend.no_sts
    assert @apache_db_sts.empty?
  end

  def test_aliases
    set_dbs_empty

    frontend = OpenShift::FrontendHttpServer.new(@container_uuid, @container_name, @namespace)
    frontend.create
    frontend.connect("", "#{@ip}:#{@port}", { "websocket" => 1})
    frontend.add_alias("#{@test_alias}")

    assert (not @apache_db_aliases.empty?)
    assert (not @nodejs_db_routes.empty?)
    assert (not @nodejs_db_routes[@test_alias].nil?)

    assert_equal @fqdn, @apache_db_aliases[@test_alias]

    assert_equal @nodejs_db_routes[@fqdn]["endpoints"], @nodejs_db_routes[@test_alias]["endpoints"]
    assert_equal @nodejs_db_routes[@fqdn]["limits"], @nodejs_db_routes[@test_alias]["limits"]

    assert_equal [@test_alias], frontend.aliases

    frontend.remove_alias(@test_alias)

    assert @apache_db_aliases.empty?
    assert (not @nodejs_db_routes.has_key?(@test_alias))
  end

  def test_ssl_certs
    set_dbs_empty

    openssl_pkey = mock('OpenSSL::PKey')
    openssl_pkey.stubs(:to_pem).returns(@test_ssl_key_decrypted)
    openssl_pkey.stubs(:class).returns(OpenSSL::PKey::RSA)
    OpenSSL::PKey.stubs(:read).returns(openssl_pkey)

    openssl_cert = mock('OpenSSL::X509::Certificate')
    openssl_cert.stubs(:to_pem).returns(@test_ssl_cert)
    openssl_cert.stubs(:check_private_key).returns(true).then.returns(false)
    OpenSSL::X509::Certificate.stubs(:new).returns(openssl_cert)


    FileUtils.stubs(:mkdir_p).with(@test_ssl_path).once
    File.stubs(:open).with("#{@test_ssl_path}/#{@test_alias}.crt", 'w').once
    File.stubs(:open).with("#{@test_ssl_path}/#{@test_alias}.key", 'w').once
    File.stubs(:open).with("#{@test_ssl_path}.conf", 'w').once

    File.stubs(:read).with("#{@test_ssl_path}/#{@test_alias}.crt").returns(@test_ssl_cert).once
    File.stubs(:read).with("#{@test_ssl_path}/#{@test_alias}.key").returns(@test_ssl_key_decrypted).once

    File.stubs(:exists?).with("#{@test_ssl_path}.conf").returns(true).once
    FileUtils.stubs(:rm_rf).with(@test_ssl_path).once
    FileUtils.stubs(:rm_rf).with("#{@test_ssl_path}.conf").once

    frontend = OpenShift::FrontendHttpServer.new(@container_uuid, @container_name, @namespace)
    frontend.create
    frontend.connect("", "#{@ip}:#{@port}", { "websocket" => 1})
    frontend.add_alias("#{@test_alias}")

    OpenShift::Utils.expects(:oo_spawn).returns(["", "", 0]).twice

    frontend.add_ssl_cert(@test_ssl_cert, @test_ssl_key, @test_alias, @test_ssl_key_passphrase)

    assert_equal [[@test_ssl_cert, @test_ssl_key_decrypted, @test_alias]], frontend.ssl_certs

    frontend.remove_ssl_cert(@test_alias)

    # check_private_key returns false
    assert_raise OpenShift::FrontendHttpServerException do
      frontend.add_ssl_cert(@test_ssl_cert, @test_ssl_key, @test_alias)
    end

    # bad alias
    assert_raise OpenShift::FrontendHttpServerException do
      frontend.add_ssl_cert(@test_ssl_cert, @test_ssl_key, @test_alias.reverse)
    end
  end


  def test_serialization
    set_dbs_empty

    frontend = OpenShift::FrontendHttpServer.new(@container_uuid, @container_name, @namespace)
    frontend.create
    frontend.connect("", "#{@ip}:#{@port}", { "websocket" => 1})
    frontend.add_alias("#{@test_alias}")

    fehash = frontend.to_hash

    set_dbs_empty

    new_frontend = OpenShift::FrontendHttpServer.json_create( { 'data' => fehash } )

    assert_equal @container_uuid, new_frontend.container_uuid
    assert_equal @container_name, new_frontend.container_name
    assert_equal @namespace, new_frontend.namespace

    assert @nodejs_db_routes.has_key?(@fqdn)
    assert_equal ["#{@ip}:#{@port}"], @nodejs_db_routes[@fqdn]["endpoints"]

    assert @nodejs_db_routes.has_key?(@fqdn)
    assert @nodejs_db_routes.has_key?(@test_alias)
    assert (not @nodejs_db_routes[@fqdn].nil?)
    assert_equal @nodejs_db_routes[@fqdn]["endpoints"], @nodejs_db_routes[@test_alias]["endpoints"]
    assert_equal @nodejs_db_routes[@fqdn]["limits"], @nodejs_db_routes[@test_alias]["limits"]
    assert_equal @fqdn, @nodejs_db_routes[@test_alias]["alias"]
  end

end

class TestApacheDB < Test::Unit::TestCase

  def setup

    @mock_mutex = mock('Mutex') do
      stubs(:lock)
      stubs(:unlock)
      stubs(:locked?).returns(true)
    end
    Mutex.stubs(:new).returns(@mock_mutex)

    @gear_base_dir = "/tmp/apachedb_test"
    @http_conf_dir = "/tmp/apachedb_test/.httpd.d"
    
    @config_mock = mock('OpenShift::Config')
    @config_mock.stubs(:get).with("GEAR_BASE_DIR").returns(@gear_base_dir)
    @config_mock.stubs(:get).with("OPENSHIFT_HTTP_CONF_DIR").returns(@http_conf_dir)
    OpenShift::Config.stubs(:new).returns(@config_mock)
    

    @apachedb_lockfiles = Hash[["nodes",
                                "aliases",
                                "idler",
                                "sts",
                                "routes",
                                "containers" ].map { |k|
                                 [k, "/var/run/openshift/ApacheDB.#{k}.txt.lock"]}]
    @apachedb_lockfiles.update(Hash[["routes",
                                     "containers"].map { |k|
                                      [k, "/var/run/openshift/ApacheDB.#{k}.json.lock"]}])

    @apachedb_files = Hash[["nodes",
                            "aliases",
                            "idler",
                            "sts",
                            "routes",
                            "containers" ].map { |k|
                             [k, File.join(@http_conf_dir,"#{k}.txt")]}]
    @apachedb_files.update(Hash[["routes",
                                 "containers"].map { |k|
                                  [k, File.join(@http_conf_dir,"#{k}.json")]}])
  end

  def test_node_fetch
    lockfile_mock = mock('FileLockfile') do
      stubs(:flock).with(File::LOCK_SH).once
      stubs(:flock).with(File::LOCK_EX).never
      stubs(:closed?).returns(false)
      stubs(:close).once
    end
    File.stubs(:new).with(@apachedb_lockfiles["nodes"], anything, anything).returns(lockfile_mock).once

    readfile_mock = mock('FileRead') do
      stubs(:each).yields("www.example.com 127.0.0.1:8080\n")
      stubs(:write).never
    end
    File.stubs(:open).with(@apachedb_files["nodes"], Fcntl::O_RDONLY).yields(readfile_mock).once

    File.stubs(:open).never

    OpenShift::ApacheDBNodes.stubs(:callout).never

    dest = nil
    assert_nothing_raised do
      OpenShift::ApacheDBNodes.open(OpenShift::ApacheDBNodes::READER) do |d|
        dest = d.fetch("www.example.com")
      end
    end
    assert_equal "127.0.0.1:8080", dest
  end

  def test_node_store
    lockfile_mock = mock('FileLockfile') do
      stubs(:flock).with(File::LOCK_SH).never
      stubs(:flock).with(File::LOCK_EX).once
      stubs(:closed?).returns(false)
      stubs(:close).once
    end
    File.stubs(:new).with(@apachedb_lockfiles["nodes"], anything, anything).returns(lockfile_mock).once

    writefile_mock = mock('FileWrite') do
      stubs(:write).with("www.example.com 127.0.0.1:8080\n").once
    end
    File.stubs(:open).with(@apachedb_files["nodes"] + '-', anything, anything).yields(writefile_mock).once

    File.stubs(:open).never

    FileUtils.stubs(:compare_file).with(@apachedb_files["nodes"] + '-', @apachedb_files["nodes"]).returns(false).once
    FileUtils.stubs(:rm).never
    FileUtils.stubs(:mv).once

    OpenShift::ApacheDBNodes.any_instance.stubs(:callout).once

    OpenShift::ApacheDBNodes.open(OpenShift::ApacheDBNodes::NEWDB) do |d|
      d.store("www.example.com", "127.0.0.1:8080")
    end

  end

end
