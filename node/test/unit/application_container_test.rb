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
# Test the OpenShift application_container model
#
require_relative '../test_helper'
require 'fileutils'
require 'yaml'

module OpenShift
  ;
end

module OpenShift
  module Runtime
    class ApplicationContainer
      def self.shim

      end
    end
  end
end

class ApplicationContainerTest < OpenShift::NodeTestCase
  GEAR_BASE_DIR = '/var/lib/openshift'

  def setup
    ::OpenShift::Runtime::ApplicationContainer.shim

    @ports_begin    = 35531
    @ports_per_user = 5
    @uid_begin      = 500

    @config.stubs(:get).with("PORT_BEGIN").returns(@ports_begin.to_s)
    @config.stubs(:get).with("PORTS_PER_USER").returns(@ports_per_user.to_s)
    @config.stubs(:get).with("UID_BEGIN").returns(@uid_begin.to_s)
    @config.stubs(:get).with("GEAR_BASE_DIR").returns("/tmp")

    script_dir     = File.expand_path(File.dirname(__FILE__))
    cart_base_path = File.join(script_dir, '..', '..', '..', 'cartridges')

    raise "Couldn't find cart base path at #{cart_base_path}" unless File.exists?(cart_base_path)

    @config.stubs(:get).with("CARTRIDGE_BASE_PATH").returns(cart_base_path)

    # Set up the container
    @gear_uuid = "5502"
    @user_uid  = "5502"
    @app_name  = 'ApplicatioContainerTestCase'
    @gear_name = @app_name
    @namespace = 'jwh201204301647'
    @gear_ip   = "127.0.0.1"

    Etc.stubs(:getpwnam).returns(
      OpenStruct.new(
        uid: @user_uid.to_i,
        gid: @user_uid.to_i,
        gecos: "OpenShift guest",
        container_dir: "/var/lib/openshift/#{@gear_uuid}"
      )
    )

    @container_plugin = mock()
    OpenShift::Runtime::Containerization::Plugin.stubs(:new).with(anything()).returns(@container_plugin)

    @container = OpenShift::Runtime::ApplicationContainer.new(@gear_uuid, @gear_uuid, @user_uid,
        @app_name, @gear_uuid, @namespace, nil, nil, nil)


    @mock_manifest = %q{#
        Name: mock
        Cartridge-Short-Name: MOCK
        Cartridge-Version: 1.0
        Cartridge-Vendor: unit_test
        Display-Name: Mock
        Description: "A mock cartridge for development use only."
        Version: 0.1
        License: "None"
        Vendor: Red Hat
        Categories:
        - service
        Provides:
        - mock
        Scaling:
        Min: 1
        Max: -1
        Group-Overrides:
        - components:
        - mock
        Endpoints:
          - Private-IP-Name:   EXAMPLE_IP1
            Private-Port-Name: EXAMPLE_PORT1
            Private-Port:      8080
            Public-Port-Name:  EXAMPLE_PUBLIC_PORT1
            Mappings:
              - Frontend:      "/front1a"
                Backend:       "/back1a"
                Options:       { websocket: true, tohttps: true }
              - Frontend:      "/front1b"
                Backend:       "/back1b"
                Options:       { noproxy: true }

          - Private-IP-Name:   EXAMPLE_IP1
            Private-Port-Name: EXAMPLE_PORT2
            Private-Port:      8081
            Public-Port-Name:  EXAMPLE_PUBLIC_PORT2
            Mappings:
              - Frontend:      "/front2"
                Backend:       "/back2"
                Options:       { file: true }

          - Private-IP-Name:   EXAMPLE_IP1
            Private-Port-Name: EXAMPLE_PORT3
            Private-Port:      8082
            Public-Port-Name:  EXAMPLE_PUBLIC_PORT3
            Mappings:
              - Frontend:      "/front3"
                Backend:       "/back3"

          - Private-IP-Name:   EXAMPLE_IP2
            Private-Port-Name: EXAMPLE_PORT4
            Private-Port:      9090
            Public-Port-Name:  EXAMPLE_PUBLIC_PORT4
            Mappings:
              - Frontend:      "/front4"
                Backend:       "/back4"

          - Private-IP-Name:   EXAMPLE_IP2
            Private-Port-Name: EXAMPLE_PORT5
            Private-Port:      9091
    }

    manifest = "/tmp/manifest-#{Process.pid}"
    IO.write(manifest, @mock_manifest, 0)
    @mock_cartridge = OpenShift::Runtime::Manifest.new(manifest)
    @container.stubs(:get_cartridge).with("mock").returns(@mock_cartridge)
  end

  def test_public_endpoints_create
    OpenShift::Runtime::Utils::Environ.stubs(:for_gear).returns({
        "OPENSHIFT_MOCK_EXAMPLE_IP1" => "127.0.0.1",
        "OPENSHIFT_MOCK_EXAMPLE_IP2" => "127.0.0.2"
    })

    proxy = mock('OpenShift::Runtime::FrontendProxyServer')
    OpenShift::Runtime::FrontendProxyServer.stubs(:new).returns(proxy)

    proxy.expects(:add).with(@user_uid.to_i, "127.0.0.1", 8080).returns(@ports_begin)
    proxy.expects(:add).with(@user_uid.to_i, "127.0.0.1", 8081).returns(@ports_begin+1)
    proxy.expects(:add).with(@user_uid.to_i, "127.0.0.1", 8082).returns(@ports_begin+2)
    proxy.expects(:add).with(@user_uid.to_i, "127.0.0.2", 9090).returns(@ports_begin+3)

    @container.expects(:add_env_var).returns(nil).times(4)

    @container.create_public_endpoints(@mock_cartridge.name)
  end

  def test_public_endpoints_delete
    OpenShift::Runtime::Utils::Environ.stubs(:for_gear).returns({
        "OPENSHIFT_MOCK_EXAMPLE_IP1" => "127.0.0.1",
        "OPENSHIFT_MOCK_EXAMPLE_IP2" => "127.0.0.2"
    })

    proxy = mock('OpenShift::Runtime::FrontendProxyServer')
    OpenShift::Runtime::FrontendProxyServer.stubs(:new).returns(proxy)
    @container.expects(:list_proxy_mappings).returns([
        {public_port_name: "Endpoint_1", proxy_port:       @ports_begin},
        {public_port_name: "Endpoint_2", proxy_port:       @ports_begin+1},
        {public_port_name: "Endpoint_3", proxy_port:       @ports_begin+2},
        {public_port_name: "Endpoint_4", proxy_port:       @ports_begin+3}])
    #proxy.expects(:find_mapped_proxy_port).with(@user_uid, "127.0.0.1", 8080).returns(@ports_begin)
    #proxy.expects(:find_mapped_proxy_port).with(@user_uid, "127.0.0.1", 8081).returns(@ports_begin+1)
    #proxy.expects(:find_mapped_proxy_port).with(@user_uid, "127.0.0.1", 8082).returns(@ports_begin+2)
    #proxy.expects(:find_mapped_proxy_port).with(@user_uid, "127.0.0.2", 9090).returns(@ports_begin+3)

    delete_all_args = [@ports_begin, @ports_begin+1, @ports_begin+2, @ports_begin+3]
    proxy.expects(:delete_all).with(delete_all_args, true).returns(nil)

    @container.expects(:remove_env_var).returns(nil).times(4)

    @container.delete_public_endpoints(@mock_cartridge.name)
  end

  def test_tidy_success
    OpenShift::Runtime::Utils::Environ.stubs(:for_gear).returns(
        {'OPENSHIFT_HOMEDIR' => '/foo', 'OPENSHIFT_APP_NAME' => 'app_name' })

    @container.stubs(:stop_gear)
    @container.stubs(:gear_level_tidy_tmp).with('/foo/.tmp')
    @container.expects(:each_cartridge).yields(@mock_cartridge)
    @container.expects(:do_control).with('tidy', @mock_cartridge)
    @container.stubs(:gear_level_tidy_git).with('/foo/git/app_name.git')
    @container.stubs(:start_gear)

    @container.stubs(:cartridge_model).returns(mock())

    @container.tidy
  end

  def test_tidy_stop_gear_fails
    OpenShift::Runtime::Utils::Environ.stubs(:for_gear).returns(
        {'OPENSHIFT_HOMEDIR' => '/foo', 'OPENSHIFT_APP_NAME' => 'app_name' })

    @container.stubs(:stop_gear).raises(Exception.new)
    @container.stubs(:gear_level_tidy_tmp).with('/foo/.tmp')
    @container.expects(:each_cartridge).never
    @container.expects(:do_control).never
    @container.stubs(:gear_level_tidy_git).with('/foo/git/app_name.git')
    @container.stubs(:start_gear).never

    assert_raise Exception do
      @container.tidy
    end
  end

  def test_tidy_gear_level_tidy_fails
    OpenShift::Runtime::Utils::Environ.stubs(:for_gear).returns(
        {'OPENSHIFT_HOMEDIR' => '/foo', 'OPENSHIFT_APP_NAME' => 'app_name'})

    @container.expects(:stop_gear)
    @container.expects(:gear_level_tidy_tmp).with('/foo/.tmp').raises(Exception.new)
    @container.expects(:start_gear)

    @container.tidy
  end

  def test_force_stop
    FileUtils.mkpath("/tmp/#@user_uid/app-root/runtime")
    OpenShift::Runtime::Containerization::Plugin.stubs(:kill_procs).with(@user_uid).returns(nil)
    @container.state.expects(:value=).with(OpenShift::Runtime::State::STOPPED)
    @container.expects(:create_stop_lock)
    @container_plugin.expects(:stop)
    @container.force_stop
  end

  def test_connector_execute
    cart_name = 'mock-0.1'
    pub_cart_name = 'mock-plugin-0.1'
    connector_type = 'ENV:NET_TCP'
    connector = 'set-db-connection-info'
    args = 'foo'

    @container.expects(:connector_execute).with(cart_name, pub_cart_name, connector_type, connector, args)

    @container.connector_execute(cart_name, pub_cart_name, connector_type, connector, args)
  end

  # Tests a variety of UID/host ID to IP address conversions.
  #
  # TODO: Is there a way to do this algorithmically?
  def test_get_ip_addr_success
    ::OpenShift::Runtime::Containerization::Plugin.unstub(:new)

    scenarios = [
        [501, 1, "127.0.250.129"],
        [501, 10, "127.0.250.138"],
        [501, 20, "127.0.250.148"],
        [501, 100, "127.0.250.228"],
        [540, 1, "127.1.14.1"],
        [560, 7, "127.1.24.7"]
    ]

    scenarios.each do |s|
      Etc.stubs(:getpwnam).returns(
        OpenStruct.new(
          uid: s[0].to_i,
          gid: s[0].to_i,
          gecos: "OpenShift guest",
          container_dir: "/var/lib/openshift/gear_uuid"
        )
      )

      container = OpenShift::Runtime::ApplicationContainer.new("gear_uuid", "gear_uuid", s[0],
                                                                "app_name", "gear_uuid", "namespace", nil, nil, nil)

      assert_equal container.get_ip_addr(s[1]), s[2]
    end
  end

  def test_get_cartridge_error_loading
    @container.unstub(:get_cartridge)

    hourglass = mock()
    hourglass.stubs(:remaining).returns(3600)

    YAML.stubs(:load_file).with("#{@homedir}/redhat-crtest/metadata/manifest.yml").raises(ArgumentError.new('bla'))

    assert_raise(RuntimeError, "Failed to load cart manifest from #{@homedir}/redhat-crtest/metadata/manifest.yml for cart mock in gear : bla") do
      @container.get_cartridge("mock-0.1")
    end
  end

  def test_private_endpoint_create
    ip1 = "127.0.250.1"
    ip2 = "127.0.250.2"

    @container.expects(:find_open_ip).with(8080).returns(ip1)
    @container.expects(:find_open_ip).with(9090).returns(ip2)

    @container.expects(:addresses_bound?).returns(false)

    @container.expects(:add_env_var).with("OPENSHIFT_MOCK_EXAMPLE_IP1", ip1)
    @container.expects(:add_env_var).with("OPENSHIFT_MOCK_EXAMPLE_PORT1", 8080)
    @container.expects(:add_env_var).with("OPENSHIFT_MOCK_EXAMPLE_PORT2", 8081)
    @container.expects(:add_env_var).with("OPENSHIFT_MOCK_EXAMPLE_PORT3", 8082)
    @container.expects(:add_env_var).with("OPENSHIFT_MOCK_EXAMPLE_IP2", ip2)
    @container.expects(:add_env_var).with("OPENSHIFT_MOCK_EXAMPLE_PORT4", 9090)
    @container.expects(:add_env_var).with("OPENSHIFT_MOCK_EXAMPLE_PORT5", 9091)

    @container.create_private_endpoints(@mock_cartridge)
  end

  def test_private_endpoint_create_empty_endpoints
    @container.expects(:add_env_var).never
    @container.expects(:find_open_ip).never
    @container.expects(:address_bound?).never
    @container.expects(:addresses_bound?).never

    cart = mock()
    cart.stubs(:directory).returns("/nowhere")
    cart.stubs(:endpoints).returns([])

    @container.create_private_endpoints(cart)
  end

  def test_private_endpoint_create_binding_failure
    ip1 = "127.0.250.1"
    ip2 = "127.0.250.2"

    @container.expects(:find_open_ip).with(8080).returns(ip1)
    @container.expects(:find_open_ip).with(9090).returns(ip2)

    @container.expects(:add_env_var).times(7)

    @container.expects(:addresses_bound?).returns(true)
    @container.expects(:address_bound?).returns(true).times(5)

    assert_raise(RuntimeError) do
      @container.create_private_endpoints(@mock_cartridge)
    end
  end

  def test_private_endpoint_delete
    @container.expects(:remove_env_var).with("OPENSHIFT_MOCK_EXAMPLE_IP1")
    @container.expects(:remove_env_var).with("OPENSHIFT_MOCK_EXAMPLE_PORT1")
    @container.expects(:remove_env_var).with("OPENSHIFT_MOCK_EXAMPLE_IP1")
    @container.expects(:remove_env_var).with("OPENSHIFT_MOCK_EXAMPLE_PORT2")
    @container.expects(:remove_env_var).with("OPENSHIFT_MOCK_EXAMPLE_IP1")
    @container.expects(:remove_env_var).with("OPENSHIFT_MOCK_EXAMPLE_PORT3")
    @container.expects(:remove_env_var).with("OPENSHIFT_MOCK_EXAMPLE_IP2")
    @container.expects(:remove_env_var).with("OPENSHIFT_MOCK_EXAMPLE_PORT4")
    @container.expects(:remove_env_var).with("OPENSHIFT_MOCK_EXAMPLE_IP2")
    @container.expects(:remove_env_var).with("OPENSHIFT_MOCK_EXAMPLE_PORT5")

    @container.delete_private_endpoints(@mock_cartridge)
  end

  # Verifies that an IP can be allocated for a simple port binding request
  # where no other IPs are allocated to any carts in a gear.
  def test_find_open_ip_success
    ::OpenShift::Runtime::Containerization::Plugin.unstub(:new)
    @container = OpenShift::Runtime::ApplicationContainer.new(@gear_uuid, @gear_uuid, @user_uid,
        @app_name, @gear_uuid, @namespace, nil, nil, nil)

    @container.expects(:get_allocated_private_ips).returns([])

    assert_equal "127.10.190.129", @container.find_open_ip(8080)
  end

  # Ensures that a previously allocated IP within the gear won't be recycled
  # when a new allocation request is made.
  def test_find_open_ip_already_allocated
    @container.expects(:get_allocated_private_ips).returns(["127.10.190.129"])

    assert_equal "127.10.190.130", @container.find_open_ip(8080)
  end

  # Verifies that nil is returned from find_open_ip when all possible IPs
  # are already allocated to other endpoints.
  def test_find_open_ip_all_previously_allocated
    # Stub out a mock allocated IP array which will always tell the caller
    # that their input is included in the array. This simulates the case where
    # any IP the caller wants appears to be already allocated by other endpoints.
    allocated_array = mock()
    allocated_array.expects(:include?).returns(true).at_least_once

    @container.expects(:get_allocated_private_ips).returns(allocated_array)

    assert_nil @container.find_open_ip(8080)
  end

  # Flow control for destroy success - cartridge_teardown called for each method
  # and unix user destroyed.
  def test_destroy_success
    @container.expects(:notify_observers).with(:before_container_destroy)

    mock_lock = mock()

    File.expects(:open).with("/var/lock/oo-create.#{@gear_uuid}", File::RDWR|File::CREAT|File::TRUNC, 0o0600).yields(mock_lock)
    mock_lock.expects(:fcntl).with(Fcntl::F_SETFD, Fcntl::FD_CLOEXEC)
    mock_lock.expects(:flock).with(File::LOCK_EX)

    @container.expects(:each_cartridge).yields(@mock_cartridge)
    @container.expects(:unlock_gear).with(@mock_cartridge, false).yields(@mock_cartridge)
    @container.expects(:cartridge_teardown).with('mock', false).returns("")

    Dir.stubs(:chdir).with('/tmp').yields

    @container_plugin.expects(:destroy)

    @config.expects(:get).with('CREATE_APP_SYMLINKS').returns(nil)
    mock_lock.expects(:flock).with(File::LOCK_UN)

    @container.expects(:notify_observers).with(:after_container_destroy)

    @container.destroy
  end

  # Flow control for destroy without running hooks
  # Verifies that none of the teardown hooks are called but the user is destroyed
  def test_destroy_skip_hooks
    @container.expects(:notify_observers).with(:before_container_destroy)

    mock_lock = mock()

    File.expects(:open).with("/var/lock/oo-create.#{@gear_uuid}", File::RDWR|File::CREAT|File::TRUNC, 0o0600).yields(mock_lock)
    mock_lock.expects(:fcntl).with(Fcntl::F_SETFD, Fcntl::FD_CLOEXEC)
    mock_lock.expects(:flock).with(File::LOCK_EX)

    @container.expects(:each_cartridge).yields(@mock_cartridge).once
    @container.expects(:unlock_gear).never
    @container.expects(:cartridge_teardown).never

    Dir.stubs(:chdir).with('/tmp').yields

    @container_plugin.expects(:destroy)

    @config.expects(:get).with('CREATE_APP_SYMLINKS').returns(nil)
    mock_lock.expects(:flock).with(File::LOCK_UN)

    @container.expects(:notify_observers).with(:after_container_destroy)

    @container.destroy(true)
  end  

  # Flow control for destroy when teardown raises an error.
  # Verifies that all teardown hooks are called, even if one raises an error,
  # and that unix user is still destroyed.
  def test_destroy_teardown_raises
    @container.expects(:notify_observers).with(:before_container_destroy)

    mock_lock = mock()

    File.expects(:open).with("/var/lock/oo-create.#{@gear_uuid}", File::RDWR|File::CREAT|File::TRUNC, 0o0600).yields(mock_lock)
    mock_lock.expects(:fcntl).with(Fcntl::F_SETFD, Fcntl::FD_CLOEXEC)
    mock_lock.expects(:flock).with(File::LOCK_EX)

    @container.expects(:each_cartridge).yields(@mock_cartridge)
    @container.expects(:unlock_gear).with(@mock_cartridge, false).yields(@mock_cartridge)
    @container.expects(:cartridge_teardown).with('mock', false).returns("")
    @container.expects(:cartridge_teardown).with(@mock_cartridge.directory, false).raises(::OpenShift::Runtime::Utils::ShellExecutionException.new('error'))

    Dir.stubs(:chdir).with('/tmp').yields

    @container_plugin.expects(:destroy)

    @config.expects(:get).with('CREATE_APP_SYMLINKS').returns(nil)
    mock_lock.expects(:flock).with(File::LOCK_UN)

    @container.expects(:notify_observers).with(:after_container_destroy)

    @container.destroy

    @container.destroy
  end
end
