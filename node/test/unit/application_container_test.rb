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
module OpenShift; end

require 'openshift-origin-node/model/application_container'
require 'openshift-origin-node/model/v1_cart_model'
require 'openshift-origin-node/utils/environ'
require 'openshift-origin-common'
require 'test/unit'
require 'fileutils'
require 'mocha'

# Run unit test manually
# ruby -I node/lib:common/lib node/test/unit/application_container_test.rb
class TestApplicationContainer < Test::Unit::TestCase

  def setup
    # Set up the config
    @config = mock('OpenShift::Config')

    @ports_begin = 35531
    @ports_per_user = 5
    @uid_begin = 500

    @config.stubs(:get).with("PORT_BEGIN").returns(@ports_begin.to_s)
    @config.stubs(:get).with("PORTS_PER_USER").returns(@ports_per_user.to_s)
    @config.stubs(:get).with("UID_BEGIN").returns(@uid_begin.to_s)
    @config.stubs(:get).with("GEAR_BASE_DIR").returns("/tmp")

    script_dir = File.expand_path(File.dirname(__FILE__))
    cart_base_path = File.join(script_dir, '..', '..', '..', 'cartridges')

    raise "Couldn't find cart base path at #{cart_base_path}" unless File.exists?(cart_base_path)

    @config.stubs(:get).with("CARTRIDGE_BASE_PATH").returns(cart_base_path)

    OpenShift::Config.stubs(:new).returns(@config)

    # Set up the container
    @gear_uuid = "501"
    @user_uid = "501"
    @app_name = 'UnixUserTestCase'
    @gear_name = @app_name
    @namespace = 'jwh201204301647'
    @gear_ip = "127.0.0.1"

    @container = OpenShift::ApplicationContainer.new(@gear_uuid, @gear_uuid, @user_uid,
        @app_name, @gear_uuid, @namespace, nil, nil, nil)   
  end

  def test_private_endpoint_create_php
    @container.stubs(:cart_model).returns(OpenShift::V1CartridgeModel.new(@config, nil))

    cart = "openshift-origin-cartridge-php-5.3"

    ip = "127.0.250.255"

    @container.expects(:find_open_ip).with(8080).returns(ip).once

    @container.expects(:address_bound?).returns(false).once

    @container.user.expects(:add_env_var).with("OPENSHIFT_PHP_IP", ip).once
    @container.user.expects(:add_env_var).with("OPENSHIFT_PHP_PORT", 8080).once
    
    @container.create_private_endpoints(cart)
  end

  def test_public_endpoint_create_php
    @container.stubs(:cart_model).returns(OpenShift::V1CartridgeModel.new(@config, nil))

    cart = "openshift-origin-cartridge-php-5.3"

    OpenShift::Utils::Environ.stubs(:for_gear).returns({"OPENSHIFT_PHP_IP" => @gear_ip})

    proxy = mock('OpenShift::FrontendProxyServer')
    OpenShift::FrontendProxyServer.stubs(:new).returns(proxy)

    proxy.expects(:add).with(@user_uid, @gear_ip, 8080).returns(@ports_begin).once

    @container.user.expects(:add_env_var).returns(nil).once
    
    @container.create_public_endpoints(cart)
  end

  def test_public_endpoint_create_jbossas7
    @container.stubs(:cart_model).returns(OpenShift::V1CartridgeModel.new(@config, nil))

    cart = "openshift-origin-cartridge-jbossas-7"
    
    OpenShift::Utils::Environ.stubs(:for_gear).returns({"OPENSHIFT_JBOSSAS_IP" => @gear_ip})

    proxy = mock('OpenShift::FrontendProxyServer')
    OpenShift::FrontendProxyServer.stubs(:new).returns(proxy)

    proxy.expects(:add).with(@user_uid, @gear_ip, 8080).returns(@ports_begin).once
    proxy.expects(:add).with(@user_uid, @gear_ip, 7600).returns(@ports_begin+1).once
    proxy.expects(:add).with(@user_uid, @gear_ip, 5445).returns(@ports_begin+2).once
    proxy.expects(:add).with(@user_uid, @gear_ip, 5455).returns(@ports_begin+3).once
    proxy.expects(:add).with(@user_uid, @gear_ip, 4447).returns(@ports_begin+4).once

    @container.user.expects(:add_env_var).returns(nil).times(5)

    @container.create_public_endpoints(cart)
  end

  def test_private_endpoint_create_jbossas7
    @container.stubs(:cart_model).returns(OpenShift::V1CartridgeModel.new(@config, nil))

    cart = "openshift-origin-cartridge-jbossas-7"

    ip = "127.0.250.255"

    @container.expects(:find_open_ip).with(8080).returns(ip).once

    @container.expects(:address_bound?).returns(false).times(5)

    @container.user.expects(:add_env_var).with("OPENSHIFT_JBOSSAS_IP", ip).once
    @container.user.expects(:add_env_var).with("OPENSHIFT_JBOSSAS_PORT", 8080).once
    @container.user.expects(:add_env_var).with("OPENSHIFT_JBOSSAS_CLUSTER_PORT", 7600).once
    @container.user.expects(:add_env_var).with("OPENSHIFT_JBOSSAS_MESSAGING_PORT", 5445).once
    @container.user.expects(:add_env_var).with("OPENSHIFT_JBOSSAS_MESSAGING_THROUGHPUT_PORT", 5455).once
    @container.user.expects(:add_env_var).with("OPENSHIFT_JBOSSAS_REMOTING_PORT", 4447).once
    
    @container.create_private_endpoints(cart)
  end

  def test_endpoint_delete_jbossas7
    @container.stubs(:cart_model).returns(OpenShift::V1CartridgeModel.new(@config, nil))

    cart = "openshift-origin-cartridge-jbossas-7"
    
    OpenShift::Utils::Environ.stubs(:for_gear).returns({"OPENSHIFT_JBOSSAS_IP" => @gear_ip})

    proxy = mock('OpenShift::FrontendProxyServer')
    OpenShift::FrontendProxyServer.stubs(:new).returns(proxy)

    proxy.expects(:find_mapped_proxy_port).with(@user_uid, @gear_ip, 8080).returns(@ports_begin).once
    proxy.expects(:find_mapped_proxy_port).with(@user_uid, @gear_ip, 7600).returns(@ports_begin+1).once
    proxy.expects(:find_mapped_proxy_port).with(@user_uid, @gear_ip, 5445).returns(@ports_begin+2).once
    proxy.expects(:find_mapped_proxy_port).with(@user_uid, @gear_ip, 5455).returns(@ports_begin+3).once
    proxy.expects(:find_mapped_proxy_port).with(@user_uid, @gear_ip, 4447).returns(@ports_begin+4).once

    delete_all_args = [@ports_begin, @ports_begin+1, @ports_begin+2, @ports_begin+3, @ports_begin+4]
    proxy.expects(:delete_all).with(delete_all_args, true).returns(nil)

    @container.user.expects(:remove_env_var).returns(nil).times(5)

    @container.delete_public_endpoints(cart)
  end

  def test_tidy_success
    @container.stubs(:cart_model).returns(OpenShift::V1CartridgeModel.new(@config, nil))

    OpenShift::Utils::Environ.stubs(:for_gear).returns(
        {'OPENSHIFT_HOMEDIR' => '/foo', 'OPENSHIFT_APP_NAME' => 'app_name' })

    cart_model = mock()

    @container.stubs(:cart_model).returns(cart_model)
    @container.stubs(:stop_gear).with('/foo').once
    @container.stubs(:gear_level_tidy).with('/foo/git/app_name.git', '/foo/.tmp').once
    cart_model.expects(:tidy).once
    @container.stubs(:start_gear).once

    @container.tidy
  end

  def test_tidy_stop_gear_fails
    @container.stubs(:cart_model).returns(OpenShift::V1CartridgeModel.new(@config, nil))

    OpenShift::Utils::Environ.stubs(:for_gear).returns(
        {'OPENSHIFT_HOMEDIR' => '/foo', 'OPENSHIFT_APP_NAME' => 'app_name' })

    cart_model = mock()

    @container.stubs(:cart_model).returns(cart_model)
    @container.stubs(:stop_gear).with('/foo').raises(Exception.new).once
    @container.stubs(:gear_level_tidy).with('/foo/git/app_name.git', '/foo/.tmp').never
    cart_model.expects(:tidy).never
    @container.stubs(:start_gear).never

    assert_raise Exception do 
      @container.tidy
    end
  end

  def test_tidy_gear_level_tidy_fails
    @container.stubs(:cart_model).returns(OpenShift::V1CartridgeModel.new(@config, nil))

    OpenShift::Utils::Environ.stubs(:for_gear).returns(
        {'OPENSHIFT_HOMEDIR' => '/foo', 'OPENSHIFT_APP_NAME' => 'app_name' })


    @container.expects(:stop_gear).with('/foo').once
    @container.expects(:gear_level_tidy).with('/foo/git/app_name.git', '/foo/.tmp').raises(Exception.new).once
    @container.expects(:start_gear).once

    @container.tidy
  end

  # Verifies that an IP can be allocated for a simple port binding request
  # where no other IPs are allocated to any carts in a gear.
  def test_find_open_ip_success
    @container.stubs(:cart_model).returns(OpenShift::V1CartridgeModel.new(@config, nil))

    @container.stubs(:get_allocated_private_ips).returns([])
    @container.stubs(:address_bound?).returns(false).once

    assert_equal @container.find_open_ip(8080), "127.0.250.129"
  end

  # Ensures that a previously allocated IP within the gear won't be recycled
  # when a new allocation request is made.
  def test_find_open_ip_already_allocated
    @container.stubs(:cart_model).returns(OpenShift::V1CartridgeModel.new(@config, nil))

    @container.stubs(:get_allocated_private_ips).returns(["127.0.250.129"])

    @container.stubs(:address_bound?).returns(false).once

    assert_equal @container.find_open_ip(8080), "127.0.250.130"
  end

  # Verifies that nil is returned from find_open_ip when all requested ports are
  # already bound on all possible IPs.
  def test_find_open_ip_all_previously_bound
    @container.stubs(:cart_model).returns(OpenShift::V1CartridgeModel.new(@config, nil))

    @container.stubs(:get_allocated_private_ips).returns([])

    # Simulate an lsof call indicating the IP/port is already bound
    @container.stubs(:address_bound?).returns(true).at_least_once

    assert_nil @container.find_open_ip(8080)
  end

  # Verifies that nil is returned from find_open_ip when all possible IPs
  # are already allocated to other endpoints.
  def test_find_open_ip_all_previously_allocated
    @container.stubs(:cart_model).returns(OpenShift::V1CartridgeModel.new(@config, nil))

    # Stub out a mock allocated IP array which will always tell the caller
    # that their input is included in the array. This simulates the case where
    # any IP the caller wants appears to be already allocated by other endpoints.
    allocated_array = mock()
    @container.stubs(:get_allocated_private_ips).returns(allocated_array)
    allocated_array.expects(:include?).returns(true).at_least_once

    # Simulate an lsof call indicating the IP/port is available
    OpenShift::Utils::ShellExec.stubs(:shellCmd).returns([nil, nil, 0])

    assert_nil @container.find_open_ip(8080)
  end
end
