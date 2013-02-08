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

require 'test_helper'
require 'openshift-origin-node/model/application_container'
require 'openshift-origin-node/model/v2_cart_model'
require 'openshift-origin-node/utils/environ'
require 'openshift-origin-common'
require 'test/unit'
require 'fileutils'
require 'mocha'

class V2CartModelTest < Test::Unit::TestCase

  def setup
  end

  # Verifies that nil is returned from find_open_ip when all requested ports are
  # already bound on all possible IPs.
  def test_find_open_ip_all_previously_bound
    @model.expects(:get_allocated_private_ips).returns([])

    # Simulate an lsof call indicating the IP/port is already bound
    @model.expects(:address_bound?).returns(true).at_least_once

    assert_nil @model.find_open_ip(8080)
  end

  # Verifies that nil is returned from find_open_ip when all possible IPs
  # are already allocated to other endpoints.
  def test_find_open_ip_all_previously_allocated
    # Stub out a mock allocated IP array which will always tell the caller
    # that their input is included in the array. This simulates the case where
    # any IP the caller wants appears to be already allocated by other endpoints.
    allocated_array = mock()
    allocated_array.expects(:include?).returns(true).at_least_once

    @model.expects(:get_allocated_private_ips).returns(allocated_array)

    # Simulate an lsof call indicating the IP/port is available
    @model.expects(:address_bound?).never

    assert_nil @model.find_open_ip(8080)
  end

  # Flow control for destroy success - cartridge_teardown called for each method
  # and unix user destroyed.
  def test_destroy_success
    @model.expects(:process_cartridges).multiple_yields(%w(/var/lib/openshift/0001000100010001/cartridge1), 
                                                        %w(/var/lib/openshift/0001000100010001/cartridge2))
    @model.expects(:cartridge_teardown).with('cartridge1')
    @model.expects(:cartridge_teardown).with('cartridge2')
    @container.user.expects(:destroy)

    @model.destroy
  end

  # Flow control for destroy when teardown raises an error.
  # Verifies that all teardown hooks are called, even if one raises an error,
  # and that unix user is still destroyed.
  def test_destroy_teardown_raises
    @model.expects(:process_cartridges).multiple_yields(%w(/var/lib/openshift/0001000100010001/cartridge1), 
                                                        %w(/var/lib/openshift/0001000100010001/cartridge2))
    @model.expects(:cartridge_teardown).with('cartridge1').raises(OpenShift::Utils::ShellExecutionException.new('error'))
    @model.expects(:cartridge_teardown).with('cartridge2')
    @container.user.expects(:destroy)

    @model.destroy
  end

  # Flow control for unlock_gear success - block is yielded to
  # with cartridge name, do_unlock_gear and do_lock_gear bound the call.
  def test_unlock_gear_success
    @model.expects(:lock_files).with('mock-0.1').returns(%w(file1 file2 file3))
    @model.expects(:do_unlock_gear).with(%w(file1 file2 file3))
    @model.expects(:do_lock_gear).with(%w(file1 file2 file3))

    params = []
    @model.unlock_gear('mock-0.1') { |cart_name| params << cart_name }
    
    assert_equal 1, params.size
    assert_equal 'mock-0.1', params[0]
  end

  # Flow control for unlock gear failure - do_lock_gear is called
  # even when the block raises and exception.  Exception bubbles
  # out to caller.
  def test_unlock_gear_block_raises
    @model.expects(:lock_files).with('mock-0.1').returns(%w(file1 file2 file3))
    @model.expects(:do_unlock_gear).with(%w(file1 file2 file3))
    @model.expects(:do_lock_gear).with(%w(file1 file2 file3))

    assert_raise OpenShift::Utils::ShellExecutionException do 
      @model.unlock_gear('mock-0.1') { raise OpenShift::Utils::ShellExecutionException.new('error') }
    end
  end
end
