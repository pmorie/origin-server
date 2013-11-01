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

require_relative '../test_helper'
require 'socket'
require 'net/http'
require 'fileutils'

class PlatformSnapshotTest < OpenShift::NodeBareTestCase
  include Test::Unit::Assertions
  include OpenShift::Runtime::NodeLogger

  DEFAULT_TITLE     = "Welcome to OpenShift"
  CHANGED_TITLE     = "Test1"

  def setup
    @api = FunctionalApi.new
    @namespace = @api.create_domain
  end

  def basic_snapshot_test(cartridges, options={})
    scaling          = !!options[:scaling]
    keep_deployments = options[:keep_deployments]

    app_name = "app#{@api.random_string}"
    app_id = @api.create_application(app_name, cartridges, scaling)
    @api.add_ssh_key(app_id, app_name)

    snapshot_path = @api.snapshot_app

    @api.clone_repo(app_id)
    @api.change_title(CHANGED_TITLE, app_name, app_id, framework)

    @api.restore(snapshot_path)
    @api.assert_http_title_for_app(app_name, @namespace, DEFAULT_TITLE)
  end
end