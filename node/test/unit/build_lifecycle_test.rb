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

class BuildLifecycleTest < OpenShift::NodeTestCase

  def setup
    @config.stubs(:get).with("GEAR_BASE_DIR").returns("/tmp")

    # Set up the container
    @gear_uuid = "5503"
    @user_uid  = "5503"
    @app_name  = 'ApplicationContainerTestCase'
    @gear_name = @app_name
    @namespace = 'jwh201204301647'
    @gear_ip   = "127.0.0.1"

    @cartridge_model = mock()
    OpenShift::Runtime::V2CartridgeModel.stubs(:new).returns(@cartridge_model)

    @state = mock()
    OpenShift::Runtime::Utils::ApplicationState.stubs(:new).returns(@state)

    @container = OpenShift::Runtime::ApplicationContainer.new(@gear_uuid, @gear_uuid, @user_uid,
        @app_name, @gear_uuid, @namespace, nil, nil)

    @frontend = mock('OpenShift::Runtime::FrontendHttpServer')
    OpenShift::Runtime::FrontendHttpServer.stubs(:new).returns(@frontend)
  end

  def test_pre_receive_default_builder
    @cartridge_model.expects(:builder_cartridge).returns(nil)

    @container.expects(:stop_gear).with(user_initiated: true, hot_deploy: nil, exclude_web_proxy: true, out: $stdout, err: $stderr)

    @container.pre_receive(out: $stdout, err: $stderr)
  end

  def test_post_receive_default_builder
    repository = mock()

    OpenShift::Runtime::ApplicationRepository.expects(:new).returns(repository)

    @cartridge_model.expects(:builder_cartridge).returns(nil)

    primary = mock()
    @cartridge_model.stubs(:primary_cartridge).returns(primary)

    @cartridge_model.expects(:do_control).with('pre-repo-archive',
                                                primary,
                                                out:                       $stdout,
                                                err:                       $stderr,
                                                pre_action_hooks_enabled:  false,
                                                post_action_hooks_enabled: false)

    deployment_datetime = "abc"
    @container.expects(:create_deployment_dir).returns(deployment_datetime)

    repository.expects(:archive).with(PathUtils.join(@container.container_dir, 'app-deployments', deployment_datetime, 'repo'), 'master')

    @container.expects(:build).with(out: $stdout, err: $stderr, deployment_datetime: deployment_datetime)
    @container.expects(:prepare).with(out: $stdout, err: $stderr, deployment_datetime: deployment_datetime)
    @container.expects(:distribute).with(out: $stdout, err: $stderr, deployment_datetime: deployment_datetime)
    @container.expects(:activate).with(out: $stdout, err: $stderr, deployment_datetime: deployment_datetime)
    @container.expects(:report_build_analytics)

    @container.post_receive(out: $stdout, err: $stderr)
  end

  def test_pre_receive_builder_cart
    builder = mock()
    @cartridge_model.expects(:builder_cartridge).returns(builder)

    @cartridge_model.expects(:do_control).with('pre-receive', builder, out: $stdout, err: $stderr)

    @container.pre_receive(out: $stdout, err: $stderr)
  end

  def test_post_receive_builder_cart
    builder = mock()
    @cartridge_model.expects(:builder_cartridge).returns(builder)

    @cartridge_model.expects(:do_control).with('post-receive', builder, out: $stdout, err: $stderr)

    @container.expects(:report_build_analytics)

    @container.post_receive(out: $stdout, err: $stderr)
  end

  def test_build_success
    @state.expects(:value=).with(OpenShift::Runtime::State::BUILDING)

    deployment_datetime = "abc"
    @container.expects(:update_dependencies_symlink).with(deployment_datetime)

    primary = mock()
    @cartridge_model.expects(:primary_cartridge).returns(primary).times(3)

    env_overrides = {'OPENSHIFT_REPO_DIR' => PathUtils.join(@container.container_dir, 'app-deployments', deployment_datetime, 'repo') + "/"}

    @cartridge_model.expects(:do_control).with('update-configuration',
                                               primary,
                                               pre_action_hooks_enabled:  false,
                                               post_action_hooks_enabled: false,
                                               out:                       $stdout,
                                               err:                       $stderr,
                                               env_overrides:             env_overrides)
                                          .returns('update-configuration|')

    @cartridge_model.expects(:do_control).with('pre-build',
                                               primary,
                                               pre_action_hooks_enabled: false,
                                               prefix_action_hooks:      false,
                                               out:                      $stdout,
                                               err:                      $stderr,
                                               env_overrides:            env_overrides)
                                          .returns('pre-build|')

    @cartridge_model.expects(:do_control).with('build',
                                               primary,
                                               pre_action_hooks_enabled: false,
                                               prefix_action_hooks:      false,
                                               out:                      $stdout,
                                               err:                      $stderr,
                                               env_overrides:            env_overrides)
                                           .returns('build')

    output = @container.build(out: $stdout, err: $stderr, deployment_datetime: deployment_datetime)

    assert_equal "update-configuration|pre-build|build", output
  end

  def test_remote_deploy_success
    primary = mock()
    @cartridge_model.expects(:primary_cartridge).returns(primary)

    @cartridge_model.expects(:do_control).with('update-configuration',
                                               primary,
                                               pre_action_hooks_enabled:  false,
                                               post_action_hooks_enabled: false,
                                               out:                       $stdout,
                                               err:                       $stderr)
                                          .returns('')

    ::OpenShift::Runtime::Utils::Environ.expects(:for_gear).with(@container.container_dir).returns({})

    deployment_datetime = "now"

    [:prepare, :distribute, :activate].each do |method|
      @container.expects(method).with(out: $stdout, err: $stderr, deployment_datetime: deployment_datetime)
    end

    @container.remote_deploy(out: $stdout, err: $stderr, deployment_datetime: deployment_datetime)
  end

  def test_distribute_no_web_proxy
    #TODO implement/fix
    #@cartridge_model.expects(:web_proxy).returns(nil)
    #@container.distribute(out: $stdout, err: $stderr)
  end
end