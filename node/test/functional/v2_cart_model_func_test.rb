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

require_relative '../../lib/openshift-origin-node/model/v2_cart_model'
require_relative '../../lib/openshift-origin-node/model/cartridge'

require 'test/unit'
require 'mocha'
require 'pathname'

class V2CartModelFuncTest < Test::Unit::TestCase
  MockCartridge = Struct.new(:endpoints)

  # Called before every test method runs. Can be used
  # to set up fixture information.
  def setup
    skip "run_as tests require root permissions"  if 0 != Process.uid
    coverage_path = 'test/coverage'
    FileUtils.mkpath(coverage_path) unless File.exist? coverage_path
    File.chmod(0777, coverage_path)

    # TODO: is this a safe uid?
    @uid            = 501
    @uuid           = `uuidgen -r |sed -e s/-//g`.chomp
    @cartridge_name = 'mock-0.0'
    @cartridge_path = File.join(File::SEPARATOR, 'tmp', 'cartridges', 'v2', @cartridge_name)
    @homedir        = File.join(File::SEPARATOR, 'tmp', 'tests', @uuid)
    FileUtils.mkpath(@cartridge_path)

    # UnixUser tasks...
    FileUtils.mkpath(File.join(@homedir, 'git'))
    FileUtils.mkpath(File.join(@homedir, '.env'))

    # Cartridge Author tasks...
    perl = File.join(@cartridge_path, 'template', 'perl')
    FileUtils.mkpath(perl)
    File.open(File.join(perl, 'health_check.pl'), 'w', 0664) { |f|
      f.write(%Q{\
#!/usr/bin/perl
print "Content-type: text/plain\r\n\r\n";
print "1";
})
    }

    File.open(File.join(perl, 'index.pl'), 'w', 0664) { |f|
      f.write(%Q{\
#!/usr/bin/perl
print "Content-type: text/html\r\n\r\n";
print <<EOF
  <html>
    <head>
      <title>Welcome to OpenShift</title>
    </head>
    <body>
      <p>Welcome to OpenShift
    </body>
  </html>
EOF
})
    }

    setup   = File.join(File.join(@cartridge_path, 'bin', 'setup'))
    control = File.join(File.join(@cartridge_path, 'bin', 'control'))
    FileUtils.mkpath(Pathname.new(setup).parent.to_path)

    [setup, control].each { |script|
      File.open(script, 'w', 0755) { |f|
        f.write(%Q{\
#!/bin/bash
echo "#{f} Hello, World"
exit 0
})
      }
    }

    FileUtils.chown_R(@uid, @uid, @homedir)
    `chcon -R -r object_r -t openshift_var_lib_t -l s0:c0,c#@uid #@homedir`

    @config = mock('OpenShift::Config')
    @config.stubs(:get).with('BROKER_HOST').returns('localhost')
    @config.stubs(:get).with('CARTRIDGE_BASE_PATH').returns('/tmp/cartridges/v2')
    OpenShift::Config.stubs(:new).returns(@config)

    mock_cart = MockCartridge.new(Array.new)
    @gear     = mock('OpenShift::ApplicationContainer')
    @gear.stubs(:get_cartridge).with(@cartridge_name).returns(mock_cart)

    @user = mock('OpenShift::UnixUser')
    @user.stubs(:homedir).returns(@homedir)
    @user.stubs(:uid).returns(@uid)
    @user.stubs(:uuid).returns(@uuid)
    @user.stubs(:app_name).returns('mocking')
    @user.stubs(:get_mcs_label).with(any_parameters).returns("s0:c0,c#@uid")
    @user.stubs(:container_uuid).returns(@uuid)
    @user.stubs(:container_name).returns('mocking')
    @user.stubs(:namespace).returns('nowhere')

    @mock_frontend = mock("Mock Frontend")
    @mock_frontend.stubs(:reload_httpd).returns(true)
    OpenShift::FrontendHttpServer.stubs(:new).with(any_parameters).returns(@mock_frontend)
  end

  # Called after every test method runs. Can be used to tear
  # down fixture information.

  def teardown
    #FileUtils.rm_rf(@user.homedir)
  end

  def test_configure
    m = OpenShift::V2CartridgeModel.new(@config, @user, @gear)
    refute_nil m

    buffer = m.configure(@cartridge_name)
    refute_empty buffer
  end
end