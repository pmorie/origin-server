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
require "test/unit"
require "mocha"
require "openshift-origin-node/utils/shell_exec"
require 'test_helper'

module OpenShift
  class UtilsSpawnFunctionalTest < Test::Unit::TestCase
    def test_run_as
      skip "run_as tests require root permissions"  if 0 != Process.uid

      uid = 1000
      out, err, rc = Utils.oo_spawn("touch #{Process.pid}.b",
                                 :chdir => "/tmp",
                                 :uid => uid)
      assert_equal 0, rc
      assert_empty err
      assert_empty out
      stats = File.stat(File.join("/tmp", Process.pid.to_s + ".b"))
      assert_equal uid, stats.uid

      c = File.join("/tmp", Process.pid.to_s + ".c")
      FileUtils.touch c
      stats = File.stat(c)
      assert_equal Process.uid, stats.uid
    end

    def test_run_as_stdout
      skip "run_as tests require root permissions"  if 0 != Process.uid

      uid = 1000
      out, err, rc = Utils.oo_spawn("echo Hello, World",
                                 :chdir => "/tmp",
                                 :uid => uid)
      assert_equal 0, rc
      assert_empty err
      assert_equal "Hello, World\n", out
    end
  end
end
