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

require_relative '../../lib/openshift-origin-node/model/application_repository'
require 'test/unit'
require 'mocha'

class ApplicationRepositoryFuncTest < Test::Unit::TestCase
  User = Struct.new(:homedir, :uid, :app_name)

  # FIXME: I cannot get assert_path_exist method to resolve. :-(
  def assert_path_exist(path, message=nil)
    failure_message = build_message(message,
                                    "<?> expected to exist",
                                    path)
    assert_block(failure_message) do
      File.exist?(path)
    end
  end

  # Called before every test method runs. Can be used
  # to set up fixture information.
  def setup
    @uuid           = `uuidgen -r |sed -e s/-//g`.chomp
    @cartridge_name = 'mock-0.0'
    @user           = User.new("/tmp/tests/#@uuid", 1000, 'mocking')

    # UnixUser tasks...
    FileUtils.mkpath(File.join(@user.homedir, 'git'))
    File.chown(@user.uid, @user.uid, @user.homedir)
    `chcon -R -r object_r -t openshift_var_lib_t -l s0:c0,c#{@user.uid} #{@user.homedir}`

    # Cartridge Author tasks...
    perl = File.join(@user.homedir, @cartridge_name, 'template', 'perl')
    FileUtils.mkpath(perl)
    File.open(File.join(perl, 'health_check.pl'), 'w', 0664) { |f|
      f.write(%q{\
#!/usr/bin/perl
print "Content-type: text/plain\r\n\r\n";
print "1";
})
    }

    File.open(File.join(perl, 'index.pl'), 'w', 0664) { |f|
      f.write(%q{\
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

    @config = mock('OpenShift::Config')
    @config.stubs(:get).with("BROKER_HOST").returns("localhost")
    OpenShift::Config.stubs(:new).returns(@config)
  end

  # Called after every test method runs. Can be used to tear
  # down fixture information.

  def teardown
    FileUtils.rm_rf(@user.homedir)
  end

  def test_new
    repo = OpenShift::ApplicationRepository.new(@user)
    refute_nil repo
  end

  def test_populate_from_cartridge
    expected_path = File.join(@user.homedir, 'git', @user.app_name + '.git')
    refute File.exist?(expected_path), 'Error: target git repository already exists'

    repo          = OpenShift::ApplicationRepository.new(@user)

    begin
      repo.populate_from_cartridge(@cartridge_name)
    rescue OpenShift::Utils::ShellExecutionException => e
      puts %Q{
        Failed to create git repo from cartridge template: rc(#{e.rc})
        stdout ==> #{e.stdout}
        stderr ==> #{e.stderr}
           #{e.backtrace.join("\n")}}
      raise
    end

    assert_equal expected_path, repo.path

    assert_path_exist repo.path
    assert_path_exist File.join(repo.path, 'description')
    assert_path_exist File.join(@user.homedir, '.gitconfig')
    assert_path_exist File.join(repo.path, 'hooks', 'pre-receive')
    assert_path_exist File.join(repo.path, 'hooks', 'post-receive')

    files = Dir[repo.path + '/objects/**/*']
    assert files.count > 0, 'Error: Git repository missing objects'
    files.each { |f|
      stat = File.stat(f)
      assert_equal @user.uid, stat.uid, 'Error: Git object wrong ownership'
    }

    stat = File.stat(File.join(repo.path, 'hooks'))
    assert_equal 0, stat.uid, 'Error: Git hook directory not owned by root'

    stat = File.stat(File.join(repo.path, 'hooks', 'post-receive'))
    assert_equal 0, stat.uid, 'Error: Git hook post-receive not owned by root'
  end
end
