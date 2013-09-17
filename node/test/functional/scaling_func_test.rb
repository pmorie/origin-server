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

class ScalingFuncTest < OpenShift::NodeBareTestCase
  DEFAULT_TITLE = "Welcome to OpenShift"
  CHANGED_TITLE = "Test1"

  CART_TO_INDEX = {
    'ruby-1.8'     => 'config.ru',
    'ruby-1.9'     => 'config.ru',
    'php-5.3'      => 'php/index.php',
    'nodejs-0.6'   => 'index.html',
    'jbossas-7'    => 'src/main/webapp/index.html',
    'jbosseap-6'   => 'src/main/webapp/index.html',
    'jbossews-1.0' => 'src/main/webapp/index.html',
    'jbossews-2.0' => 'src/main/webapp/index.html',
    'python-2.6'   => 'wsgi/application',
    'python-2.7'   => 'wsgi/application',
    'python-3.3'   => 'wsgi/application',
    'perl-5.10'    => 'perl/perl/index.pl'
  }

  def setup
    @tmp_dir = "/var/tmp-tests/#{Time.now.to_i}"
    FileUtils.mkdir_p(@tmp_dir)

    log_config = mock()
    log_config.stubs(:get).with("PLATFORM_LOG_CLASS").returns("StdoutLogger")
    ::OpenShift::Runtime::NodeLogger.stubs(:load_config).returns(log_config)

    @created_domain_names = []
    @created_app_ids = []

    @login = "user#{random_string}"
    @namespace = "ns#{random_string}"
    @url_base = "https://#{@login}:password@localhost/broker/rest"

    # create domain
    RestClient.post("#{@url_base}/domains", {name: @namespace}, accept: :json)
    @created_domain_names << @namespace
    OpenShift::Runtime::NodeLogger.logger.info("Created domain #{@namespace} for user #{@login}")

    # keep up to 3 deployments
    `oo-admin-ctl-domain -l #{@login} -n #{@namespace} -c env_add -e OPENSHIFT_KEEP_DEPLOYMENTS -v 3`
  end

  def teardown
    unless ENV['PRESERVE']
      response = RestClient.get("#{@url_base}/domains/#{@namespace}/applications", accept: :json)
      response = JSON.parse(response)

      response['data'].each do |app_data|
        id = app_data['id']
        OpenShift::Runtime::NodeLogger.logger.info("Deleting application id #{id}")
        RestClient.delete("#{@url_base}/applications/#{id}")
      end

      @created_domain_names.each do |name|
        OpenShift::Runtime::NodeLogger.logger.info("Deleting domain #{name}")
        RestClient.delete("#{@url_base}/domains/#{name}")
      end
    end
  end

  # def test_ruby_scaled
  #   basic_build_test(%w(ruby-1.9))
  # end

  # def test_ruby_unscaled
  #   basic_build_test(%w(ruby-1.9), false)
  # end

  # def test_ruby_unscaled_jenkins
  #   create_jenkins
  #   basic_build_test(%w(ruby-1.9 jenkins-client-1), false)
  # end

  # def test_php_scaled
  #   basic_build_test(%w(php-5.3))
  # end

  # def test_php_unscaled
  #   basic_build_test(%w(php-5.3), false)
  # end

  # def test_php_unscaled_jenkins
  #   create_jenkins
  #   basic_build_test(%w(php-5.3 jenkins-client-1), false)
  # end

  # def test_php_scaled_jenkins
  #   up_gears
  #   create_jenkins
  #   basic_build_test(%w(php-5.3 jenkins-client-1))
  # end


  # def test_jbossas_scaled
  #   basic_build_test(%w(jbossas-7))
  # end

  # def test_jbossas_unscaled
  #   basic_build_test(%w(jbossas-7), false)
  # end

  # def test_jbossas_unscaled_jenkins
  #   create_jenkins
  #   basic_build_test(%w(jbossas-7 jenkins-client-1), false)
  # end

  def test_jbossas_scaled_jenkins
    up_gears
    create_jenkins
    basic_build_test(%w(jbossas-7 jenkins-client-1))
  end

  # def test_jbosseap_scaled
  #   basic_build_test(%w(jbosseap-6))
  # end

  # def test_jbosseap_unscaled
  #   basic_build_test(%w(jbosseap-6), false)
  # end

  # def test_jbosseap_unscaled_jenkins
  #   create_jenkins
  #   basic_build_test(%w(jbosseap-6 jenkins-client-1), false)
  # end

  # def test_jbosseap_scaled_jenkins
  #   up_gears
  #   create_jenkins
  #   basic_build_test(%w(jbosseap-6 jenkins-client-1))
  # end


  def create_jenkins
    app_name = "jenkins#{random_string}"
    create_application(app_name, %w(jenkins-1), false)
  end

  # def test_basic_ruby_18_scaling
  #   basic_build_test(%w(ruby-1.8))
  # end

  # def test_basic_php_scaling
  #   basic_build_test(%w(php-5.3))
  # end

  def basic_build_test(cartridges, scaling = true)
    app_name = "app#{random_string}"

    app_id = create_application(app_name, cartridges, scaling)
    add_ssh_key(app_id, app_name)

    framework = cartridges[0]

    if scaling
      app_container = OpenShift::Runtime::ApplicationContainer.from_uuid(app_id)
      gear_registry = OpenShift::Runtime::GearRegistry.new(app_container)
      entries = gear_registry.entries
      OpenShift::Runtime::NodeLogger.logger.info("Gear registry contents: #{entries}")
      assert_equal 1, entries.size
      entry = entries.values[0]

      assert_equal app_id, entry.uuid
      assert_equal @namespace, entry.namespace
      assert_equal "#{app_name}-#{@namespace}.dev.rhcloud.com", entry.dns
      assert_equal local_ip, entry.private_ip
      assert_equal IO.read(File.join(app_container.container_dir, '.env', 'OPENSHIFT_LOAD_BALANCER_PORT')).chomp, entry.proxy_port

      assert_http_title_for_entry entry, DEFAULT_TITLE

      # scale up to 2
      assert_scales_to app_name, framework, 2

      gear_registry.load
      entries = gear_registry.entries
      assert_equal 2, entries.size

      # make sure the http content is good
      entries.values.each do |entry| 
        OpenShift::Runtime::NodeLogger.logger.info("Checking title for #{entry}")
        assert_http_title_for_entry entry, DEFAULT_TITLE
      end
    else
      assert_http_title_for_app app_name, @namespace, DEFAULT_TITLE
    end

    # clone the git repo and make a change
    OpenShift::Runtime::NodeLogger.logger.info("Modifying the title and pushing the change")
    Dir.chdir(@tmp_dir) do
      response = RestClient.get("#{@url_base}/applications/#{app_id}", accept: :json)
      response = JSON.parse(response)
      git_url = response['data']['git_url']
      `git clone #{git_url}`
      Dir.chdir(app_name) do
        `sed -i "s,<title>.*</title>,<title>#{CHANGED_TITLE}</title>," #{CART_TO_INDEX[framework]}`
        `git commit -am 'test1'`
        `git push`
      end
    end

    if scaling
      # make sure the http content is updated
      entries.values.each { |entry| assert_http_title_for_entry entry, CHANGED_TITLE }

      # scale up to 3
      assert_scales_to app_name, framework, 3

      gear_registry.load
      entries = gear_registry.entries
      assert_equal 3, entries.size

      # make sure the http content is good
      entries.values.each { |entry| assert_http_title_for_entry entry, CHANGED_TITLE }

      # rollback
      OpenShift::Runtime::NodeLogger.logger.info("Rolling back")
      OpenShift::Runtime::NodeLogger.logger.info `ssh -o 'StrictHostKeyChecking=no' #{app_id}@localhost gear rollback`

      # make sure the http content is rolled back
      entries.values.each { |entry| assert_http_title_for_entry entry, DEFAULT_TITLE }
    else
      assert_http_title_for_app app_name, @namespace, CHANGED_TITLE

      OpenShift::Runtime::NodeLogger.logger.info("Rolling back")
      OpenShift::Runtime::NodeLogger.logger.info `ssh -o 'StrictHostKeyChecking=no' #{app_id}@localhost gear rollback`

      assert_http_title_for_app app_name, @namespace, DEFAULT_TITLE      
    end
  end

  def create_application(app_name, cartridges, scaling = true)
    OpenShift::Runtime::NodeLogger.logger.info("Creating app #{app_name} with cartridges: #{cartridges} with scaling: #{scaling}")
    response = RestClient.post("#{@url_base}/domains/#{@namespace}/applications", {name: app_name, cartridges: cartridges, scale: scaling}, accept: :json)
    response = JSON.parse(response)
    app_id = response['data']['id']
    @created_app_ids << app_id
    OpenShift::Runtime::NodeLogger.logger.info("Created app #{app_name} with id #{app_id}")

    app_id
  end

  def add_ssh_key(app_id, app_name)
    ssh_key = IO.read(File.expand_path('~/.ssh/id_rsa.pub')).chomp.split[1]
    `oo-authorized-ssh-key-add -a #{app_id} -c #{app_id} -s #{ssh_key} -t ssh-rsa -m default`
    File.open(File.expand_path('~/.ssh/config'), 'a', 0o0600) do |f|
      f.write <<END
Host #{app_name}-#{@namespace}.dev.rhcloud.com
  StrictHostKeyChecking no
END
    end  
  end

  def up_gears
    `oo-admin-ctl-user -l #{@login} --setmaxgears 5`
  end

  def random_string(len = 8)
    # Make sure this is an Array in case we pass a range
    charspace = ("1".."9").to_a
    (0...len).map{ charspace[rand(charspace.length)] }.join
  end

  def local_ip
    addrinfo     = Socket.getaddrinfo(Socket.gethostname, 80) # 80 is arbitrary
    private_addr = addrinfo.select { |info|
      info[3] !~ /^127/
    }.first
    private_ip   = private_addr[3]
  end

  def assert_http_title_for_entry(entry, expected)
    OpenShift::Runtime::NodeLogger.logger.info("Checking http://#{entry.dns}:#{entry.proxy_port}/ for title '#{expected}'")
    content = Net::HTTP.get(entry.dns, '/', entry.proxy_port)
    content =~ /<title>(.+)<\/title>/
    title = $~[1]
    assert_equal expected, title
  end

  def assert_http_title_for_app(app_name, namespace, expected)
    url = "http://#{app_name}-#{@namespace}.dev.rhcloud.com"
    OpenShift::Runtime::NodeLogger.logger.info("Checking http://#{url}/ for title '#{expected}'")
    content = Net::HTTP.get(URI.parse(url))
    content =~ /<title>(.+)<\/title>/
    title = $~[1]
    assert_equal expected, title
  end

  def assert_scales_to(app_name, cartridge, count)
    OpenShift::Runtime::NodeLogger.logger.info("Scaling to #{count}")
    response = RestClient.put("#{@url_base}/domains/#{@namespace}/applications/#{app_name}/cartridges/#{cartridge}", {scales_from: count}, {accept: :json, timeout: 60})
    response = JSON.parse(response)
    assert_equal count, response['data']['current_scale']
  end  
end
