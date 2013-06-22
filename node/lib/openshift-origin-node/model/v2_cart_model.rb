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

require 'rubygems'
require 'openshift-origin-node/model/unix_user'
require 'openshift-origin-node/model/application_repository'
require 'openshift-origin-node/model/cartridge_repository'
require 'openshift-origin-common/models/manifest'
require 'openshift-origin-node/model/pub_sub_connector'
require 'openshift-origin-node/utils/shell_exec'
require 'openshift-origin-node/utils/selinux'
require 'openshift-origin-node/utils/node_logger'
require 'openshift-origin-node/utils/cgroups'
require 'openshift-origin-node/utils/sdk'
require 'openshift-origin-node/utils/environ'
require 'openshift-origin-common/utils/path_utils'
require 'openshift-origin-node/utils/application_state'
require 'openshift-origin-node/utils/managed_files'
require 'openshift-origin-node/utils/sanitize'

module OpenShift
  class FileLockError < Exception
    attr_reader :filename

    def initialize(msg = nil, filename)
      super(msg)
      @filename = filename
    end
  end

  class FileUnlockError < Exception
    attr_reader :filename

    def initialize(msg = nil, filename)
      super(msg)
      @filename = filename
    end
  end

  class V2CartridgeModel
    include NodeLogger
    include ManagedFiles

    def initialize(config, user, state, hourglass)
      @config     = config
      @user       = user
      @state      = state
      @timeout    = 30
      @cartridges = {}
      @hourglass  = hourglass
    end



















    ##
    # Shuts down the gear by running the cartridge +stop+ control action for each cartridge 
    # in the gear.
    #
    # +options+: hash
    #   :user_initiated => [boolean]  : Indicates whether the operation was user initated.
    #                                   Default is +true+.
    #   :out                          : An +IO+ object to which control script STDOUT should be directed. If
    #                                   +nil+ (the default), output is logged.
    #   :err                          : An +IO+ object to which control script STDERR should be directed. If
    #                                   +nil+ (the default), output is logged.
    #
    # Returns the combined output of all +stop+ action executions as a +String+.
    def stop_gear(options={})
      options[:user_initiated] = true if not options.has_key?(:user_initiated)

      buffer = ''

      each_cartridge do |cartridge|
        buffer << stop_cartridge(cartridge, options)
      end

      buffer
    end

    ##
    # Starts up the gear by running the cartridge +start+ control action for each 
    # cartridge in the gear.
    #
    # By default, all cartridges in the gear are started. The selection of cartridges
    # to be started is configurable via +options+.
    #
    # +options+: hash
    #   :primary_only   => [boolean]  : If +true+, only the primary cartridge will be started.
    #                                   Mutually exclusive with +secondary_only+.
    #   :secondary_only => [boolean]  : If +true+, all cartridges except the primary cartridge
    #                                   will be started. Mutually exclusive with +primary_only+.
    #   :user_initiated => [boolean]  : Indicates whether the operation was user initated.
    #                                   Default is +true+.
    #   :out                          : An +IO+ object to which control script STDOUT should be directed. If
    #                                   +nil+ (the default), output is logged.
    #   :err                          : An +IO+ object to which control script STDERR should be directed. If
    #                                   +nil+ (the default), output is logged.
    #
    # Returns the combined output of all +start+ action executions as a +String+.
    def start_gear(options={})
      options[:user_initiated] = true if not options.has_key?(:user_initiated)

      if options[:primary_only] && options[:secondary_only]
        raise ArgumentError.new('The primary_only and secondary_only options are mutually exclusive options')
      end

      buffer = ''
      each_cartridge do |cartridge|
        next if options[:primary_only] and cartridge.name != primary_cartridge.name
        next if options[:secondary_only] and cartridge.name == primary_cartridge.name

        buffer << start_cartridge('start', cartridge, options)
      end

      buffer
    end

    ##
    # Starts a cartridge.
    #
    # Both application state and the stop lock are managed during the operation. If start
    # of the primary cartridge is invoked and +user_initiated+ is true, the stop lock is
    # created.
    #
    # +type+      : Type of start [start, restart, reload]
    # +cartridge+ : A +Cartridge+ instance or +String+ name of a cartridge.
    # +options+   : hash
    #   :user_initiated => [boolean]  : Indicates whether the operation was user initated.
    #                                   Default is +true+.
    #   :hot_deploy => [boolean]      : If +true+ and if +cartridge+ is the primary cartridge in the gear, the
    #                                   gear state will be set to +STARTED+ but the actual cartridge start operation
    #                                   will be skipped. Non-primary cartridges will be skipped with no state change.
    #                                   Default is +false+.
    #   :out                          : An +IO+ object to which control script STDOUT should be directed. If
    #                                   +nil+ (the default), output is logged.
    #   :err                          : An +IO+ object to which control script STDERR should be directed. If
    #                                   +nil+ (the default), output is logged.
    #
    # Returns the output of the operation as a +String+ or raises a +ShellExecutionException+
    # if the cartridge script fails.
    def start_cartridge(type, cartridge, options={})
      options[:user_initiated] = true if not options.has_key?(:user_initiated)
      options[:hot_deploy] = false if not options.has_key?(:hot_deploy)

      cartridge = get_cartridge(cartridge) if cartridge.is_a?(String)

      if not options[:user_initiated] and stop_lock?
        return "Not starting cartridge #{cartridge.name} because the application was explicitly stopped by the user"
      end

      if cartridge.name == primary_cartridge.name
        FileUtils.rm_f(stop_lock) if options[:user_initiated]
        @state.value = OpenShift::State::STARTED

        # Unidle the application, preferring to use the privileged operation if possible
        frontend = FrontendHttpServer.new(@user.uuid)
        if Process.uid == @user.uid
          frontend.unprivileged_unidle
        else
          frontend.unidle
        end
      end

      if options[:hot_deploy]
        output = "Not starting cartridge #{cartridge.name} because hot deploy is enabled"
        options[:out].puts(output) if options[:out]
        return output
      end

      do_control(type, cartridge, options)
    end

    ##
    # Stops a cartridge.
    #
    # Both application state and the stop lock are managed during the operation. If stop
    # of the primary cartridge is invoked and +user_initiated+ is true, the stop lock
    # is removed.
    #
    # +cartridge+ : A +Cartridge+ instance or +String+ name of a cartridge.
    # +options+   : hash
    #   :user_initiated => [boolean]  : Indicates whether the operation was user initated.
    #                                   Default is +true+.
    #   :hot_deploy => [boolean]      : If +true+, the stop operation is skipped for all cartridge types,
    #                                   the gear state is not modified, and the stop lock is never created.
    #                                   Default is +false+. 
    #   :out                          : An +IO+ object to which control script STDOUT should be directed. If
    #                                   +nil+ (the default), output is logged.
    #   :err                          : An +IO+ object to which control script STDERR should be directed. If
    #                                   +nil+ (the default), output is logged.
    #
    # Returns the output of the operation as a +String+ or raises a +ShellExecutionException+
    # if the cartridge script fails.
    def stop_cartridge(cartridge, options={})
      options[:user_initiated] = true if not options.has_key?(:user_initiated)
      options[:hot_deploy] = false if not options.has_key?(:hot_deploy)

      cartridge = get_cartridge(cartridge) if cartridge.is_a?(String)

      if options[:hot_deploy]
        output = "Not stopping cartridge #{cartridge.name} because hot deploy is enabled"
        options[:out].puts(output) if options[:out]
        return output
      end

      if not options[:user_initiated] and stop_lock?
        return "Not stopping cartridge #{cartridge.name} because the application was explicitly stopped by the user\n"
      end

      if cartridge.name == primary_cartridge.name
        create_stop_lock if options[:user_initiated]
        @state.value = OpenShift::State::STOPPED
      end

      do_control('stop', cartridge, options)
    end

    ##
    # Writes the +stop_lock+ file and changes its ownership to the gear user.
    def create_stop_lock
      unless stop_lock?
        mcs_label = Utils::SELinux.get_mcs_label(@user.uid)
        File.new(stop_lock, File::CREAT|File::TRUNC|File::WRONLY, 0644).close()
        PathUtils.oo_chown(@user.uid, @user.gid, stop_lock)
        Utils::SELinux.set_mcs_label(mcs_label, stop_lock)
      end
    end

    ##
    # Generate an RSA ssh key
    def generate_ssh_key(cartridge)
      ssh_dir        = File.join(@user.homedir, '.openshift_ssh')
      known_hosts    = File.join(ssh_dir, 'known_hosts')
      ssh_config     = File.join(ssh_dir, 'config')
      ssh_key        = File.join(ssh_dir, 'id_rsa')
      ssh_public_key = ssh_key + '.pub'

      FileUtils.mkdir_p(ssh_dir)
      make_user_owned(ssh_dir)

      Utils::oo_spawn("/usr/bin/ssh-keygen -N '' -f #{ssh_key}",
                      chdir:               @user.homedir,
                      uid:                 @user.uid,
                      gid:                 @user.gid,
                      timeout:             @hourglass.remaining,
                      expected_exitstatus: 0)

      FileUtils.touch(known_hosts)
      FileUtils.touch(ssh_config)

      make_user_owned(ssh_dir)

      FileUtils.chmod(0750, ssh_dir)
      FileUtils.chmod(0600, [ssh_key, ssh_public_key])
      FileUtils.chmod(0660, [known_hosts, ssh_config])

      @user.add_env_var('APP_SSH_KEY', ssh_key, true)
      @user.add_env_var('APP_SSH_PUBLIC_KEY', ssh_public_key, true)

      public_key_bytes = IO.read(ssh_public_key)
      public_key_bytes.sub!(/^ssh-rsa /, '')

      output = "APP_SSH_KEY_ADD: #{cartridge.directory} #{public_key_bytes}\n"
      # The BROKER_AUTH_KEY_ADD token does not use any arguments.  It tells the broker
      # to enable this gear to make REST API calls on behalf of the user who owns this gear.
      output << "BROKER_AUTH_KEY_ADD: \n"
      output
    end

    ##
    # Change the ownership and SELinux context of the target
    # to be owned as the user using the user's MCS labels
    def make_user_owned(target)
      mcs_label = Utils::SELinux.get_mcs_label(@user.uid)

      PathUtils.oo_chown_R(@user.uid, @user.gid, target)
      Utils::SELinux.set_mcs_label_R(mcs_label, target)
    end

    private
    ## special methods that are handled especially by the platform
    def publish_gear_endpoint
      begin
        # TODO:
        # There is some concern about how well-behaved Facter is
        # when it is require'd.
        # Instead, we use oo_spawn here to avoid it altogether.
        # For the long-term, then, figure out a way to reliably
        # determine the IP address from Ruby.
        out, err, status = Utils.oo_spawn('facter ipaddress',
                                          env:                 cartridge_env,
                                          unsetenv_others:     true,
                                          chdir:               @user.homedir,
                                          uid:                 @user.uid,
                                          timeout:             @hourglass.remaining,
                                          expected_exitstatus: 0)
        private_ip       = out.chomp
      rescue
        require 'socket'
        addrinfo     = Socket.getaddrinfo(Socket.gethostname, 80) # 80 is arbitrary
        private_addr = addrinfo.select { |info|
          info[3] !~ /^127/
        }.first
        private_ip   = private_addr[3]
      end

      env = Utils::Environ::for_gear(@user.homedir)

      output = "#{env['OPENSHIFT_GEAR_UUID']}@#{private_ip}:#{primary_cartridge.name};#{env['OPENSHIFT_GEAR_DNS']}"
      logger.debug output
      output
    end
  end
end
