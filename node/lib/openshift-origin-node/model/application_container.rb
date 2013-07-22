#--
# Copyright 2010 Red Hat, Inc.
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
require 'openshift-origin-node/model/frontend_proxy'
require 'openshift-origin-node/model/frontend_httpd'
require 'openshift-origin-node/model/v2_cart_model'
require 'openshift-origin-common/models/manifest'
require 'openshift-origin-node/model/application_container_ext/environment'
require 'openshift-origin-node/model/application_container_ext/setup'
require 'openshift-origin-node/model/application_container_ext/snapshots'
require 'openshift-origin-node/model/application_container_ext/cartridge_actions'
require 'openshift-origin-node/utils/shell_exec'
require 'openshift-origin-node/utils/application_state'
require 'openshift-origin-node/utils/environ'
require 'openshift-origin-node/utils/sdk'
require 'openshift-origin-node/utils/node_logger'
require 'openshift-origin-node/utils/hourglass'
require 'openshift-origin-node/utils/cgroups'
require 'openshift-origin-common'
require 'yaml'
require 'active_model'
require 'json'
require 'rest-client'
require 'openshift-origin-node/utils/managed_files'
require 'timeout'

module OpenShift
  module Runtime
    class UserCreationException < Exception
    end

    class UserDeletionException < Exception
    end

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

    # == Application Container
    class ApplicationContainer
      include ActiveModel::Observing
      include NodeLogger
      include ManagedFiles
      include ApplicationContainerExt::Environment
      include ApplicationContainerExt::Setup
      include ApplicationContainerExt::Snapshots
      include ApplicationContainerExt::CartridgeActions

      GEAR_TO_GEAR_SSH = "/usr/bin/ssh -q -o 'BatchMode=yes' -o 'StrictHostKeyChecking=no' -i $OPENSHIFT_APP_SSH_KEY "
      DEFAULT_SKEL_DIR = PathUtils.join(OpenShift::Config::CONF_DIR,"skel")
      $OpenShift_ApplicationContainer_SSH_KEY_MUTEX = Mutex.new

      attr_reader :uuid, :application_uuid, :state, :container_name, :application_name, :namespace, :container_dir,
                  :quota_blocks, :quota_files, :base_dir, :gecos, :skel_dir, :supplementary_groups,
                  :container_plugin, :hourglass
      attr_accessor :uid, :gid

      containerization_plugin_gem = ::OpenShift::Config.new.get('CONTAINERIZATION_PLUGIN') 
      containerization_plugin_gem ||= 'openshift-origin-container-selinux'

      begin
        require containerization_plugin_gem
      rescue LoadError => e
        raise ArgumentError.new("error loading #{containerization_plugin_gem}: #{e.message}")
      end

      if !::OpenShift::Runtime::Containerization::Plugin.respond_to?(:container_dir)
        raise ArgumentError.new('containerization plugin must respond to container_dir')
      end
      
      def initialize(application_uuid, container_uuid, user_uid = nil, application_name = nil, container_name = nil,
                     namespace = nil, quota_blocks = nil, quota_files = nil, hourglass = nil)
        @config           = ::OpenShift::Config.new
        @uuid             = container_uuid
        @application_uuid = application_uuid
        @container_name   = container_name
        @application_name = application_name
        @namespace        = namespace
        @quota_blocks     = quota_blocks
        @quota_files      = quota_files
        @uid              = user_uid
        @gid              = user_uid
        @base_dir         = @config.get("GEAR_BASE_DIR")
        @skel_dir         = @config.get("GEAR_SKEL_DIR") || DEFAULT_SKEL_DIR
        @supplementary_groups = @config.get("GEAR_SUPPLEMENTARY_GROUPS")
        @hourglass        = hourglass || ::OpenShift::Runtime::Utils::Hourglass.new(3600)
        @timeout          = 30
        @cartridges       = {}

        begin
          user_info         = Etc.getpwnam(@uuid)
          @uid              = user_info.uid
          @gid              = user_info.gid
          @gecos            = user_info.gecos
          @container_dir    = "#{user_info.dir}/"
          @container_plugin = Containerization::Plugin.new(self)
        rescue ArgumentError => e
          @uid              = user_uid
          @gid              = user_uid 
          @gecos            = @config.get("GEAR_GECOS") || "OO application container"
          @container_dir    = Containerization::Plugin.container_dir(self)
          @container_plugin = nil
        end

        @state = ::OpenShift::Runtime::Utils::ApplicationState.new(self)
      end

      #
      # Public: Return a ApplicationContainer object loaded from the gear_uuid on the system
      #
      # Caveat: the quota information will not be populated.
      #
      def self.from_uuid(container_uuid, hourglass=nil)
        config = ::OpenShift::Config.new
        gecos  = config.get("GEAR_GECOS") || "OO application container"
        pwent  = Etc.getpwnam(container_uuid)

        if pwent.gecos != gecos
          raise ArgumentError, "Not an OpenShift gear: #{container_uuid}"
        end

        env = ::OpenShift::Runtime::Utils::Environ.for_gear(pwent.dir)
        if env['OPENSHIFT_GEAR_DNS'] == nil
          namespace = nil
        else
          namespace = env['OPENSHIFT_GEAR_DNS'].sub(/\..*$/,"").sub(/^.*\-/,"")
        end

        ApplicationContainer.new(env["OPENSHIFT_APP_UUID"], container_uuid, pwent.uid, env["OPENSHIFT_APP_NAME"],
                                 env["OPENSHIFT_GEAR_NAME"], namespace, nil, nil, hourglass)
      end

      def name
        @container_name
      end

      def get_ip_addr(host_id)
        @container_plugin.get_ip_addr(host_id)
      end

      # create gear
      #
      # - model/unix_user.rb
      # context: root
      def create
        notify_observers(:before_container_create)
        # lock to prevent race condition between create and delete of gear
        uuid_lock_file = "/var/lock/oo-create.#{@uuid}"
        File.open(uuid_lock_file, File::RDWR|File::CREAT|File::TRUNC, 0o0600) do | uuid_lock |
          uuid_lock.fcntl(Fcntl::F_SETFD, Fcntl::FD_CLOEXEC)
          uuid_lock.flock(File::LOCK_EX)

          @container_plugin = Containerization::Plugin.new(self)
          @container_plugin.create

          if @config.get("CREATE_APP_SYMLINKS").to_i == 1
            unobfuscated = PathUtils.join(File.dirname(@container_dir),"#{@container_name}-#{@namespace}")
            if not File.exists? unobfuscated
              FileUtils.ln_s File.basename(@container_dir), unobfuscated, :force=>true
            end
          end

          uuid_lock.flock(File::LOCK_UN)
        end

        notify_observers(:after_container_create)
      end

      # destroy(skip_hooks = false) -> [buffer, '', 0]
      #
      # Remove all cartridges from a gear and delete the gear.  Accepts
      # and discards any parameters to comply with the signature of V1
      # require, which accepted a single argument.
      #
      # destroy() => ['', '', 0]
      # Destroy gear
      #
      # - model/unix_user.rb
      # context: root
      # @param skip_hooks should destroy call the gear's hooks before destroying the gear
      def destroy(skip_hooks=false)
        notify_observers(:before_container_destroy)

        if @uid.nil? or (@container_dir.nil? or !File.directory?(@container_dir.to_s))
          # gear seems to have been destroyed already... suppress any error
          # TODO : remove remaining stuff if it exists, e.g. .httpd/#{uuid}* etc
          return ['', '', 0]
        end

        notify_endpoint_delete = ''
        output = ''
        errout = ''
        retcode = -1

        # Don't try to delete a gear that is being scaled-up|created|deleted
        uuid_lock_file = "/var/lock/oo-create.#{@uuid}"
        File.open(uuid_lock_file, File::RDWR|File::CREAT|File::TRUNC, 0o0600) do | lock |
          lock.fcntl(Fcntl::F_SETFD, Fcntl::FD_CLOEXEC)
          lock.flock(File::LOCK_EX)

          env = ::OpenShift::Runtime::Utils::Environ::for_gear(@container_dir)

          each_cartridge do |cart|
            cart.public_endpoints.each do |endpoint|
              notify_endpoint_delete << "NOTIFY_ENDPOINT_DELETE: #{endpoint.public_port_name} #{@config.get('PUBLIC_IP')} #{env[endpoint.public_port_name]}\n"
            end

            begin
              unless skip_hooks
                unlock_gear(cart, false) do |c|
                  begin
                    buffer << cartridge_teardown(c.directory, false)
                  rescue ::OpenShift::Runtime::Utils::ShellExecutionException => e
                    logger.warn("Cartridge teardown operation failed on gear #{uuid} for cartridge #{c.directory}: #{e.message} (rc=#{e.rc})")
                  end
                end
              end
            rescue Exception => e
              logger.warn("Cartridge teardown operation failed on gear #{uuid} for some cartridge: #{e.message}")
              output << "CLIENT_ERROR: Abandoned cartridge teardowns. There may be extraneous data left on system."
            end
          end

          # Ensure we're not in the gear's directory
          Dir.chdir(@config.get("GEAR_BASE_DIR"))
          retcode = 0

          raise UserDeletionException.new("ERROR: unable to destroy user account #{@uuid}") if @uuid.nil?

          @container_plugin.destroy

          if @config.get("CREATE_APP_SYMLINKS").to_i == 1
            Dir.foreach(File.dirname(@container_dir)) do |dent|
              unobfuscate = PathUtils.join(File.dirname(@container_dir), dent)
              if (File.symlink?(unobfuscate)) &&
                  (File.readlink(unobfuscate) == File.basename(@container_dir))
                File.unlink(unobfuscate)
              end
            end
          end

          lock.flock(File::LOCK_UN)
        end

        output += notify_endpoint_delete

        notify_observers(:after_container_destroy)

        return output, errout, retcode
      end

      # Public: Sets the app state to "stopped" and causes an immediate forced
      # termination of all gear processes.
      #
      # TODO: exception handling
      def force_stop
        @state.value = State::STOPPED
        create_stop_lock
        @container_plugin.stop
      end

      #
      # Kill processes belonging to this app container.
      #
      def kill_procs
        # Give it a good try to delete all processes.
        # This abuse is neccessary to release locks on polyinstantiated
        #    directories by pam_namespace.
        out = err = rc = nil
        10.times do |i|
          ::OpenShift::Runtime::Utils::oo_spawn(%{/usr/bin/pkill -9 -u #{uid}})
          out,err,rc = ::OpenShift::Runtime::Utils::oo_spawn(%{/usr/bin/pgrep -u #{uid}})
          break unless 0 == rc

          logger.error "ERROR: attempt #{i}/10 there are running \"killed\" processes for #{uid}(#{rc}): stdout: #{out} stderr: #{err}"
          sleep 0.5
        end

        # looks backwards but 0 implies processes still existed
        if 0 == rc
          out,err,rc = ::OpenShift::Runtime::Utils::oo_spawn("ps -u #{uid} -o state,pid,ppid,cmd")
          logger.error "ERROR: failed to kill all processes for #{uid}(#{rc}): stdout: #{out} stderr: #{err}"
        end
      end

      # Public: Cleans up the gear, providing any installed
      # cartridges with the opportunity to perform their own
      # cleanup operations via the tidy hook.
      #
      # The generic gear-level cleanup flow is:
      # * Stop the gear
      # * Gear temp dir cleanup
      # * Cartridge tidy hook executions
      # * Git cleanup
      # * Start the gear
      #
      # Raises an Exception if an internal error occurs, and ignores
      # failed cartridge tidy hook executions.
      def tidy
        logger.debug("Starting tidy on gear #{@uuid}")

        env      = ::OpenShift::Runtime::Utils::Environ::for_gear(@container_dir)
        gear_dir = env['OPENSHIFT_HOMEDIR']
        app_name = env['OPENSHIFT_APP_NAME']

        raise 'Missing required env var OPENSHIFT_HOMEDIR' unless gear_dir
        raise 'Missing required env var OPENSHIFT_APP_NAME' unless app_name

        gear_repo_dir = PathUtils.join(gear_dir, 'git', "#{app_name}.git")
        gear_tmp_dir  = PathUtils.join(gear_dir, '.tmp')

        stop_gear(user_initiated: false)

        # Perform the gear- and cart- level tidy actions.  At this point, the gear has
        # been stopped; we'll attempt to start the gear no matter what tidy operations fail.
        begin
          # clear out the tmp dir
          gear_level_tidy_tmp(gear_tmp_dir)

          # Delegate to cartridge model to perform cart-level tidy operations for all installed carts.
          each_cartridge do |cartridge|
            begin
              output = do_control('tidy', cartridge)
            rescue ::OpenShift::Runtime::Utils::ShellExecutionException => e
              logger.warn("Tidy operation failed for cartridge #{cartridge.name} on "\
                          "gear #{uuid}: #{e.message} (rc=#{e.rc}), output=#{output}")
            end
          end

          # git gc - do this last to maximize room  for git to write changes
          gear_level_tidy_git(gear_repo_dir)
        rescue Exception => e
          logger.warn("An unknown exception occured during tidy for gear #{@uuid}: #{e.message}\n#{e.backtrace}")
        ensure
          start_gear(user_initiated: false)
        end

        logger.debug("Completed tidy for gear #{@uuid}")
      end

      ##
      # Idles the gear if there is no stop lock and state is not already +STOPPED+.
      #
      def idle_gear(options={})
        if not stop_lock? and (state.value != State::STOPPED)
          frontend = FrontendHttpServer.new(self)
          frontend.idle
          begin
            output = stop_gear
          ensure
            state.value = State::IDLE
          end
          output
        end
      end

      ##
      # Unidles the gear.
      #
      def unidle_gear(options={})
        output = ""
        OpenShift::Runtime::Utils::Cgroups::with_no_cpu_limits(@uuid) do
          if stop_lock? and (state.value == State::IDLE)
            state.value = State::STARTED
            output      = start_gear
          end

          frontend = FrontendHttpServer.new(self)
          if frontend.idle?
            frontend.unidle
          end
        end
        output
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
      ##
      # Sets the application state to +STOPPED+ and stops the gear. Gear stop implementation
      # is model specific, but +options+ is provided to the implementation.
      def stop_gear(options={})
        options[:user_initiated] = true if not options.has_key?(:user_initiated)

        buffer = ''

        each_cartridge do |cartridge|
          buffer << stop_cartridge(cartridge, options)
        end

        unless buffer.empty?
          buffer.chomp!
          buffer << "\n"
        end

        buffer << stopped_status_attr
        buffer
      end

      def gear_level_tidy_tmp(gear_tmp_dir)
        # Temp dir cleanup
        tidy_action do
          FileUtils.rm_rf(Dir.glob(PathUtils.join(gear_tmp_dir, "*")))
          logger.debug("Cleaned gear temp dir at #{gear_tmp_dir}")
        end
      end

      def gear_level_tidy_git(gear_repo_dir)
        # Git pruning
        tidy_action do
          run_in_container_context('git prune', chdir: gear_repo_dir, expected_exitstatus: 0, timeout: @hourglass.remaining)
          logger.debug("Pruned git directory at #{gear_repo_dir}")
        end

        # Git GC
        tidy_action do
          run_in_container_context('git gc --aggressive', chdir: gear_repo_dir, expected_exitstatus: 0, timeout: @hourglass.remaining)
          logger.debug("Executed git gc for repo #{gear_repo_dir}")
        end
      end

      # Executes a block, trapping ShellExecutionExceptions and treating them
      # as warnings. Any other exceptions are unexpected and will bubble out.
      def tidy_action
        begin
          yield
        rescue ::OpenShift::Runtime::Utils::ShellExecutionException => e
          logger.warn(%Q{
            Tidy operation failed on gear #{@uuid}: #{e.message}
            --- stdout ---\n#{e.stdout}
            --- stderr ---\n#{e.stderr}
                      })
        end
      end

      ##
      # Get the gear groups for the application this gear is part of.
      #
      # Returns the parsed JSON for the response.
      def get_gear_groups(gear_env)
        broker_addr = @config.get('BROKER_HOST')
        domain = gear_env['OPENSHIFT_NAMESPACE']
        app_name = gear_env['OPENSHIFT_APP_NAME']
        url = "https://#{broker_addr}/broker/rest/domains/#{domain}/applications/#{app_name}/gear_groups.json"

        params = {
          'broker_auth_key' => File.read(PathUtils.join(@config.get('GEAR_BASE_DIR'), uuid, '.auth', 'token')).chomp,
          'broker_auth_iv' => File.read(PathUtils.join(@config.get('GEAR_BASE_DIR'), uuid, '.auth', 'iv')).chomp
        }

        request = RestClient::Request.new(:method => :get,
                                          :url => url,
                                          :timeout => 120,
                                          :headers => { :accept => 'application/json;version=1.0', :user_agent => 'OpenShift' },
                                          :payload => params)

        begin
          response = request.execute()

          if 300 <= response.code
            raise response
          end
        rescue
          raise
        end

        begin
          gear_groups = JSON.parse(response)
        rescue
          raise
        end

        gear_groups
      end

      ##
      # Given a list of gear groups, return the secondary gear groups
      def get_secondary_gear_groups(groups)
        secondary_groups = {}

        groups['data'].each do |group|
          group['cartridges'].each do |cartridge|
            cartridge['tags'].each do |tag|
              if tag == 'database'
                secondary_groups[cartridge['name']] = group
              end
            end
          end
        end

        secondary_groups
      end

      def stopped_status_attr
        if state.value == State::STOPPED || stop_lock?
          "ATTR: status=ALREADY_STOPPED\n"
        elsif state.value == State::IDLE
          "ATTR: status=ALREADY_IDLED\n"
        else
          ''
        end
      end

      def empty_repository?
        ApplicationRepository.new(self).empty?
      end

      def stop_lock
        PathUtils.join(@container.container_dir, 'app-root', 'runtime', '.stop_lock')
      end

      def stop_lock?
        File.exists?(stop_lock)
      end

      ##
      # Writes the +stop_lock+ file and changes its ownership to the gear user.
      def create_stop_lock
        unless stop_lock?
          mcs_label = ::OpenShift::Runtime::Utils::SELinux.get_mcs_label(uid)
          File.new(stop_lock, File::CREAT|File::TRUNC|File::WRONLY, 0644).close()
          set_rw_permission(stop_lock)
        end
      end

      ##
      # Yields a +Cartridge+ instance for each cartridge in the gear.
      #
      def each_cartridge
        process_cartridges do |cartridge_dir|
          cartridge = get_cartridge_from_directory(File.basename(cartridge_dir))
          yield cartridge
        end
      end

      ##
      # Returns the primary +Cartridge+ in the gear as specified by the
      # +OPENSHIFT_PRIMARY_CARTRIDGE_DIR+ environment variable, or +Nil+ if
      # no primary cartridge is present.
      #
      def primary_cartridge
        env              = ::OpenShift::Runtime::Utils::Environ.for_gear(@container.container_dir)
        primary_cart_dir = env['OPENSHIFT_PRIMARY_CARTRIDGE_DIR']

        raise "No primary cartridge detected in gear #{@container.uuid}" unless primary_cart_dir

        return get_cartridge_from_directory(File.basename(primary_cart_dir))
      end

      ##
      # Returns the +Cartridge+ in the gear whose +web_proxy+ flag is set to
      # true, nil otherwise
      #
      def web_proxy
        each_cartridge do |cartridge|
          return cartridge if cartridge.web_proxy?
        end
        nil
      end

      ##
      # Detects and returns a builder +Cartridge+ in the gear if present, otherwise +nil+.
      #
      def builder_cartridge
        builder_cart = nil
        each_cartridge do |c|
          if c.categories.include? 'ci_builder'
            builder_cart = c
            break
          end
        end
        builder_cart
      end

      # FIXME: Once Broker/Node protocol updated to provided necessary information this hack must go away
      def map_cartridge_name(cartridge_name)
        results = cartridge_name.scan(/([a-zA-Z\d-]+)-([\d\.]+)/).first
        raise "Invalid cartridge identifier '#{cartridge_name}': expected name-version" unless results && 2 == results.size
        results
      end

      def cartridge_directory(cart_name)
        name, _  = map_cartridge_name(cart_name)
        cart_dir = Dir.glob(PathUtils.join(container_dir, "#{name}"))
        raise "Ambiguous cartridge name #{cart_name}: found #{cart_dir}:#{cart_dir.size}" if 1 < cart_dir.size
        raise "Cartridge directory not found for #{cart_name}" if  1 > cart_dir.size

        File.basename(cart_dir.first)
      end

      # Load the cartridge's local manifest from the Broker token 'name-version'
      def get_cartridge(cart_name)
        unless @cartridges.has_key? cart_name
          cart_dir = ''
          begin
            cart_dir = cartridge_directory(cart_name)

            @cartridges[cart_name] = get_cartridge_from_directory(cart_dir)
          rescue Exception => e
            logger.error e.message
            logger.error e.backtrace.join("\n")
            raise "Failed to get cartridge '#{cart_name}' from #{cart_dir} in gear #{uuid}: #{e.message}"
          end
        end

        @cartridges[cart_name]
      end

      # Load cartridge's local manifest from cartridge directory name
      def get_cartridge_from_directory(directory)
        raise "Directory name is required" if (directory == nil || directory.empty?)

        unless @cartridges.has_key? directory
          cartridge_path = PathUtils.join(container_dir, directory)
          manifest_path  = PathUtils.join(cartridge_path, 'metadata', 'manifest.yml')
          ident_path     = Dir.glob(PathUtils.join(cartridge_path, 'env', "OPENSHIFT_*_IDENT")).first

          raise "Cartridge manifest not found: #{manifest_path} missing" unless File.exists?(manifest_path)
          raise "Cartridge Ident not found: #{ident_path} missing" unless File.exists?(ident_path)

          _, _, version, _ = Runtime::Manifest.parse_ident(IO.read(ident_path))

          @cartridges[directory] = Manifest.new(manifest_path, version, container_dir)
        end
        @cartridges[directory]
      end

      # Load the cartridge's local manifest from the Broker token 'name-version'
      def get_cartridge_fallback(cart_name)
        directory = cartridge_directory(cart_name)
        _, version  = map_cartridge_name(cart_name)

        raise "Directory name is required" if (directory == nil || directory.empty?)

        cartridge_path = PathUtils.join(container_dir, directory)
        manifest_path  = PathUtils.join(cartridge_path, 'metadata', 'manifest.yml')

        raise "Cartridge manifest not found: #{manifest_path} missing" unless File.exists?(manifest_path)

        Manifest.new(manifest_path, version, container_dir)
      end

      # Finds the next IP address available for binding of the given port for
      # the current gear user. The IP is assumed to be available only if the IP is
      # not already associated with an existing endpoint defined by any cartridge within the gear.
      #
      # Returns a string IP address in dotted-quad notation if one is available
      # for the given port, or returns nil if IP is available.
      def find_open_ip(port)
        allocated_ips = get_allocated_private_ips
        logger.debug("IPs already allocated for #{port} in gear #{uuid}: #{allocated_ips}")

        open_ip = nil

        for host_ip in 1..127
          candidate_ip = get_ip_addr(host_ip)

          # Skip the IP if it's already assigned to an endpoint
          next if allocated_ips.include?(candidate_ip)

          open_ip = candidate_ip
          break
        end

        open_ip
      end

      # Returns true if the given IP and port are currently bound
      # according to lsof, otherwise false.
      def address_bound?(ip, port)
        _, _, rc = run_in_container_context("/usr/sbin/lsof -i @#{ip}:#{port}", timeout: @hourglass.remaining)
        rc == 0
      end

      def addresses_bound?(addresses)
        command = "/usr/sbin/lsof"
        addresses.each do |addr|
          command << " -i @#{addr[:ip]}:#{addr[:port]}"
        end

        _, _, rc = @container.run_in_container_context(command, timeout: @hourglass.remaining)
        rc == 0
      end

      # Returns an array containing all currently allocated endpoint private
      # IP addresses assigned to carts within the current gear, or an empty
      # array if none are currently defined.
      def get_allocated_private_ips
        env = ::OpenShift::Runtime::Utils::Environ::for_gear(container_dir)

        allocated_ips = []

        # Collect all existing endpoint IP allocations
        process_cartridges do |cart_path|
          cart_dir = File.basename(cart_path)
          cart     = get_cartridge_from_directory(cart_dir)

          cart.endpoints.each do |endpoint|
            # TODO: If the private IP variable exists but the value isn't in
            # the environment, what should happen?
            ip = env[endpoint.private_ip_name]
            allocated_ips << ip unless ip == nil
          end
        end

        allocated_ips
      end

      ##
      # Generate an RSA ssh key
      def generate_ssh_key(cartridge)
        ssh_dir        = PathUtils.join(@container.container_dir, '.openshift_ssh')
        known_hosts    = PathUtils.join(ssh_dir, 'known_hosts')
        ssh_config     = PathUtils.join(ssh_dir, 'config')
        ssh_key        = PathUtils.join(ssh_dir, 'id_rsa')
        ssh_public_key = ssh_key + '.pub'

        FileUtils.mkdir_p(ssh_dir)
        set_rw_permission(ssh_dir)

        run_in_container_context("/usr/bin/ssh-keygen -N '' -f #{ssh_key}",
                                 chdir:               @container.container_dir,
                                 timeout:             @hourglass.remaining,
                                 expected_exitstatus: 0)

        FileUtils.touch(known_hosts)
        FileUtils.touch(ssh_config)

        set_rw_permission_R(ssh_dir)

        FileUtils.chmod(0750, ssh_dir)
        FileUtils.chmod(0600, [ssh_key, ssh_public_key])
        FileUtils.chmod(0660, [known_hosts, ssh_config])

        add_env_var('APP_SSH_KEY', ssh_key, true)
        add_env_var('APP_SSH_PUBLIC_KEY', ssh_public_key, true)

        public_key_bytes = IO.read(ssh_public_key)
        public_key_bytes.sub!(/^ssh-rsa /, '')

        output = "APP_SSH_KEY_ADD: #{cartridge.directory} #{public_key_bytes}\n"
        # The BROKER_AUTH_KEY_ADD token does not use any arguments.  It tells the broker
        # to enable this gear to make REST API calls on behalf of the user who owns this gear.
        output << "BROKER_AUTH_KEY_ADD: \n"
        output
      end

      #
      # Send a fire-and-forget request to the broker to report build analytics.
      #
      def report_build_analytics
        broker_addr = @config.get('BROKER_HOST')
        url         = "https://#{broker_addr}/broker/nurture"

        payload = {
          "json_data" => {
            "app_uuid" => @application_uuid,
            "action"   => "push"
          }.to_json
        }

        request = RestClient::Request.new(:method => :post,
                                          :url => url,
                                          :timeout => 30,
                                          :open_timeout => 30,
                                          :headers => { :user_agent => 'OpenShift' },
                                          :payload => payload)

        pid = fork do
          Process.daemon
          begin
            Timeout::timeout(60) do
              response = request.execute()
            end
          rescue
            # ignore it
          end

          exit!
        end

        Process.detach(pid)
      end

      #
      # Public: Return an enumerator which provides an ApplicationContainer object
      # for every OpenShift gear in the system.
      #
      # Caveat: the quota information will not be populated.
      #
      def self.all(hourglass=nil)
        Enumerator.new do |yielder|
          config = OpenShift::Config.new
          gecos = config.get("GEAR_GECOS") || "OO application container"

          # Some duplication with from_uuid; it may be expensive to keep re-parsing passwd.
          # Etc is not reentrent.  Capture the password table in one shot.
          pwents = []
          Etc.passwd do |pwent|
            if pwent.gecos == gecos
              pwents << pwent.clone
            end
          end

          pwents.each do |pwent|
            env = ::OpenShift::Runtime::Utils::Environ.for_gear(pwent.dir)
            if env['OPENSHIFT_GEAR_DNS'] == nil
              namespace = nil
            else
              namespace = env['OPENSHIFT_GEAR_DNS'].sub(/\..*$/,"").sub(/^.*\-/,"")
            end

            begin
              a=ApplicationContainer.new(env["OPENSHIFT_APP_UUID"], pwent.name, pwent.uid, env["OPENSHIFT_APP_NAME"],
                                         env["OPENSHIFT_GEAR_NAME"], namespace, nil, nil, hourglass)
            rescue => e
              NodeLogger.logger.error("Failed to instantiate ApplicationContainer for uid #{pwent.uid}/uuid #{env["OPENSHIFT_APP_UUID"]}: #{e}")
              NodeLogger.logger.error("Backtrace: #{e.backtrace}")
            else
              yielder.yield(a)
            end
          end
        end
      end

      # run_in_container_context(command, [, options]) -> [stdout, stderr, exit status]
      #
      # Executes specified command and return its stdout, stderr and exit status.
      # Or, raise exceptions if certain conditions are not met.
      # The command is as container user in a SELinux context using runuser/runcon.
      # The environment variables are cleared and mys be specified by :env.
      #
      # command: command line string which is passed to the standard shell
      #
      # options: hash
      #   :env: hash
      #     name => val : set the environment variable
      #     name => nil : unset the environment variable
      #   :chdir => path             : set current directory when running command
      #   :expected_exitstatus       : An Integer value for the expected return code of command
      #                              : If not set spawn() returns exitstatus from command otherwise
      #                              : raise an error if exitstatus is not expected_exitstatus
      #   :timeout                   : Maximum number of seconds to wait for command to finish. default: 3600
      #                              : stdin for the command is /dev/null
      #   :out                       : If specified, STDOUT from the child process will be redirected to the
      #                                provided +IO+ object.
      #   :err                       : If specified, STDERR from the child process will be redirected to the
      #                                provided +IO+ object.
      #
      # NOTE: If the +out+ or +err+ options are specified, the corresponding return value from +run_in_container_context+
      # will be the incoming/provided +IO+ objects instead of the buffered +String+ output. It's the
      # responsibility of the caller to correctly handle the resulting data type.
      def run_in_container_context(command, options = {})
        @container_plugin.run_in_container_context(command, options)
      end

      def reset_permission(paths)
        @container_plugin.reset_permission(paths)
      end

      def reset_permission_R(paths)
        @container_plugin.reset_permission_R(paths)
      end

      def set_ro_permission_R(paths)
        @container_plugin.set_ro_permission_R(paths)
      end

      def set_ro_permission(paths)
        @container_plugin.set_ro_permission(paths)
      end

      def set_rw_permission_R(paths)
        @container_plugin.set_rw_permission_R(paths)
      end

      def set_rw_permission(paths)
        @container_plugin.set_rw_permission(paths)
      end

      private
      ## special methods that are handled especially by the platform
      def publish_gear_endpoint
        begin
          # TODO:
          # There is some concern about how well-behaved Facter is
          # when it is require'd.
          # Instead, we use run_in_container_context here to avoid it altogether.
          # For the long-term, then, figure out a way to reliably
          # determine the IP address from Ruby.
          out, err, status = @container.run_in_container_context('facter ipaddress',
              env:                 cartridge_env,
              chdir:               @container.container_dir,
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

        env = ::OpenShift::Runtime::Utils::Environ::for_gear(@container.container_dir)

        output = "#{env['OPENSHIFT_GEAR_UUID']}@#{private_ip}:#{primary_cartridge.name};#{env['OPENSHIFT_GEAR_DNS']}"
        logger.debug output
        output
      end
    end
  end
end
