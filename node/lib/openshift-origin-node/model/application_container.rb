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
require 'openshift-origin-node/model/unix_user'
require 'openshift-origin-node/model/v2_cart_model'
require 'openshift-origin-common/models/manifest'
require 'openshift-origin-node/utils/shell_exec'
require 'openshift-origin-node/utils/application_state'
require 'openshift-origin-node/utils/environ'
require 'openshift-origin-node/utils/sdk'
require 'openshift-origin-node/utils/node_logger'
require 'openshift-origin-node/utils/hourglass'
require 'openshift-origin-node/utils/cgroups'
require 'openshift-origin-node/utils/managed_files'
require 'openshift-origin-node/utils/sanitize'
require 'openshift-origin-common'
require 'yaml'
require 'active_model'
require 'json'
require 'rest-client'
require 'openshift-origin-node/utils/managed_files'
require 'timeout'

module OpenShift
  # == Application Container
  class ApplicationContainer
    include OpenShift::Utils::ShellExec
    include ActiveModel::Observing
    include NodeLogger
    include ManagedFiles

    GEAR_TO_GEAR_SSH = "/usr/bin/ssh -q -o 'BatchMode=yes' -o 'StrictHostKeyChecking=no' -i $OPENSHIFT_APP_SSH_KEY "

    attr_reader :uuid, :application_uuid, :user, :state, :container_name, :cartridge_model

    def initialize(application_uuid, container_uuid, user_uid = nil,
        app_name = nil, container_name = nil, namespace = nil, quota_blocks = nil, quota_files = nil, hourglass = nil)

      @config           = OpenShift::Config.new
      @uuid             = container_uuid
      @application_uuid = application_uuid
      @container_name   = container_name
      @user             = UnixUser.new(application_uuid, container_uuid, user_uid,
                                       app_name, container_name, namespace, quota_blocks, quota_files)
      @state            = OpenShift::Utils::ApplicationState.new(container_uuid)
      @hourglass        = hourglass || Utils::Hourglass.new(3600)
      @timeout          = 30
      @cartridges       = {}

      @cartridge_model = V2CartridgeModel.new(@config, @user, @state, @hourglass)
    end

    def name
      @uuid
    end

    #
    # Yields a +Cartridge+ instance for each cartridge in the gear.
    #
    def each_cartridge
      process_cartridges do |cartridge_dir|
        cartridge = get_cartridge_from_directory(File.basename(cartridge_dir))
        yield cartridge
      end
    end

    #
    # Returns the primary +Cartridge+ in the gear as specified by the
    # +OPENSHIFT_PRIMARY_CARTRIDGE_DIR+ environment variable, or +Nil+ if
    # no primary cartridge is present.
    #
    def primary_cartridge
      env              = Utils::Environ.for_gear(@user.homedir)
      primary_cart_dir = env['OPENSHIFT_PRIMARY_CARTRIDGE_DIR']

      raise "No primary cartridge detected in gear #{@user.uuid}" unless primary_cart_dir

      return get_cartridge_from_directory(File.basename(primary_cart_dir))
    end

    #
    # Returns the +Cartridge+ in the gear whose +web_proxy+ flag is set to
    # true, nil otherwise
    #
    def web_proxy
      each_cartridge do |cartridge|
        return cartridge if cartridge.web_proxy?
      end

      nil
    end

    #
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

    #
    # FIXME: Once Broker/Node protocol updated to provided necessary information this hack must go away
    #
    def map_cartridge_name(cartridge_name)
      results = cartridge_name.scan(/([a-zA-Z\d-]+)-([\d\.]+)/).first
      raise "Invalid cartridge identifier '#{cartridge_name}': expected name-version" unless results && 2 == results.size
      results
    end

    #
    # Return the directory for a given cartridge name in the gear.
    #
    def cartridge_directory(cart_name)
      name, _  = map_cartridge_name(cart_name)
      cart_dir = Dir.glob(PathUtils.join(@user.homedir, "#{name}"))
      raise "Ambiguous cartridge name #{cart_name}: found #{cart_dir}:#{cart_dir.size}" if 1 < cart_dir.size
      raise "Cartridge directory not found for #{cart_name}" if  1 > cart_dir.size

      File.basename(cart_dir.first)
    end

    #
    # Load the cartridge's local manifest from the Broker token 'name-version'
    #
    def get_cartridge(cart_name)
      unless @cartridges.has_key? cart_name
        cart_dir = ''
        begin
          cart_dir = cartridge_directory(cart_name)

          @cartridges[cart_name] = get_cartridge_from_directory(cart_dir)
        rescue Exception => e
          logger.error e.message
          logger.error e.backtrace.join("\n")
          raise "Failed to get cartridge '#{cart_name}' from #{cart_dir} in gear #{@user.uuid}: #{e.message}"
        end
      end

      @cartridges[cart_name]
    end

    # Load cartridge's local manifest from cartridge directory name
    def get_cartridge_from_directory(directory)
      raise "Directory name is required" if (directory == nil || directory.empty?)

      unless @cartridges.has_key? directory
        cartridge_path = PathUtils.join(@user.homedir, directory)
        manifest_path  = PathUtils.join(cartridge_path, 'metadata', 'manifest.yml')
        ident_path     = Dir.glob(PathUtils.join(cartridge_path, 'env', "OPENSHIFT_*_IDENT")).first

        raise "Cartridge manifest not found: #{manifest_path} missing" unless File.exists?(manifest_path)
        raise "Cartridge Ident not found: #{ident_path} missing" unless File.exists?(ident_path)

        _, _, version, _ = Runtime::Manifest.parse_ident(IO.read(ident_path))

        @cartridges[directory] = OpenShift::Runtime::Manifest.new(manifest_path, version, @user.homedir)
      end
      
      @cartridges[directory]
    end

    #----- Gear locking methods -----

    # unlock_gear(cartridge_name) -> nil
    #
    # Prepare the given cartridge for the cartridge author
    #
    #   v2_cart_model.unlock_gear('php-5.3')
    def unlock_gear(cartridge, relock = true)
      begin
        do_unlock(locked_files(cartridge))
        yield cartridge
      ensure
        do_lock(locked_files(cartridge)) if relock
      end
      nil
    end

    # do_unlock_gear(array of file names) -> array
    #
    # Take the given array of file system entries and prepare them for the cartridge author
    #
    #   v2_cart_model.do_unlock_gear(entries)
    def do_unlock(entries)
      mcs_label = Utils::SELinux.get_mcs_label(@user.uid)

      entries.each do |entry|
        if entry.end_with?('/')
          entry.chomp!('/')
          FileUtils.mkpath(entry, mode: 0755) unless File.exist? entry
        else
          # FileUtils.touch not used as it doesn't support mode
          File.new(entry, File::CREAT|File::TRUNC|File::WRONLY, 0644).close() unless File.exist?(entry)
        end
        # It is expensive doing one file at a time but...
        # ...it allows reporting on the failed command at the file level
        # ...we don't have to worry about the length of argv
        begin
          PathUtils.oo_chown(@user.uid, @user.gid, entry)
          Utils::SELinux.set_mcs_label(mcs_label, entry)
        rescue Exception => e
          raise OpenShift::FileUnlockError.new("Failed to unlock file system entry [#{entry}]: #{e}",
                                               entry)
        end
      end

      begin
        PathUtils.oo_chown(@user.uid, @user.gid, @user.homedir)
      rescue Exception => e
        raise OpenShift::FileUnlockError.new(
                  "Failed to unlock gear home [#{@user.homedir}]: #{e}",
                  @user.homedir)
      end
    end

    # do_lock_gear(array of file names) -> array
    #
    # Take the given array of file system entries and prepare them for the application developer
    #    v2_cart_model.do_lock_gear(entries)
    def do_lock(entries)
      mcs_label = Utils::SELinux.get_mcs_label(@user.uid)

      # It is expensive doing one file at a time but...
      # ...it allows reporting on the failed command at the file level
      # ...we don't have to worry about the length of argv
      entries.each do |entry|
        begin
          PathUtils.oo_chown(0, @user.gid, entry)
          Utils::SELinux.set_mcs_label(mcs_label, entry)
        rescue Exception => e
          raise OpenShift::FileLockError.new("Failed to lock file system entry [#{entry}]: #{e}",
                                             entry)
        end
      end

      begin
        PathUtils.oo_chown(0, @user.gid, @user.homedir)
      rescue Exception => e
        raise OpenShift::FileLockError.new("Failed to lock gear home [#{@user.homedir}]: #{e}",
                                           @user.homedir)
      end
    end

    #----- Cartridge add/remove internal methods -----

    # create_cartridge_directory(cartridge name) -> nil
    #
    # Create the cartridges home directory
    #
    #   v2_cart_model.create_cartridge_directory('php-5.3')
    def create_cartridge_directory(cartridge, software_version)
      logger.info("Creating cartridge directory #{@user.uuid}/#{cartridge.directory}")

      target = File.join(@user.homedir, cartridge.directory)
      CartridgeRepository.instantiate_cartridge(cartridge, target)

      ident = Runtime::Manifest.build_ident(cartridge.cartridge_vendor,
                                            cartridge.name,
                                            software_version,
                                            cartridge.cartridge_version)

      envs                                  = {}
      envs["#{cartridge.short_name}_DIR"]   = target + File::SEPARATOR
      envs["#{cartridge.short_name}_IDENT"] = ident

      write_environment_variables(File.join(target, 'env'), envs)

      envs.clear
      envs['namespace'] = @user.namespace if @user.namespace

      # If there's not already a primary cartridge on the gear, assume
      # the new cartridge is the primary.
      current_gear_env = Utils::Environ.for_gear(@user.homedir)
      unless current_gear_env['OPENSHIFT_PRIMARY_CARTRIDGE_DIR']
        envs['primary_cartridge_dir'] = target + File::SEPARATOR
        logger.info("Cartridge #{cartridge.name} recorded as primary within gear #{@user.uuid}")
      end

      unless envs.empty?
        write_environment_variables(File.join(@user.homedir, '.env'), envs)
      end

      # Gear level actions: Placed here to be off the V1 code path...
      old_path = File.join(@user.homedir, '.env', 'PATH')
      File.delete(old_path) if File.file? old_path

      secure_cartridge(cartridge.short_name, @user.uid, @user.gid, target)

      logger.info("Created cartridge directory #{@user.uuid}/#{cartridge.directory}")
      nil
    end

    # process_erb_templates(cartridge_name) -> nil
    #
    # Search cartridge for any remaining <code>erb</code> files render them
    def process_erb_templates(cartridge)
      directory = PathUtils.join(@user.homedir, cartridge.name)
      logger.info "Processing ERB templates for #{cartridge.name}"

      env  = Utils::Environ.for_gear(@user.homedir, directory)
      erbs = processed_templates(cartridge).map { |x| PathUtils.join(@user.homedir, x) }
      render_erbs(env, erbs)
    end    

    def secure_cartridge(short_name, uid, gid=uid, cartridge_home)
      Dir.chdir(cartridge_home) do
        make_user_owned(cartridge_home)

        files = ManagedFiles::IMMUTABLE_FILES.collect do |file|
          file.gsub!('*', short_name)
          file if File.exist?(file)
        end || []
        files.compact!

        unless files.empty?
          PathUtils.oo_chown(0, gid, files)
          FileUtils.chmod(0644, files)
        end
      end
    end

    ##
    # Write out environment variables.
    def write_environment_variables(path, hash, prefix = true)
      FileUtils.mkpath(path) unless File.exist? path

      hash.each_pair do |k, v|
        name = k.to_s.upcase

        if prefix
          name = "OPENSHIFT_#{name}"
        end

        File.open(PathUtils.join(path, name), 'w', 0666) do |f|
          f.write(v)
        end
      end
    end

    def delete_cartridge_directory(cartridge)
      logger.info("Deleting cartridge directory for #{@user.uuid}/#{cartridge.directory}")
      # TODO: rm_rf correct?
      FileUtils.rm_rf(File.join(@user.homedir, cartridge.directory))
      logger.info("Deleted cartridge directory for #{@user.uuid}/#{cartridge.directory}")
    end    

    #
    # Add cartridge to gear.  This method establishes the cartridge model
    # to use, but does not mark the application.  Marking the application
    # is the responsibility of the cart model.
    #
    # This method does not enforce constraints on whether the cartridge
    # being added is compatible with other installed cartridges.  That
    # is the responsibility of the broker.
    #
    # context: root -> gear user -> root
    # @param cart_name         cartridge name
    # @param template_git_url  URL for template application source/bare repository
    # @param manifest          Broker provided manifest
    def configure(cart_name, template_git_url=nil,  manifest=nil)
      output                 = ''
      name, software_version = map_cartridge_name(cartridge_name)
      cartridge              = if manifest
                                 logger.debug("Loading from manifest...")
                                 Runtime::Manifest.new(manifest, software_version)
                               else
                                 CartridgeRepository.instance.select(name, software_version)
                               end

      OpenShift::Utils::Sdk.mark_new_sdk_app(@user.homedir)
      OpenShift::Utils::Cgroups::with_no_cpu_limits(@user.uuid) do
        create_cartridge_directory(cartridge, software_version)
        # Note: the following if statement will check the following criteria long-term:
        # 1. Is the app scalable?
        # 2. Is this the head gear?
        # 3. Is this the first time the platform has generated an ssh key?
        #
        # In the current state of things, the following check is sufficient to test all
        # of these criteria, and we do not have a way to explicitly check the first two
        # criteria.  However, it should be considered a TODO to add more explicit checks.
        if cartridge.web_proxy?
          output << generate_ssh_key(cartridge)
        end

        create_private_endpoints(cartridge)

        Dir.chdir(PathUtils.join(@user.homedir, cartridge.directory)) do
          unlock_gear(cartridge) do |c|
            output << cartridge_action(cartridge, 'setup', software_version, true)
            process_erb_templates(c)
            output << cartridge_action(cartridge, 'install', software_version)
            output << populate_gear_repo(c.directory, template_git_url) if cartridge.deployable?
          end

        end

        connect_frontend(cartridge)
      end

      logger.info "configure output: #{output}"
      return output
    rescue Utils::ShellExecutionException => e
      rc_override = e.rc < 100 ? 157 : e.rc
      raise Utils::Sdk.translate_shell_ex_for_client(e, rc_override)
    rescue => e
      ex =  RuntimeError.new(Utils::Sdk.translate_out_for_client(e.message, :error))
      ex.set_backtrace(e.backtrace)
      raise ex
    end

    def post_configure(cart_name, template_git_url=nil)
      output = ''

      cartridge = @cartridge_model.get_cartridge(cart_name)
      cartridge_home = PathUtils.join(@user.homedir, cartridge.directory)

      # Only perform an initial build if the manifest explicitly specifies a need,
      # or if a template Git URL is provided and the cart is capable of builds or deploys.
      if (cartridge.install_build_required || template_git_url) && cartridge.buildable?
        build_log = '/tmp/initial-build.log'
        env       = Utils::Environ.for_gear(@user.homedir)

        begin
          logger.info "Executing initial gear prereceive for #{@uuid}"
          Utils.oo_spawn("gear prereceive >> #{build_log} 2>&1",
                         env:                 env,
                         chdir:               @user.homedir,
                         uid:                 @user.uid,
                         timeout:             @hourglass.remaining,
                         expected_exitstatus: 0)

          logger.info "Executing initial gear postreceive for #{@uuid}"
          Utils.oo_spawn("gear postreceive >> #{build_log} 2>&1",
                         env:                 env,
                         chdir:               @user.homedir,
                         uid:                 @user.uid,
                         timeout:             @hourglass.remaining,
                         expected_exitstatus: 0)
        rescue Utils::ShellExecutionException => e
          max_bytes = 10 * 1024
          out, _, _ = Utils.oo_spawn("tail -c #{max_bytes} #{build_log} 2>&1",
                         env:                 env,
                         chdir:               @user.homedir,
                         uid:                 @user.uid,
                         timeout:             @hourglass.remaining)

          message = "The initial build for the application failed: #{e.message}\n\n.Last #{max_bytes/1024} kB of build output:\n#{out}"

          raise Utils::Sdk.translate_out_for_client(message, :error)
        end
      end

      output = ''

      begin
        name, software_version = map_cartridge_name(cartridge_name)
        cartridge              = get_cartridge(name)

        OpenShift::Utils::Cgroups::with_no_cpu_limits(@user.uuid) do
          output << start_cartridge('start', cartridge, user_initiated: true)
          output << cartridge_action(cartridge, 'post_install', software_version)
        end

        logger.info("post-configure output: #{output}")
      rescue Utils::ShellExecutionException => e
        raise Utils::Sdk.translate_shell_ex_for_client(e, 157)
      end

      output
    end

    def post_install(cartridge, software_version, options = {})
      output = cartridge_action(cartridge, 'post_install', software_version)
      options[:out].puts(output) if options[:out]
      output
    end

    #
    # deconfigure(cartridge_name) -> nil
    #
    # Remove cartridge from gear with the following workflow:
    #
    #   1. Delete private endpoints
    #   2. Stop the cartridge
    #   3. Execute the cartridge `control teardown` action
    #   4. Disconnect the frontend for the cartridge
    #   5. Delete the cartridge directory
    #
    # If the cartridge stop or teardown operations fail, the error output will be
    # captured, but the frontend will still be disconnect and the cartridge directory
    # will be deleted.
    #
    # context: root -> gear user -> root
    # @param cart_name   cartridge name
    def deconfigure(cart_name)
      teardown_output = ''

      cartridge = get_cartridge(cartridge_name)
      delete_private_endpoints(cartridge)
      OpenShift::Utils::Cgroups::with_no_cpu_limits(@user.uuid) do
        begin
          stop_cartridge(cartridge, user_initiated: true)
          unlock_gear(cartridge, false) do |c|
            teardown_output << cartridge_teardown(c.directory)            
          end
        rescue Utils::ShellExecutionException => e
          teardown_output << Utils::Sdk::translate_out_for_client(e.stdout, :error)
          teardown_output << Utils::Sdk::translate_out_for_client(e.stderr, :error)
        ensure
          disconnect_frontend(cartridge)
          delete_cartridge_directory(cartridge)
        end
      end

      teardown_output
    end

    #
    # Unsubscribe from a cart
    #
    # @param cart_name   unsubscribing cartridge name
    # @param cart_name   publishing cartridge name
    def unsubscribe(cart_name, pub_cart_name)
      @cartridge_model.unsubscribe(cart_name, pub_cart_name)
    end

    # create gear
    #
    # - model/unix_user.rb
    # context: root
    def create
      notify_observers(:before_container_create)

      @user.create

      notify_observers(:after_container_create)
    end

    # Destroy gear
    #
    # - model/unix_user.rb
    # context: root
    # @param skip_hooks should destroy call the gear's hooks before destroying the gear
    def destroy(skip_hooks=false)
      notify_observers(:before_container_destroy)

      # possible mismatch across cart model versions
      output, errout, retcode = perform_destroy(skip_hooks)

      notify_observers(:after_container_destroy)

      return output, errout, retcode
    end

    # destroy(skip_hooks = false) -> [buffer, '', 0]
    #
    # Remove all cartridges from a gear and delete the gear.  Accepts
    # and discards any parameters to comply with the signature of V1
    # require, which accepted a single argument.
    #
    # destroy() => ['', '', 0]
    def perform_destroy(skip_hooks = false)  # NOTE: renamed while inlining v2 cart model
      logger.info('V2 destroy')

      buffer = ''
      unless skip_hooks
        each_cartridge do |cartridge|
          unlock_gear(cartridge, false) do |c|
            begin
              buffer << cartridge_teardown(c.directory, false)
            rescue Utils::ShellExecutionException => e
              logger.warn("Cartridge teardown operation failed on gear #{@user.uuid} for cartridge #{c.directory}: #{e.message} (rc=#{e.rc})")
            end
          end
        end
      end

      # Ensure we're not in the gear's directory
      Dir.chdir(@config.get("GEAR_BASE_DIR"))

      @user.destroy

      # FIXME: V1 contract is there a better way?
      [buffer, '', 0]
    end


    # Public: Sets the app state to "stopped" and causes an immediate forced
    # termination of all gear processes.
    #
    # TODO: exception handling
    def force_stop
      @state.value = OpenShift::State::STOPPED
      @cartridge_model.create_stop_lock
      UnixUser.kill_procs(@user.uid)
    end

    # Creates public endpoints for the given cart. Public proxy mappings are created via
    # the FrontendProxyServer, and the resulting mapped ports are written to environment
    # variables with names based on the cart manifest endpoint entries.
    #
    # Returns nil on success, or raises an exception if any errors occur: all errors here
    # are considered fatal.
    def create_public_endpoints(cart_name)
      env  = Utils::Environ::for_gear(@user.homedir)
      cart = @cartridge_model.get_cartridge(cart_name)

      proxy = OpenShift::FrontendProxyServer.new

      # TODO: better error handling
      cart.public_endpoints.each do |endpoint|
        # Load the private IP from the gear
        private_ip = env[endpoint.private_ip_name]

        if private_ip == nil
          raise "Missing private IP #{endpoint.private_ip_name} for cart #{cart.name} in gear #{@uuid}, "\
            "required to create public endpoint #{endpoint.public_port_name}"
        end

        # Attempt the actual proxy mapping assignment
        public_port = proxy.add(@user.uid, private_ip, endpoint.private_port)

        @user.add_env_var(endpoint.public_port_name, public_port)

        logger.info("Created public endpoint for cart #{cart.name} in gear #{@uuid}: "\
          "[#{endpoint.public_port_name}=#{public_port}]")
      end
    end

    # Deletes all public endpoints for the given cart. Public port mappings are
    # looked up and deleted using the FrontendProxyServer, and all corresponding
    # environment variables are deleted from the gear.
    #
    # Returns nil on success. Failed public port delete operations are logged
    # and skipped.
    def delete_public_endpoints(cart_name)
      env  = Utils::Environ::for_gear(@user.homedir)
      cart = @cartridge_model.get_cartridge(cart_name)

      proxy = OpenShift::FrontendProxyServer.new

      public_ports     = []
      public_port_vars = []

      cart.public_endpoints.each do |endpoint|
        # Load the private IP from the gear
        private_ip = env[endpoint.private_ip_name]

        public_port_vars << endpoint.public_port_name

        public_port = proxy.find_mapped_proxy_port(@user.uid, private_ip, endpoint.private_port)

        public_ports << public_port unless public_port == nil
      end

      begin
        # Remove the proxy entries
        rc = proxy.delete_all(public_ports, true)
        logger.info("Deleted all public endpoints for cart #{cart.name} in gear #{@uuid}\n"\
          "Endpoints: #{public_port_vars}\n"\
          "Public ports: #{public_ports}")
      rescue => e
        logger.warn(%Q{Couldn't delete all public endpoints for cart #{cart.name} in gear #{@uuid}: #{e.message}
          Endpoints: #{public_port_vars}
          Public ports: #{public_ports}
                    #{e.backtrace}
                    })
      end

      # Clean up the environment variables
      public_port_vars.each { |var| @user.remove_env_var(var) }
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

      env      = Utils::Environ::for_gear(@user.homedir)
      gear_dir = env['OPENSHIFT_HOMEDIR']
      app_name = env['OPENSHIFT_APP_NAME']

      raise 'Missing required env var OPENSHIFT_HOMEDIR' unless gear_dir
      raise 'Missing required env var OPENSHIFT_APP_NAME' unless app_name

      gear_repo_dir = File.join(gear_dir, 'git', "#{app_name}.git")
      gear_tmp_dir  = File.join(gear_dir, '.tmp')

      stop_gear(user_initiated: false)

      # Perform the gear- and cart- level tidy actions.  At this point, the gear has
      # been stopped; we'll attempt to start the gear no matter what tidy operations fail.
      begin
        # clear out the tmp dir
        gear_level_tidy_tmp(gear_tmp_dir)

        # tidy each cartridge
        each_cartridge do |cartridge|
          begin
            output = do_control('tidy', cartridge)
          rescue Utils::ShellExecutionException => e
            logger.warn("Tidy operation failed for cartridge #{cartridge.name} on "\
                        "gear #{@user.uuid}: #{e.message} (rc=#{e.rc}), output=#{output}")
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
    # Sets the application state to +STOPPED+ and stops the gear. Gear stop implementation
    # is model specific, but +options+ is provided to the implementation.
    def stop_gear(options={})
      buffer = @cartridge_model.stop_gear(options)
      unless buffer.empty?
        buffer.chomp!
        buffer << "\n"
      end
      buffer << stopped_status_attr
      buffer
    end

    ##
    # Idles the gear if there is no stop lock and state is not already +STOPPED+.
    #
    def idle_gear(options={})
      if not stop_lock? and (state.value != State::STOPPED)
        frontend = FrontendHttpServer.new(@uuid)
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
      OpenShift::Utils::Cgroups::with_no_cpu_limits(@user.uuid) do
        if stop_lock? and (state.value == State::IDLE)
          state.value = State::STARTED
          output      = start_gear
        end

        frontend = FrontendHttpServer.new(@uuid)
        if frontend.idle?
          frontend.unidle
        end
      end
      output
    end

    ##
    # Sets the application state to +STARTED+ and starts the gear. Gear state implementation
    # is model specific, but +options+ is provided to the implementation.
    def start_gear(options={})
      @cartridge_model.start_gear(options)
    end

    def gear_level_tidy_tmp(gear_tmp_dir)
      # Temp dir cleanup
      tidy_action do
        FileUtils.rm_rf(Dir.glob(File.join(gear_tmp_dir, "*")))
        logger.debug("Cleaned gear temp dir at #{gear_tmp_dir}")
      end
    end

    def gear_level_tidy_git(gear_repo_dir)
      # Git pruning
      tidy_action do
        Utils.oo_spawn('git prune', uid: @user.uid, chdir: gear_repo_dir, expected_exitstatus: 0, timeout: @hourglass.remaining)
        logger.debug("Pruned git directory at #{gear_repo_dir}")
      end

      # Git GC
      tidy_action do
        Utils.oo_spawn('git gc --aggressive', uid: @user.uid, chdir: gear_repo_dir, expected_exitstatus: 0, timeout: @hourglass.remaining)
        logger.debug("Executed git gc for repo #{gear_repo_dir}")
      end
    end

    # Executes a block, trapping ShellExecutionExceptions and treating them
    # as warnings. Any other exceptions are unexpected and will bubble out.
    def tidy_action
      begin
        yield
      rescue OpenShift::Utils::ShellExecutionException => e
        logger.warn(%Q{
          Tidy operation failed on gear #{@uuid}: #{e.message}
          --- stdout ---\n#{e.stdout}
          --- stderr ---\n#{e.stderr}
                    })
      end
    end

    def connector_execute(cart_name, pub_cart_name, connector_type, connector, args)
      @cartridge_model.connector_execute(cart_name, pub_cart_name, connector_type, connector, args)
    end

    def deploy_httpd_proxy(cart_name)
      @cartridge_model.deploy_httpd_proxy(cart_name)
    end

    def remove_httpd_proxy(cart_name)
      @cartridge_model.remove_httpd_proxy(cart_name)
    end

    def restart_httpd_proxy(cart_name)
      @cartridge_model.restart_httpd_proxy(cart_name)
    end

    #
    # Handles the pre-receive portion of the Git push lifecycle.
    #
    # If a builder cartridge is present, the +pre-receive+ control action is invoked on
    # the builder cartridge. If no builder is present, a user-initiated gear stop is
    # invoked.
    #
    # options: hash
    #   :out        : an IO to which any stdout should be written (default: nil)
    #   :err        : an IO to which any stderr should be written (default: nil)
    #   :hot_deploy : a boolean to toggle hot deploy for the operation (default: false)
    #
    def pre_receive(options={})
      builder_cart = builder_cartridge

      if builder_cart
        @cartridge_model.do_control('pre-receive',
                                    builder_cart,
                                    out: options[:out],
                                    err: options[:err])
      else
        stop_gear(user_initiated: true,
                  hot_deploy:     options[:hot_deploy],
                  out:            options[:out],
                  err:            options[:err])
      end
    end

    #
    # Handles the post-receive portion of the Git push lifecycle.
    #
    # If a builder cartridge is present, the +post-receive+ control action is invoked on
    # the builder cartridge. If no builder is present, the following sequence occurs:
    #
    #   1. Executes the primary cartridge +pre-repo-archive+ control action
    #   2. Archives the application Git repository, redeploying the code
    #   3. Executes +build+
    #   4. Executes +deploy+
    #
    # options: hash
    #   :out        : an IO to which any stdout should be written (default: nil)
    #   :err        : an IO to which any stderr should be written (default: nil)
    #   :hot_deploy : a boolean to toggle hot deploy for the operation (default: false)
    #
    def post_receive(options={})
      builder_cartridge = builder_cartridge

      if builder_cart
        @cartridge_model.do_control('post-receive',
                                    builder_cart,
                                    out: options[:out],
                                    err: options[:err])
      else
        @cartridge_model.do_control('pre-repo-archive',
                                    primary_cartridge,
                                    out:                       options[:out],
                                    err:                       options[:err],
                                    pre_action_hooks_enabled:  false,
                                    post_action_hooks_enabled: false)

        ApplicationRepository.new(@user).archive

        build(options)

        deploy(options)
      end

      report_build_analytics
    end

    #
    # A deploy variant intended for use by builder cartridges. This method is useful when
    # the build has already occured elsewhere, and the gear now needs a local deployment.
    #
    #   1. Runs the primary cartridge +update-configuration+ control action
    #   2. Executes +deploy+
    #   3. (optional) Executes the primary cartridge post-install steps
    #
    # options: hash
    #   :out  : an IO to which any stdout should be written (default: nil)
    #   :err  : an IO to which any stderr should be written (default: nil)
    #   :init : boolean; if true, post-install steps will be executed (default: false)
    # 
    def remote_deploy(options={})
      @cartridge_model.do_control('update-configuration',
                                  primary_cartridge,
                                  pre_action_hooks_enabled:  false,
                                  post_action_hooks_enabled: false,
                                  out:                       options[:out],
                                  err:                       options[:err])

      deploy(options)

      if options[:init]
        primary_cart_env_dir = File.join(@user.homedir, primary_cartridge.directory, 'env')
        primary_cart_env     = Utils::Environ.load(primary_cart_env_dir)
        ident                = primary_cart_env.keys.grep(/^OPENSHIFT_.*_IDENT/)
        _, _, version, _     = Runtime::Manifest.parse_ident(primary_cart_env[ident.first])

        @cartridge_model.post_install(primary_cartridge,
                                      version,
                                      out: options[:out],
                                      err: options[:err])

      end
    end

    #
    # Implements the following build process:
    #
    #   1. Set the application state to +BUILDING+
    #   2. Run the cartridge +update-configuration+ control action
    #   3. Run the cartridge +pre-build+ control action
    #   4. Run the +pre_build+ user action hook
    #   5. Run the cartridge +build+ control action
    #   6. Run the +build+ user action hook
    #
    # Returns the combined output of all actions as a +String+.
    #
    def build(options={})
      @state.value = OpenShift::State::BUILDING

      buffer = ''

      buffer << @cartridge_model.do_control('update-configuration',
                                            primary_cartridge,
                                            pre_action_hooks_enabled:  false,
                                            post_action_hooks_enabled: false,
                                            out:                       options[:out],
                                            err:                       options[:err])

      buffer << @cartridge_model.do_control('pre-build',
                                            primary_cartridge,
                                            pre_action_hooks_enabled: false,
                                            prefix_action_hooks:      false,
                                            out:                      options[:out],
                                            err:                      options[:err])

      buffer << @cartridge_model.do_control('build',
                                            primary_cartridge,
                                            pre_action_hooks_enabled: false,
                                            prefix_action_hooks:      false,
                                            out:                      options[:out],
                                            err:                      options[:err])

      buffer
    end

    #
    # Implements the following deploy process:
    #
    #   1. Start secondary cartridges on the gear
    #   2. Set the application state to +DEPLOYING+
    #   3. Run the web proxy cartridge +deploy+ control action (if such a cartridge is present)
    #   4. Run the primary cartridge +deploy+ control action
    #   5. Run the +deploy+ user action hook
    #   6. Start the primary cartridge on the gear
    #   7. Run the primary cartridge +post-deploy+ control action
    #
    # options: hash
    #   :out        : an IO to which any stdout should be written (default: nil)
    #   :err        : an IO to which any stderr should be written (default: nil)
    #   :hot_deploy : a boolean to toggle hot deploy for the operation (default: false)
    #
    # Returns the combined output of all actions as a +String+.
    #
    def deploy(options={})
      buffer = ''

      buffer << start_gear(secondary_only: true,
                           user_initiated: true,
                           hot_deploy:     options[:hot_deploy],
                           out:            options[:out],
                           err:            options[:err])

      @state.value = OpenShift::State::DEPLOYING

      web_proxy_cart = web_proxy
      if web_proxy_cart
        buffer << @cartridge_model.do_control('deploy',
                                              web_proxy_cart,
                                              pre_action_hooks_enabled: false,
                                              prefix_action_hooks:      false,
                                              out:                      options[:out],
                                              err:                      options[:err])
      end

      buffer << @cartridge_model.do_control('deploy',
                                            primary_cartridge,
                                            pre_action_hooks_enabled: false,
                                            prefix_action_hooks:      false,
                                            out:                      options[:out],
                                            err:                      options[:err])

      buffer << start_gear(primary_only:   true,
                           user_initiated: true,
                           hot_deploy:     options[:hot_deploy],
                           out:            options[:out],
                           err:            options[:err])

      buffer << @cartridge_model.do_control('post-deploy',
                                            primary_cartridge,
                                            pre_action_hooks_enabled: false,
                                            prefix_action_hooks:      false,
                                            out:                      options[:out],
                                            err:                      options[:err])

      buffer
    end


    # === Cartridge control methods

    def start(cart_name, options={})
      @cartridge_model.start_cartridge('start', cart_name,
                                       user_initiated: true,
                                       out:            options[:out],
                                       err:            options[:err])
    end

    def stop(cart_name, options={})
      @cartridge_model.stop_cartridge(cart_name,
                                      user_initiated: true,
                                      out:            options[:out],
                                      err:            options[:err])
    end

    # restart gear as supported by cartridges
    def restart(cart_name, options={})
      @cartridge_model.start_cartridge('restart', cart_name,
                                       user_initiated: true,
                                       out:            options[:out],
                                       err:            options[:err])
    end

    # reload gear as supported by cartridges
    def reload(cart_name)
      if State::STARTED == state.value
        return @cartridge_model.do_control('reload', cart_name)
      else
        return @cartridge_model.do_control('force-reload', cart_name)
      end
    end

    ##
    # Creates a snapshot of a gear.
    #
    # Writes an archive (in tar.gz format) to the calling process' STDOUT.
    # The operations invoked by this method write user-facing output to the
    # client on STDERR.
    def snapshot
      stop_gear

      scalable_snapshot = !!web_proxy 

      if scalable_snapshot
        begin
          handle_scalable_snapshot
        rescue => e
          $stderr.puts "We were unable to snapshot this application due to communication issues with the OpenShift broker.  Please try again later."
          $stderr.puts "#{e.message}"
          $stderr.puts "#{e.backtrace}"
          return false
        end
      end

      each_cartridge do |cartridge|
        @cartridge_model.do_control('pre-snapshot', 
                                    cartridge,
                                    err: $stderr,
                                    pre_action_hooks_enabled: false,
                                    post_action_hooks_enabled: false,
                                    prefix_action_hooks:      false,)
      end

      exclusions = []

      each_cartridge do |cartridge|
        exclusions |= snapshot_exclusions(cartridge)
      end

      write_snapshot_archive(exclusions)

      each_cartridge do |cartridge|
        @cartridge_model.do_control('post-snapshot', 
                                    cartridge, 
                                    err: $stderr,
                                    pre_action_hooks_enabled: false,
                                    post_action_hooks_enabled: false)
      end      

      start_gear
    end

    def handle_scalable_snapshot
      gear_env = Utils::Environ.for_gear(@user.homedir)

      gear_groups = get_gear_groups(gear_env)

      get_secondary_gear_groups(gear_groups).each do |type, group|
        $stderr.puts "Saving snapshot for secondary #{type} gear"

        ssh_coords = group['gears'][0]['ssh_url'].sub(/^ssh:\/\//, '')
        Utils::oo_spawn("#{GEAR_TO_GEAR_SSH} #{ssh_coords} 'snapshot' > #{type}.tar.gz",
                        env: gear_env,
                        chdir: gear_env['OPENSHIFT_DATA_DIR'],
                        uid: @user.uid,
                        gid: @user.gid,
                        err: $stderr,
                        timeout: @hourglass.remaining,
                        expected_exitstatus: 0)
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
        'broker_auth_key' => File.read(File.join(@config.get('GEAR_BASE_DIR'), name, '.auth', 'token')).chomp,
        'broker_auth_iv' => File.read(File.join(@config.get('GEAR_BASE_DIR'), name, '.auth', 'iv')).chomp
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

    def write_snapshot_archive(exclusions)
      gear_env = Utils::Environ.for_gear(@user.homedir)

      exclusions = exclusions.map { |x| "--exclude=./$OPENSHIFT_GEAR_UUID/#{x}" }.join(' ')

      tar_cmd = %Q{
/bin/tar --ignore-failed-read -czf - \
--exclude=./$OPENSHIFT_GEAR_UUID/.tmp \
--exclude=./$OPENSHIFT_GEAR_UUID/.ssh \
--exclude=./$OPENSHIFT_GEAR_UUID/.sandbox \
--exclude=./$OPENSHIFT_GEAR_UUID/*/conf.d/openshift.conf \
--exclude=./$OPENSHIFT_GEAR_UUID/*/run/httpd.pid \
--exclude=./$OPENSHIFT_GEAR_UUID/haproxy-\*/run/stats \
--exclude=./$OPENSHIFT_GEAR_UUID/app-root/runtime/.state \
--exclude=./$OPENSHIFT_DATA_DIR/.bash_history \
#{exclusions} ./$OPENSHIFT_GEAR_UUID
}

      $stderr.puts 'Creating and sending tar.gz'

      Utils.oo_spawn(tar_cmd,
                     env: gear_env,
                     unsetenv_others: true,
                     out: $stdout,
                     chdir: @config.get('GEAR_BASE_DIR'),
                     uid: @user.uid,
                     timeout: @hourglass.remaining,
                     expected_exitstatus: 0)
    end

    ##
    # Restores a gear from an archive read from STDIN.
    #
    # The operation invoked by this method write output to the client on STDERR.
    def restore(restore_git_repo)
      gear_env = Utils::Environ.for_gear(@user.homedir)

      scalable_restore = !!web_proxy 
      gear_groups = nil

      if scalable_restore
        gear_groups = get_gear_groups(gear_env)
      end
      
      if restore_git_repo
        pre_receive(err: $stderr, out: $stdout)
      else
        stop_gear
      end

      each_cartridge do |cartridge|
        @cartridge_model.do_control('pre-restore', 
                                    cartridge,
                                    pre_action_hooks_enabled: false,
                                    post_action_hooks_enabled: false,
                                    err: $stderr)
      end

      prepare_for_restore(restore_git_repo, gear_env)

      transforms = []
      each_cartridge do |cartridge|
        transforms |= restore_transforms(cartridge)
      end

      extract_restore_archive(transforms, restore_git_repo, gear_env)

      if scalable_restore
        handle_scalable_restore(gear_groups, gear_env)
      end

      each_cartridge do |cartridge|
        @cartridge_model.do_control('post-restore',
                                     cartridge,
                                     pre_action_hooks_enabled: false,
                                     post_action_hooks_enabled: false,
                                     err: $stderr)
      end

      if restore_git_repo
        post_receive(err: $stderr, out: $stdout)
      else
        start_gear
      end
    end

    def prepare_for_restore(restore_git_repo, gear_env)
      if restore_git_repo
        app_name = gear_env['OPENSHIFT_APP_NAME']
        $stderr.puts "Removing old git repo: ~/git/#{app_name}.git/"
        FileUtils.rm_rf(Dir.glob(File.join(@user.homedir, 'git', "#{app_name}.git", '[^h]*', '*')))
      end

      $stderr.puts "Removing old data dir: ~/app-root/data/*"
      FileUtils.rm_rf(Dir.glob(File.join(@user.homedir, 'app-root', 'data', '*')))
      FileUtils.rm_rf(Dir.glob(File.join(@user.homedir, 'app-root', 'data', '.[^.]*')))
      FileUtils.safe_unlink(File.join(@user.homedir, 'app-root', 'runtime', 'data'))
    end

    def extract_restore_archive(transforms, restore_git_repo, gear_env)
      includes = %w(./*/app-root/data)
      excludes = %w(./*/app-root/runtime/data)
      transforms << 's|${OPENSHIFT_GEAR_NAME}/data|app-root/data|'
      transforms << 's|git/.*\.git|git/${OPENSHIFT_GEAR_NAME}.git|'

      # TODO: use all installed cartridges, not just ones in current instance directory
      each_cartridge do |cartridge|
        excludes << "./*/#{cartridge.directory}/data"
      end

      if restore_git_repo
        excludes << './*/git/*.git/hooks'
        includes << './*/git'
        $stderr.puts "Restoring ~/git/#{name}.git and ~/app-root/data"
      else
        $stderr.puts "Restoring ~/app-root/data"
      end

      includes = includes.join(' ')
      excludes = excludes.map { |x| "--exclude=\"#{x}\"" }.join(' ')
      transforms = transforms.map { |x| "--transform=\"#{x}\"" }.join(' ')

      tar_cmd = %Q{/bin/tar --strip=2 --overwrite -xmz #{includes} #{transforms} #{excludes} 1>&2}

      Utils.oo_spawn(tar_cmd,
                     env: gear_env,
                     unsetenv_others: true,
                     out: $stdout,
                     err: $stderr,
                     in: $stdin,
                     chdir: @user.homedir,
                     uid: @user.uid,
                     timeout: @hourglass.remaining,
                     expected_exitstatus: 0)

      FileUtils.cd File.join(@user.homedir, 'app-root', 'runtime') do
        FileUtils.ln_s('../data', 'data')
      end
    end

    def handle_scalable_restore(gear_groups, gear_env)
      secondary_groups = get_secondary_gear_groups(gear_groups)

      secondary_groups.each do |type, group|
        $stderr.puts "Restoring snapshot for #{type} gear"

        ssh_coords = group['gears'][0]['ssh_url'].sub(/^ssh:\/\//, '')
        Utils::oo_spawn("cat #{type}.tar.gz | #{GEAR_TO_GEAR_SSH} #{ssh_coords} 'restore'",
                        env: gear_env,
                        chdir: gear_env['OPENSHIFT_DATA_DIR'],
                        uid: @user.uid,
                        gid: @user.gid,
                        err: $stderr,
                        timeout: @hourglass.remaining,
                        expected_exitstatus: 0)
      end
    end

    def status(cart_name)
      buffer = ''
      buffer << stopped_status_attr
      quota_cmd = "/bin/sh #{File.join('/usr/libexec/openshift/lib', "quota_attrs.sh")} #{user.name}"
      out,err,rc = shellCmd(quota_cmd)
      raise "ERROR: Error fetching quota (#{rc}): #{quota_cmd.squeeze(" ")} stdout: #{out} stderr: #{err}" unless rc == 0
      buffer << out
      buffer << @cartridge_model.do_control("status", cart_name)
      buffer
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

    def threaddump(cart_name)
      unless State::STARTED == state.value
        return "CLIENT_ERROR: Application is #{state.value}, must be #{State::STARTED} to allow a thread dump"
      end

      @cartridge_model.do_control('threaddump', cart_name)
    end

    def stop_lock?
      @cartridge_model.stop_lock?
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

    def stop_lock
      File.join(@user.homedir, 'app-root', 'runtime', '.stop_lock')
    end

    def stop_lock?
      File.exists?(stop_lock)
    end


    #
    # Public: Return an ApplicationContainer object loaded from the container_uuid on the system
    #
    # Caveat: the quota information will not be populated.
    #
    def self.from_uuid(container_uuid, logger=nil)
      u = UnixUser.from_uuid(container_uuid)
      ApplicationContainer.new(u.application_uuid, u.container_uuid, u.uid,
                               u.app_name, u.container_name, u.namespace,
                               nil, nil, logger)
    end

    #
    # Public: Return an enumerator which provides an ApplicationContainer object
    # for every OpenShift gear in the system.
    #
    # Caveat: the quota information will not be populated.
    #
    def self.all(hourglass=nil)
      Enumerator.new do |yielder|
        UnixUser.all.each do |u|
          a=nil
          begin
            a=ApplicationContainer.new(u.application_uuid, u.container_uuid, u.uid,
                                       u.app_name, u.container_name, u.namespace,
                                       nil, nil, hourglass)
          rescue => e
            if logger
              logger.error("Failed to instantiate ApplicationContainer for #{u.application_uuid}: #{e}")
              logger.error("Backtrace: #{e.backtrace}")
            else
              NodeLogger.logger.error("Failed to instantiate ApplicationContainer for #{u.application_uuid}: #{e}")
              NodeLogger.logger.error("Backtrace: #{e.backtrace}")
            end
          else
            yielder.yield(a)
          end
        end
      end
    end

  end
end
