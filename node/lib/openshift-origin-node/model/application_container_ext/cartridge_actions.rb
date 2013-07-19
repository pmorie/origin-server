module OpenShift
  module Runtime
    module ApplicationContainerExt
      module CartridgeActions
        # configure(cartridge_name, template_git_url, manifest) -> stdout
        #
        # Add a cartridge to a gear
        #
        # configure('php-5.3')
        # configure('php-666', 'git://')
        # configure('php-666', 'git://', 'git://')
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

          ::OpenShift::Runtime::Utils::Cgroups::with_no_cpu_limits(uuid) do
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

            Dir.chdir(PathUtils.join(container_dir, cartridge.directory)) do
              unlock_gear(cartridge) do |c|
                expected_entries = Dir.glob(PathUtils.join(container_dir, '*'))

                output << cartridge_action(cartridge, 'setup', software_version, true)
                process_erb_templates(c)
                output << cartridge_action(cartridge, 'install', software_version)

                actual_entries  = Dir.glob(PathUtils.join(container_dir, '*'))
                illegal_entries = actual_entries - expected_entries
                unless illegal_entries.empty?
                  raise RuntimeError.new(
                            "Cartridge created the following directories in the gear home directory: #{illegal_entries.join(', ')}")
                end

                output << populate_gear_repo(c.directory, template_git_url) if cartridge.deployable?
              end

              validate_cartridge(cartridge)
            end

            connect_frontend(cartridge)
          end

          logger.info "configure output: #{output}"
          return output
        rescue ::OpenShift::Runtime::Utils::ShellExecutionException => e
          rc_override = e.rc < 100 ? 157 : e.rc
          raise ::OpenShift::Runtime::Utils::Sdk.translate_shell_ex_for_client(e, rc_override)
        rescue => e
          logger.error "Unexpected error during configure: #{e.message} (#{e.class})\n  #{e.backtrace.join("\n  ")}"
          ex = RuntimeError.new(Utils::Sdk.translate_out_for_client("Unexpected error: #{e.message}", :error))
          ex.set_backtrace(e.backtrace)
          raise ex
        end

        # process_erb_templates(cartridge_name) -> nil
        #
        # Search cartridge for any remaining <code>erb</code> files render them
        def process_erb_templates(cartridge)
          directory = PathUtils.join(container_dir, cartridge.name)
          logger.info "Processing ERB templates for #{cartridge.name}"

          env  = ::OpenShift::Runtime::Utils::Environ.for_gear(container_dir, directory)
          erbs = processed_templates(cartridge).map { |x| PathUtils.join(container_dir, x) }
          render_erbs(env, erbs)
        end

        # render_erbs(program environment as a hash, erbs) -> nil
        #
        # Run <code>erb</code> against each template file submitted
        #
        #   v2_cart_model.render_erbs({HOMEDIR => '/home/no_place_like'}, ['/var/lib/openshift/user/cart/foo.erb', ...])
        def render_erbs(env, erbs)
          erbs.each do |file|
            begin
              run_in_container_context(%Q{/usr/bin/oo-erb -S 2 -- #{file} > #{file.chomp('.erb')}},
                                       env:                 env,
                                       chdir:               container_dir,
                                       timeout:             @hourglass.remaining,
                                       expected_exitstatus: 0)
            rescue ::OpenShift::Runtime::Utils::ShellExecutionException => e
              logger.info("Failed to render ERB #{file}: #{e.stderr}")
            else
              File.delete(file)
            end
          end

          nil
        end        

        # :call-seq:
        #   model.populate_gear_repo(cartridge name) => nil
        #   model.populate_gear_repo(cartridge name, application git template url) -> nil
        #
        # Populate the gear git repository with a sample application
        #
        #   model.populate_gear_repo('ruby-1.9')
        #   model.populate_gear_repo('ruby-1.9', 'http://rails-example.example.com')
        def populate_gear_repo(cartridge_name, template_url = nil)
          logger.info "Creating gear repo for #{uuid}/#{cartridge_name} from `#{template_url}`"

          repo = ApplicationRepository.new(self)
          if template_url.nil?
            repo.populate_from_cartridge(cartridge_name)
          elsif OpenShift::Git.empty_clone_spec?(template_url)
            repo.populate_empty(cartridge_name)
          else
            repo.populate_from_url(cartridge_name, template_url)
          end

          if repo.exist?
            repo.archive
          end
          ""
        end

        def secure_cartridge(short_name, uid, gid=uid, cartridge_home)
          Dir.chdir(cartridge_home) do
            set_rw_permission_R(cartridge_home)

            files = ManagedFiles::IMMUTABLE_FILES.collect do |file|
              file.gsub!('*', short_name)
              file if File.exist?(file)
            end || []
            files.compact!

            unless files.empty?
              @container.set_ro_permission(files)
              FileUtils.chmod(0644, files)
            end
          end
        end

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
          mcs_label = ::OpenShift::Runtime::Utils::SELinux.get_mcs_label(uid)

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
              set_rw_permission(entry)
            rescue Exception => e
              raise FileUnlockError.new("Failed to unlock file system entry [#{entry}]: #{e}",
                                                   entry)
            end
          end

          begin
            set_rw_permission(container_dir)
          rescue Exception => e
            raise FileUnlockError.new(
                      "Failed to unlock gear home [#{container_dir}]: #{e}",
                      container_dir)
          end
        end

        # do_lock_gear(array of file names) -> array
        #
        # Take the given array of file system entries and prepare them for the application developer
        #    v2_cart_model.do_lock_gear(entries)
        def do_lock(entries)
          mcs_label = ::OpenShift::Runtime::Utils::SELinux.get_mcs_label(uid)

          # It is expensive doing one file at a time but...
          # ...it allows reporting on the failed command at the file level
          # ...we don't have to worry about the length of argv
          entries.each do |entry|
            begin
              set_ro_permission(entry)
            rescue Exception => e
              raise OpenShift::Runtime::FileLockError.new("Failed to lock file system entry [#{entry}]: #{e}", entry)
            end
          end

          begin
            set_ro_permission(container_dir)
          rescue Exception => e
            raise OpenShift::Runtime::FileLockError.new("Failed to lock gear home [#{container_dir}]: #{e}", container_dir)
          end
        end

        # create_cartridge_directory(cartridge name) -> nil
        #
        # Create the cartridges home directory
        #
        #   v2_cart_model.create_cartridge_directory('php-5.3')
        def create_cartridge_directory(cartridge, software_version)
          logger.info("Creating cartridge directory #{uuid}/#{cartridge.directory}")

          target = PathUtils.join(container_dir, cartridge.directory)
          CartridgeRepository.instantiate_cartridge(cartridge, target)

          ident = Runtime::Manifest.build_ident(cartridge.cartridge_vendor,
                                                cartridge.name,
                                                software_version,
                                                cartridge.cartridge_version)

          envs                                  = {}
          envs["#{cartridge.short_name}_DIR"]   = target + File::SEPARATOR
          envs["#{cartridge.short_name}_IDENT"] = ident

          write_environment_variables(PathUtils.join(target, 'env'), envs)

          envs.clear
          envs['namespace'] = namespace if namespace

          # If there's not already a primary cartridge on the gear, assume
          # the new cartridge is the primary.
          current_gear_env = ::OpenShift::Runtime::Utils::Environ.for_gear(container_dir)
          unless current_gear_env['OPENSHIFT_PRIMARY_CARTRIDGE_DIR']
            envs['primary_cartridge_dir'] = target + File::SEPARATOR
            logger.info("Cartridge #{cartridge.name} recorded as primary within gear #{uuid}")
          end

          unless envs.empty?
            write_environment_variables(PathUtils.join(container_dir, '.env'), envs)
          end

          old_path = PathUtils.join(container_dir, '.env', 'PATH')
          File.delete(old_path) if File.file? old_path

          secure_cartridge(cartridge.short_name, uid, gid, target)

          logger.info("Created cartridge directory #{uuid}/#{cartridge.directory}")
          nil
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

        def validate_cartridge(manifest)
          illegal_overrides = ::OpenShift::Runtime::Utils::Environ.load(PathUtils.join(container_dir, '.env')).keys &
              ::OpenShift::Runtime::Utils::Environ.load(PathUtils.join(container_dir, manifest.directory, 'env')).keys
    
          # Older gears may have these and cartridges are allowed to override them
          illegal_overrides.delete('LD_LIBRARY_PATH')
          illegal_overrides.delete('PATH')
    
          unless illegal_overrides.empty?
            raise RuntimeError.new(
                      "Cartridge attempted to override the following gear environment variables: #{illegal_overrides.join(', ')}")
          end
        end

        # XXX: renamed from create_public_endpoint during collapse due to naming conflicts
        # Expose an endpoint for a cartridge through the port proxy.
        #
        # Returns nil on success, or raises an exception if any errors occur: all errors
        # here are considered fatal.
        def internal_create_public_endpoint(cartridge, endpoint, private_ip)
          public_port = create_public_endpoint(private_ip, endpoint.private_port)
          add_env_var(endpoint.public_port_name, public_port)

          logger.info("Created public endpoint for cart #{cartridge.name} in gear #{uuid}: "\
          "[#{endpoint.public_port_name}=#{public_port}]")
        end

        # Allocates and assigns private IP/port entries for a cartridge
        # based on endpoint metadata for the cartridge.
        #
        # Returns nil on success, or raises an exception if any errors occur: all errors
        # here are considered fatal.
        def create_private_endpoints(cartridge)
          raise "Cartridge is required" unless cartridge
          return unless cartridge.endpoints && cartridge.endpoints.length > 0

          logger.info "Creating #{cartridge.endpoints.length} private endpoints for #{uuid}/#{cartridge.directory}"

          allocated_ips = {}

          cartridge.endpoints.each do |endpoint|
            # Reuse previously allocated IPs of the same name. When recycling
            # an IP, double-check that it's not bound to the target port, and
            # bail if it's unexpectedly bound.
            unless allocated_ips.has_key?(endpoint.private_ip_name)
              # Allocate a new IP for the endpoint
              private_ip = find_open_ip(endpoint.private_port)

              if private_ip.nil?
                raise "No IP was available to create endpoint for cart #{cartridge.name} in gear #{@container.uuid}: "\
                "#{endpoint.private_ip_name}(#{endpoint.private_port})"
              end

              add_env_var(endpoint.private_ip_name, private_ip)

              allocated_ips[endpoint.private_ip_name] = private_ip
            end

            private_ip = allocated_ips[endpoint.private_ip_name]

            add_env_var(endpoint.private_port_name, endpoint.private_port)

            # Create the environment variable for WebSocket Port if it is specified
            # in the manifest.
            if endpoint.websocket_port_name && endpoint.websocket_port
              add_env_var(endpoint.websocket_port_name, endpoint.websocket_port)
            end

            logger.info("Created private endpoint for cart #{cartridge.name} in gear #{uuid}: "\
            "[#{endpoint.private_ip_name}=#{private_ip}, #{endpoint.private_port_name}=#{endpoint.private_port}]")

            # Expose the public endpoint if ssl_to_gear option is set
            if endpoint.options and endpoint.options["ssl_to_gear"]
              logger.info("ssl_to_gear option set for the endpoint")
              internal_create_public_endpoint(cartridge, endpoint, private_ip)
            end
          end

          # Validate all the allocations to ensure they aren't already bound. Batch up the initial check
          # for efficiency, then do individual checks to provide better reporting before we fail.
          address_list = cartridge.endpoints.map { |e| {ip: allocated_ips[e.private_ip_name], port: e.private_port} }
          if !address_list.empty? && addresses_bound?(address_list)
            failures = ''
            cartridge.endpoints.each do |endpoint|
              if address_bound?(allocated_ips[endpoint.private_ip_name], endpoint.private_port)
                failures << "#{endpoint.private_ip_name}(#{endpoint.private_port})=#{allocated_ips[endpoint.private_ip_name]};"
              end
            end
            raise "Failed to create the following private endpoints due to existing process bindings: #{failures}" unless failures.empty?
          end
        end        

        def post_configure(cart_name, template_git_url=nil)
          cartridge = get_cartridge(cart_name)
          cartridge_home = PathUtils.join(container_dir, cartridge.directory)

          # Only perform an initial build if the manifest explicitly specifies a need,
          # or if a template Git URL is provided and the cart is capable of builds or deploys.
          if !OpenShift::Git.empty_clone_spec?(template_git_url) && (cartridge.install_build_required || template_git_url) && cartridge.buildable?
            build_log = '/tmp/initial-build.log'
            env       = ::OpenShift::Runtime::Utils::Environ.for_gear(container_dir)

            begin
              ::OpenShift::Runtime::Utils::Cgroups::with_no_cpu_limits(@uuid) do
                logger.info "Executing initial gear prereceive for #{@uuid}"
                Utils.oo_spawn("gear prereceive >> #{build_log} 2>&1",
                               env:                 env,
                               chdir:               container_dir,
                               uid:                 @uid,
                               timeout:             @hourglass.remaining,
                               expected_exitstatus: 0)

                logger.info "Executing initial gear postreceive for #{@uuid}"
                Utils.oo_spawn("gear postreceive >> #{build_log} 2>&1",
                               env:                 env,
                               chdir:               container_dir,
                               uid:                 @uid,
                               timeout:             @hourglass.remaining,
                               expected_exitstatus: 0)
              end
            rescue ::OpenShift::Runtime::Utils::ShellExecutionException => e
              max_bytes = 10 * 1024
              out, _, _ = Utils.oo_spawn("tail -c #{max_bytes} #{build_log} 2>&1",
                             env:                 env,
                             chdir:               container_dir,
                             uid:                 @uid,
                             timeout:             @hourglass.remaining)

              message = "The initial build for the application failed: #{e.message}\n\n.Last #{max_bytes/1024} kB of build output:\n#{out}"

              raise ::OpenShift::Runtime::Utils::Sdk.translate_out_for_client(message, :error)
            end
          end

          output = ''

          begin
            name, software_version = map_cartridge_name(cart_name)
            cartridge              = get_cartridge(name)

            ::OpenShift::Runtime::Utils::Cgroups::with_no_cpu_limits(uuid) do
              if empty_repository?
                output << "CLIENT_MESSAGE: An empty Git repository has been created for your application.  Use 'git push' to add your code."
              else
                output << start_cartridge('start', cartridge, user_initiated: true)
              end
              output << cartridge_action(cartridge, 'post_install', software_version)
            end

            logger.info("post-configure output: #{output}")
          rescue ::OpenShift::Runtime::Utils::ShellExecutionException => e
            raise ::OpenShift::Runtime::Utils::Sdk.translate_shell_ex_for_client(e, 157)
          end
            
          output
        end

        def post_install(cartridge, software_version, options = {})
          output = cartridge_action(cartridge, 'post_install', software_version)
          options[:out].puts(output) if options[:out]
          output
        end

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
        # deconfigure('php-5.3')
        # Remove cartridge from gear
        #
        # context: root -> gear user -> root
        # @param cart_name   cartridge name
        def deconfigure(cartridge_name)
          teardown_output = ''
          cartridge = nil

          begin
            cartridge = get_cartridge(cartridge_name)
          rescue
            teardown_output << "CLIENT_ERROR: Corrupted cartridge #{cartridge_name} removed. There may be extraneous data left on system.\n"
            logger.warn("Corrupted cartridge #{uuid}/#{cartridge_name} removed. There may be extraneous data left on system.")

            name, software_version = map_cartridge_name(cartridge_name)
            begin
              logger.warn("Corrupted cartridge #{uuid}/#{cartridge_name}. Attempting to auto-correct for deconfigure using local manifest.yml.")
              cartridge = get_cartridge_fallback(cartridge_name)
            rescue
              logger.warn("Corrupted cartridge #{uuid}/#{cartridge_name}. Attempting to auto-correct for deconfigure resorting to CartridgeRepository.")
              cartridge = CartridgeRepository.instance.select(name, software_version)
            end

            ident = Runtime::Manifest.build_ident(cartridge.cartridge_vendor,
                                                  cartridge.name,
                                                  software_version,
                                                  cartridge.cartridge_version)
            write_environment_variables(
                PathUtils.join(container_dir, cartridge.directory, 'env'),
                {"#{cartridge.short_name}_IDENT" => ident})
          end

          delete_private_endpoints(cartridge)

          ::OpenShift::Runtime::Utils::Cgroups::with_no_cpu_limits(uuid) do
            begin
              stop_cartridge(cartridge, user_initiated: true)
              unlock_gear(cartridge, false) do |c|
                teardown_output << cartridge_teardown(c.directory)
              end
            rescue ::OpenShift::Runtime::Utils::ShellExecutionException => e
              teardown_output << ::OpenShift::Runtime::Utils::Sdk::translate_out_for_client(e.stdout, :error)
              teardown_output << ::OpenShift::Runtime::Utils::Sdk::translate_out_for_client(e.stderr, :error)
            ensure
              disconnect_frontend(cartridge)
              delete_cartridge_directory(cartridge)
            end
          end

          teardown_output
        end

        def delete_cartridge_directory(cartridge)
          logger.info("Deleting cartridge directory for #{uuid}/#{cartridge.directory}")
          # TODO: rm_rf correct?
          FileUtils.rm_rf(PathUtils.join(container_dir, cartridge.directory))
          logger.info("Deleted cartridge directory for #{uuid}/#{cartridge.directory}")
        end

        # cartridge_teardown(cartridge_name, remove_cartridge_dir) -> buffer
        #
        # Returns the output from calling the cartridge's teardown script.
        #  Raises exception if script fails
        #
        # stdout = cartridge_teardown('php-5.3')
        def cartridge_teardown(cartridge_name, remove_cartridge_dir=true)
          cartridge_home = PathUtils.join(container_dir, cartridge_name)
          env            = ::OpenShift::Runtime::Utils::Environ.for_gear(container_dir, cartridge_home)
          teardown       = PathUtils.join(cartridge_home, 'bin', 'teardown')

          return "" unless File.exists? teardown
          return "#{teardown}: is not executable\n" unless File.executable? teardown

          # FIXME: Will anyone retry if this reports error, or should we remove from disk no matter what?
          buffer, err, _ = run_in_container_context(teardown,
                                                    env:                 env,
                                                    chdir:               cartridge_home,
                                                    timeout:             @hourglass.remaining,
                                                    expected_exitstatus: 0)

          buffer << err

          FileUtils.rm_r(cartridge_home) if remove_cartridge_dir
          logger.info("Ran teardown for #{uuid}/#{cartridge_name}")
          buffer
        end

        # Unsubscribe from a cart
        #
        # @param cart_name   unsubscribing cartridge name
        # @param cart_name   publishing cartridge name
        # Let a cart perform some action when another cart is being removed
        # Today, it is used to cleanup environment variables
        def unsubscribe(cart_name, pub_cart_name)
          env_dir_path = PathUtils.join(container_dir, '.env', short_name_from_full_cart_name(pub_cart_name))
          FileUtils.rm_rf(env_dir_path)
        end

        # Creates public endpoints for the given cart. Public proxy mappings are created via
        # the FrontendProxyServer, and the resulting mapped ports are written to environment
        # variables with names based on the cart manifest endpoint entries.
        #
        # Returns nil on success, or raises an exception if any errors occur: all errors here
        # are considered fatal.
        def create_public_endpoints(cart_name)
          cart = get_cartridge(cart_name)

          output = ''

          env  = ::OpenShift::Runtime::Utils::Environ::for_gear(@container_dir)
          # TODO: better error handling
          cart.public_endpoints.each do |endpoint|
            # Load the private IP from the gear
            private_ip = env[endpoint.private_ip_name]

            if private_ip == nil
              raise "Missing private IP #{endpoint.private_ip_name} for cart #{cart.name} in gear #{@uuid}, "\
            "required to create public endpoint #{endpoint.public_port_name}"
            end

            public_port = create_public_endpoint(private_ip, endpoint.private_port)
            add_env_var(endpoint.public_port_name, public_port)

            config = ::OpenShift::Config.new
            output << "NOTIFY_ENDPOINT_CREATE: #{endpoint.public_port_name} #{config.get('PUBLIC_IP')} #{public_port}\n" 

            logger.info("Created public endpoint for cart #{cart.name} in gear #{@uuid}: "\
          "[#{endpoint.public_port_name}=#{public_port}]")
          end

          output
        end

        def create_public_endpoint(private_ip, private_port)
          @container_plugin.create_public_endpoint(private_ip, private_port)
        end

        # Deletes all public endpoints for the given cart. Public port mappings are
        # looked up and deleted using the FrontendProxyServer, and all corresponding
        # environment variables are deleted from the gear.
        #
        # Returns nil on success. Failed public port delete operations are logged
        # and skipped.
        def delete_public_endpoints(cart_name)
          cart = get_cartridge(cart_name)
          proxy_mappings = list_proxy_mappings

          output = ''

          begin
            # Remove the proxy entries
            @container_plugin.delete_public_endpoints(proxy_mappings)

            config = ::OpenShift::Config.new
            proxy_mappings.each { |p| 
              output << "NOTIFY_ENDPOINT_DELETE: #{p[:public_port_name]} #{config.get('PUBLIC_IP')} #{p[:proxy_port]}\n" if p[:proxy_port]
            }

            logger.info("Deleted all public endpoints for cart #{cart.name} in gear #{@uuid}\n"\
              "Endpoints: #{proxy_mappings.map{|p| p[:public_port_name]}}\n"\
              "Public ports: #{proxy_mappings.map{|p| p[:proxy_port]}}")
          rescue => e
            logger.warn(%Q{Couldn't delete all public endpoints for cart #{cart.name} in gear #{@uuid}: #{e.message}
              "Endpoints: #{proxy_mappings.map{|p| p[:public_port_name]}}\n"\
              "Public ports: #{proxy_mappings.map{|p| p[:proxy_port]}}\n"\
              #{e.backtrace}
            })
          end

          # Clean up the environment variables
          proxy_mappings.map{|p| remove_env_var(p[:public_port_name])}

          output
        end

        def delete_private_endpoints(cartridge)
          logger.info "Deleting private endpoints for #{uuid}/#{cartridge.directory}"

          cartridge.endpoints.each do |endpoint|
            remove_env_var(endpoint.private_ip_name)
            remove_env_var(endpoint.private_port_name)
          end

          logger.info "Deleted private endpoints for #{uuid}/#{cartridge.directory}"
        end        

        def list_proxy_mappings
          proxied_ports = []
          gear_env = ::OpenShift::Runtime::Utils::Environ.for_gear(container_dir)

          each_cartridge do |cartridge|
            cartridge.endpoints.each do |endpoint|
              next if gear_env[endpoint.public_port_name].nil?
              proxied_ports << {
                :private_ip_name  => endpoint.private_ip_name,
                :public_port_name => endpoint.public_port_name,
                :private_ip   => gear_env[endpoint.private_ip_name],
                :private_port => endpoint.private_port,
                :proxy_port   => gear_env[endpoint.public_port_name],
              }
            end
          end

          proxied_ports
        end

        # disconnect cartridge from frontend proxy
        #
        # This is only called when a cartridge is removed from a cartridge not a gear delete
        def disconnect_frontend(cartridge)
          mappings = []
          cartridge.endpoints.each do |endpoint|
            endpoint.mappings.each do |mapping|
              mappings << mapping.frontend
            end
          end

          logger.info("Disconnecting frontend mapping for #{@container.uuid}/#{cartridge.name}: #{mappings.inspect}")
          unless mappings.empty?
            FrontendHttpServer.new(@container).disconnect(*mappings)
          end
        end

        def connect_frontend(cartridge)
          frontend       = FrontendHttpServer.new(@container)
          gear_env       = ::OpenShift::Runtime::Utils::Environ.for_gear(@container.container_dir)
          web_proxy_cart = web_proxy

          begin
            # TODO: exception handling
            cartridge.endpoints.each do |endpoint|
              endpoint.mappings.each do |mapping|
                private_ip  = gear_env[endpoint.private_ip_name]
                backend_uri = "#{private_ip}:#{endpoint.private_port}#{mapping.backend}"
                options     = mapping.options ||= {}

                if endpoint.websocket_port
                  options["websocket_port"] = endpoint.websocket_port
                end

                # Make sure that the mapping does not collide with the default web_proxy mapping
                if mapping.frontend == "" and not cartridge.web_proxy? and web_proxy_cart
                  logger.info("Skipping default mapping as web proxy owns it for the application")
                  next
                end

                # Only web proxy cartridges can override the default mapping
                if mapping.frontend == "" && (!cartridge.web_proxy?) && (cartridge.name != primary_cartridge.name)
                  logger.info("Skipping default mapping as primary cartridge owns it for the application")
                  next
                end

                logger.info("Connecting frontend mapping for #{@container.uuid}/#{cartridge.name}: "\
                        "[#{mapping.frontend}] => [#{backend_uri}] with options: #{mapping.options}")
                frontend.connect(mapping.frontend, backend_uri, options)
              end
            end
          rescue Exception => e
            logger.warn("V2CartModel#connect_frontend: #{e.message}\n#{e.backtrace.join("\n")}")
            raise
          end
        end


        # :call-seq:
        #    V2CartridgeModel.new(...).connector_execute(cartridge_name, connection_type, connector, args) => String
        #
        def connector_execute(cart_name, pub_cart_name, connection_type, connector, args)
          raise ArgumentError.new('cart_name cannot be nil') unless cart_name

          cartridge    = get_cartridge(cart_name)
          env          = ::OpenShift::Runtime::Utils::Environ.for_gear(container_dir, PathUtils.join(container_dir, cartridge.directory))
          env_var_hook = connection_type.start_with?("ENV:") && pub_cart_name

          # Special treatment for env var connection hooks
          if env_var_hook
            set_connection_hook_env_vars(cart_name, pub_cart_name, args)
            args = convert_to_shell_arguments(args)
          end

          conn = Runtime::PubSubConnector.new connection_type, connector

          if conn.reserved?
            begin
              return send(conn.action_name)
            rescue NoMethodError => e
              logger.debug "#{e.message}; falling back to script"
            end
          end

          cartridge_home = PathUtils.join(container_dir, cartridge.directory)
          script = PathUtils.join(cartridge_home, 'hooks', conn.name)

          unless File.executable?(script)
            if env_var_hook
              return "Set environment variables successfully"
            else
              msg = "ERROR: action '#{connector}' not found."
              raise ::OpenShift::Runtime::Utils::ShellExecutionException.new(msg, 127, msg)
            end
          end

          command      = script << " " << args
          out, err, rc = run_in_container_context(command,
                                                  env:     env,
                                                  chdir:   cartridge_home,
                                                  timeout: @hourglass.remaining)
          if 0 == rc
            logger.info("(#{rc})\n------\n#{Runtime::Utils.sanitize_credentials(out)}\n------)")
            return out
          end

          logger.info("ERROR: (#{rc})\n------\n#{Runtime::Utils.sanitize_credentials(out)}\n------)")
          raise ::OpenShift::Runtime::Utils::ShellExecutionException.new(
                    "Control action '#{connector}' returned an error. rc=#{rc}\n#{out}", rc, out, err)
        end

        def short_name_from_full_cart_name(pub_cart_name)
          raise ArgumentError.new('pub_cart_name cannot be nil') unless pub_cart_name

          return pub_cart_name if pub_cart_name.index('-').nil?

          tokens = pub_cart_name.split('-')
          tokens.pop
          tokens.join('-')
        end

        def set_connection_hook_env_vars(cart_name, pub_cart_name, args)
          logger.info("Setting env vars for #{cart_name} from #{pub_cart_name}")
          logger.info("ARGS: #{args.inspect}")

          env_dir_path = PathUtils.join(container_dir, '.env', short_name_from_full_cart_name(pub_cart_name))
          FileUtils.mkpath(env_dir_path)

          envs = {}

          # Skip the first three arguments and jump to gear => "k1=v1\nk2=v2\n" hash map
          pairs = args[3].values[0].split("\n")

          pairs.each do |pair|
            k, v    = pair.strip.split("=")
            envs[k] = v
          end

          write_environment_variables(env_dir_path, envs, false)
        end

        # TODO: convert to helper method
        # Convert env var hook arguments to shell arguments
        # TODO: document expected form of args
        def convert_to_shell_arguments(args)
          new_args = []
          args[3].each do |k, v|
            vstr = v.split("\n").map { |p| p + ";" }.join(' ')
            new_args.push "'#{k}'='#{vstr}'"
          end
          (args[0, 2] << Shellwords::shellescape(new_args.join(' '))).join(' ')
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
          builder_cartridge = @cartridge_model.builder_cartridge

          if builder_cartridge
            @cartridge_model.do_control('pre-receive',
                                        builder_cartridge,
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
          builder_cartridge = @cartridge_model.builder_cartridge

          if builder_cartridge
            @cartridge_model.do_control('post-receive',
                                        builder_cartridge,
                                        out: options[:out],
                err: options[:err])
          else
            @cartridge_model.do_control('pre-repo-archive',
                                        @cartridge_model.primary_cartridge,
                                        out:                       options[:out],
                err:                       options[:err],
                pre_action_hooks_enabled:  false,
                post_action_hooks_enabled: false)

            ApplicationRepository.new(self).archive

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
            primary_cart_env_dir = PathUtils.join(@container_dir, @cartridge_model.primary_cartridge.directory, 'env')
            primary_cart_env     = ::OpenShift::Runtime::Utils::Environ.load(primary_cart_env_dir)
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
          @state.value = ::OpenShift::Runtime::State::BUILDING

          buffer = ''

          buffer << @cartridge_model.do_control('update-configuration',
                                                @cartridge_model.primary_cartridge,
                                                pre_action_hooks_enabled:  false,
              post_action_hooks_enabled: false,
              out:                       options[:out],
              err:                       options[:err])

          buffer << @cartridge_model.do_control('pre-build',
                                                @cartridge_model.primary_cartridge,
                                                pre_action_hooks_enabled: false,
              prefix_action_hooks:      false,
              out:                      options[:out],
              err:                      options[:err])

          buffer << @cartridge_model.do_control('build',
                                                @cartridge_model.primary_cartridge,
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

          @state.value = ::OpenShift::Runtime::State::DEPLOYING

          web_proxy_cart = @cartridge_model.web_proxy
          if web_proxy_cart
            buffer << @cartridge_model.do_control('deploy',
                                                  web_proxy_cart,
                                                  pre_action_hooks_enabled: false,
                prefix_action_hooks:      false,
                out:                      options[:out],
                err:                      options[:err])
          end

          buffer << @cartridge_model.do_control('deploy',
                                                @cartridge_model.primary_cartridge,
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
                                                @cartridge_model.primary_cartridge,
                                                pre_action_hooks_enabled: false,
              prefix_action_hooks:      false,
              out:                      options[:out],
              err:                      options[:err])

          buffer
        end


        # === Cartridge control methods

        # Run code block against each cartridge in gear
        #
        # @param  [block]  Code block to process cartridge
        # @yields [String] cartridge directory for each cartridge in gear
        def process_cartridges(cartridge_dir = nil) # : yields cartridge_path
          if cartridge_dir
            cart_dir = PathUtils.join(container_dir, cartridge_dir)
            yield cart_dir if File.exist?(cart_dir)
            return
          end

          Dir[PathUtils.join(container_dir, "*")].each do |cart_dir|
            next if File.symlink?(cart_dir) || !File.exist?(PathUtils.join(cart_dir, "metadata", "manifest.yml"))
            yield cart_dir
          end if container_dir and File.exist?(container_dir)
        end

        #  cartridge_action(cartridge, action, software_version, render_erbs) -> buffer
        #
        #  Returns the results from calling a cartridge's action script.
        #  Includes <code>--version</code> if provided.
        #  Raises exception if script fails
        #
        #   stdout = cartridge_action(cartridge_obj)
        def cartridge_action(cartridge, action, software_version, render_erbs=false)
          logger.info "Running #{action} for #{uuid}/#{cartridge.directory}"

          cartridge_home = PathUtils.join(container_dir, cartridge.directory)
          action         = PathUtils.join(cartridge_home, 'bin', action)
          return "" unless File.exists? action

          gear_env           = ::OpenShift::Runtime::Utils::Environ.for_gear(container_dir)
          cartridge_env_home = PathUtils.join(cartridge_home, 'env')

          cartridge_env = gear_env.merge(Utils::Environ.load(cartridge_env_home))
          if render_erbs
            erbs = Dir.glob(cartridge_env_home + '/*.erb', File::FNM_DOTMATCH).select { |f| File.file?(f) }
            render_erbs(cartridge_env, erbs)
            cartridge_env = gear_env.merge(Utils::Environ.load(cartridge_env_home))
          end

          action << " --version #{software_version}"
          out, _, _ = @container.run_in_container_context(action,
              env:                 cartridge_env,
              chdir:               cartridge_home,
              timeout:             @hourglass.remaining,
              expected_exitstatus: 0)
          logger.info("Ran #{action} for #{uuid}/#{cartridge.directory}\n#{out}")
          out
        end

        def do_control(action, cartridge, options={})
          case cartridge
            when String
              cartridge_dir = cartridge_directory(cartridge)
            when Manifest
              cartridge_dir = cartridge.directory
            else
              raise "Unsupported cartridge argument type: #{cartridge.class}"
          end

          options[:cartridge_dir] = cartridge_dir

          do_control_with_directory(action, options)
        end

        # :call-seq:
        #   V2CartridgeModel.new(...).do_control_with_directory(action, options)  -> output
        #   V2CartridgeModel.new(...).do_control_with_directory(action)           -> output
        #
        # Call action on cartridge +control+ script. Run all pre/post hooks if found.
        #
        # +options+: hash
        #   :cartridge_dir => path             : Process all cartridges (if +nil+) or the provided cartridge
        #   :pre_action_hooks_enabled => true  : Whether to process repo action hooks before +action+
        #   :post_action_hooks_enabled => true : Whether to process repo action hooks after +action+
        #   :prefix_action_hooks => true       : If +true+, action hook names are automatically prefixed with
        #                                        'pre' and 'post' depending on their execution order.
        #   :out                               : An +IO+ object to which control script STDOUT should be directed. If
        #                                        +nil+ (the default), output is logged.
        #   :err                               : An +IO+ object to which control script STDERR should be directed. If
        #                                        +nil+ (the default), output is logged.
        def do_control_with_directory(action, options={})
          cartridge_dir             = options[:cartridge_dir]
          pre_action_hooks_enabled  = options.has_key?(:pre_action_hooks_enabled) ? options[:pre_action_hooks_enabled] : true
          post_action_hooks_enabled = options.has_key?(:post_action_hooks_enabled) ? options[:post_action_hooks_enabled] : true
          prefix_action_hooks       = options.has_key?(:prefix_action_hooks) ? options[:prefix_action_hooks] : true

          logger.debug { "#{@container.uuid} #{action} against '#{cartridge_dir}'" }
          buffer       = ''
          gear_env     = ::OpenShift::Runtime::Utils::Environ.for_gear(container_dir)
          action_hooks = PathUtils.join(container_dir, %w{app-root runtime repo .openshift action_hooks})

          if pre_action_hooks_enabled
            pre_action_hook = prefix_action_hooks ? "pre_#{action}" : action
            hook_buffer     = do_action_hook(pre_action_hook, gear_env, options)
            buffer << hook_buffer if hook_buffer.is_a?(String)
          end

          process_cartridges(cartridge_dir) { |path|
            # Make sure this cartridge's env directory overrides that of other cartridge envs
            cartridge_local_env = ::OpenShift::Runtime::Utils::Environ.load(PathUtils.join(path, 'env'))

            ident                            = cartridge_local_env.keys.grep(/^OPENSHIFT_.*_IDENT/)
            _, software, software_version, _ = Runtime::Manifest.parse_ident(cartridge_local_env[ident.first])
            hooks                            = cartridge_hooks(action_hooks, action, software, software_version)

            cartridge_env = gear_env.merge(cartridge_local_env)
            control = PathUtils.join(path, 'bin', 'control')

            command = []
            command << hooks[:pre] unless hooks[:pre].empty?
            command << "#{control} #{action}" if File.executable? control
            command << hooks[:post] unless hooks[:post].empty?

            unless command.empty?
              command = ['set -e'] | command

              out, err, rc = run_in_container_context(command.join('; '),
                  env:             cartridge_env,
                  chdir:           path,
                  timeout:         @hourglass.remaining,
                  out:             options[:out],
                  err:             options[:err])

              buffer << out if out.is_a?(String)
              buffer << err if err.is_a?(String)

              raise ::OpenShift::Runtime::Utils::ShellExecutionException.new(
                        "Failed to execute: 'control #{action}' for #{path}", rc, out, err
                    ) if rc != 0
            end
          }

          if post_action_hooks_enabled
            post_action_hook = prefix_action_hooks ? "post_#{action}" : action
            hook_buffer      = do_action_hook(post_action_hook, gear_env, options)
            buffer << hook_buffer if hook_buffer.is_a?(String)
          end

          buffer
        end

        def cartridge_hooks(action_hooks, action, name, version)
          hooks = {pre: [], post: []}

          hooks.each_key do |key|
            new_hook = PathUtils.join(action_hooks, "#{key}_#{action}_#{name}")
            old_hook = PathUtils.join(action_hooks, "#{key}_#{action}_#{name}-#{version}")

            hooks[key] << "source #{new_hook}" if File.exist? new_hook
            hooks[key] << "source #{old_hook}" if File.exist? old_hook
          end
          hooks
        end

        ##
        # Executes the named +action+ from the user repo +action_hooks+ directory and returns the
        # stdout of the execution, or raises a +ShellExecutionException+ if the action returns a
        # non-zero return code.
        #
        # All hyphens in the +action+ will be replaced with underscores.
        def do_action_hook(action, env, options)
          action = action.gsub(/-/, '_')

          action_hooks_dir = PathUtils.join(container_dir, %w{app-root runtime repo .openshift action_hooks})
          action_hook      = PathUtils.join(action_hooks_dir, action)
          buffer           = ''

          if File.executable?(action_hook)
            out, err, rc = run_in_container_context(action_hook,
                env:             env,
                chdir:           container_dir,
                timeout:         @hourglass.remaining,
                out:             options[:out],
                err:             options[:err])
            raise ::OpenShift::Runtime::Utils::ShellExecutionException.new(
                      "Failed to execute action hook '#{action}' for #{uuid} application #{application_name}",
                      rc, out, err
                  ) if rc != 0
          end

          buffer << out if out.is_a?(String)
          buffer << err if err.is_a?(String)

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
            @state.value = State::STARTED

            # Unidle the application, preferring to use the privileged operation if possible
            frontend = FrontendHttpServer.new(self)
            if Process.uid == uid
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
            @state.value = State::STOPPED
          end

          do_control('stop', cartridge, options)
        end

        def start(cart_name, options={})
          start_cartridge('start', cart_name,
                          user_initiated: true,
                          out:            options[:out],
                          err:            options[:err])
        end

        def stop(cart_name, options={})
          stop_cartridge(cart_name,
                         user_initiated: true,
                         out:            options[:out],
                         err:            options[:err])
        end

        # restart gear as supported by cartridges
        def restart(cart_name, options={})
          start_cartridge('restart', cart_name,
                          user_initiated: true,
                          out:            options[:out],
                          err:            options[:err])
        end

        # reload gear as supported by cartridges
        def reload(cart_name)
          if ::OpenShift::Runtime::State::STARTED == state.value
            return @cartridge_model.do_control('reload', cart_name)
          else
            return @cartridge_model.do_control('force-reload', cart_name)
          end
        end

        def threaddump(cart_name)
          unless ::OpenShift::Runtime::State::STARTED == state.value
            return "CLIENT_ERROR: Application is #{state.value}, must be #{::OpenShift::Runtime::State::STARTED} to allow a thread dump"
          end

          @cartridge_model.do_control('threaddump', cart_name)
        end

        def status(cart_name)
          buffer = ''
          buffer << stopped_status_attr
          quota_cmd = "/bin/sh #{PathUtils.join('/usr/libexec/openshift/lib', "quota_attrs.sh")} #{@uuid}"
          out,err,rc = run_in_container_context(quota_cmd)
          raise "ERROR: Error fetching quota (#{rc}): #{quota_cmd.squeeze(" ")} stdout: #{out} stderr: #{err}" unless rc == 0
          buffer << out
          buffer << @cartridge_model.do_control("status", cart_name)
          buffer
        end
      end
    end
  end
end
