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
  module Runtime


    class V2CartridgeModel
      include NodeLogger

      def initialize(config, container, state, hourglass)
        @config     = config
        @container  = container
        @state      = state
        @timeout    = 30
        @cartridges = {}
        @hourglass  = hourglass
      end

      #  cartridge_action(cartridge, action, software_version, render_erbs) -> buffer
      #
      #  Returns the results from calling a cartridge's action script.
      #  Includes <code>--version</code> if provided.
      #  Raises exception if script fails
      #
      #   stdout = cartridge_action(cartridge_obj)
      def cartridge_action(cartridge, action, software_version, render_erbs=false)
        logger.info "Running #{action} for #{@container.uuid}/#{cartridge.directory}"

        cartridge_home = PathUtils.join(@container.container_dir, cartridge.directory)
        action         = PathUtils.join(cartridge_home, 'bin', action)
        return "" unless File.exists? action

        gear_env           = ::OpenShift::Runtime::Utils::Environ.for_gear(@container.container_dir)
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
        logger.info("Ran #{action} for #{@container.uuid}/#{cartridge.directory}\n#{out}")
        out
      end

      # Run code block against each cartridge in gear
      #
      # @param  [block]  Code block to process cartridge
      # @yields [String] cartridge directory for each cartridge in gear
      def process_cartridges(cartridge_dir = nil) # : yields cartridge_path
        if cartridge_dir
          cart_dir = PathUtils.join(@container.container_dir, cartridge_dir)
          yield cart_dir if File.exist?(cart_dir)
          return
        end

        Dir[PathUtils.join(@container.container_dir, "*")].each do |cart_dir|
          next if File.symlink?(cart_dir) || !File.exist?(PathUtils.join(cart_dir, "metadata", "manifest.yml"))
          yield cart_dir
        end if @container.container_dir and File.exist?(@container.container_dir)
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
        gear_env     = ::OpenShift::Runtime::Utils::Environ.for_gear(@container.container_dir)
        action_hooks = PathUtils.join(@container.container_dir, %w{app-root runtime repo .openshift action_hooks})

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

            out, err, rc = @container.run_in_container_context(command.join('; '),
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

        action_hooks_dir = PathUtils.join(@container.container_dir, %w{app-root runtime repo .openshift action_hooks})
        action_hook      = PathUtils.join(action_hooks_dir, action)
        buffer           = ''

        if File.executable?(action_hook)
          out, err, rc = @container.run_in_container_context(action_hook,
              env:             env,
              chdir:           @container.container_dir,
              timeout:         @hourglass.remaining,
              out:             options[:out],
              err:             options[:err])
          raise ::OpenShift::Runtime::Utils::ShellExecutionException.new(
                    "Failed to execute action hook '#{action}' for #{@container.uuid} application #{@container.application_name}",
                    rc, out, err
                ) if rc != 0
        end

        buffer << out if out.is_a?(String)
        buffer << err if err.is_a?(String)

        buffer
      end



    end
  end
end
