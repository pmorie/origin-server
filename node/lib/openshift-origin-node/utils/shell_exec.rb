#--
# Copyright 2010-2013 Red Hat, Inc.
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
require 'timeout'
require 'openshift-origin-node/utils/node_logger'

module OpenShift
  module Utils
    include NodeLogger

    class ShellExecutionException < Exception
      attr_accessor :rc, :stdout, :stderr

      def initialize(msg, rc=-1, stdout = nil, stderr = nil)
        super msg
        self.rc     = rc
        self.stdout = stdout
        self.stderr = stderr
      end
    end

    # Exception used to signal command overran it's timeout in seconds
    class TimeoutExceeded < RuntimeError
      attr_reader :seconds

      # seconds - integer of maximum seconds to wait on command
      def initialize(seconds)
        super 'Timeout exceeded'
        @seconds = seconds
      end

      def to_s
        super + " duration of #@seconds seconds"
      end
    end

    # oo_spawn(command, [, options]) -> [stdout, stderr, exit status]
    #
    # spawn executes specified command and return its stdout, stderr and exit status.
    # Or, raise exceptions if certain conditions are not met.
    #
    # command: command line string which is passed to the standard shell
    #
    # options: hash
    #   :env: hash
    #     name => val : set the environment variable
    #     name => nil : unset the environment variable
    #   :unsetenv_others => true   : clear environment variables except specified by :env
    #   :chdir => path             : set current directory when running command
    #   :expected_exitstatus       : An Integer value for the expected return code of command
    #                              : If not set spawn() returns exitstatus from command otherwise
    #                              : raise an error if exitstatus is not expected_exitstatus
    #   :timeout                   : Maximum number of seconds to wait for command to finish. default: 3600
    #   :uid                       : spawn command as given user in a SELinux context using runuser/runcon,
    #                              : stdin for the command is /dev/null
    def self.oo_spawn(command, options = {})
      options[:env]         ||= {}
      options[:timeout]     ||= 3600
      options[:buffer_size] ||= 32768

      opts                   = {}
      opts[:unsetenv_others] = (options[:unsetenv_others] ||= false)
      opts[:close_others]    = true
      opts[:chdir] = options[:chdir] unless options[:chdir].nil?

      IO.pipe do |read_stderr, write_stderr|
        IO.pipe do |read_stdout, write_stdout|
          opts[:out] = write_stdout
          opts[:err] = write_stderr

          if options[:uid]
            # lazy init otherwise we end up with a cyclic require...
            require 'openshift-origin-node/model/unix_user'

            opts[:in] = '/dev/null'
            context   = %Q{unconfined_u:system_r:openshift_t:#{UnixUser.get_mcs_label(options[:uid])}}
            name      = Etc.getpwuid(options[:uid]).name
            command   = %Q{/sbin/runuser -m -s /bin/sh #{name} -c "exec /usr/bin/runcon '#{context}' /bin/sh -c \\"#{command}\\""}
          end

          NodeLogger.trace_logger.debug { "oo_spawn running #{command}" }
          pid = Kernel.spawn(options[:env], command, opts)

          unless pid
            raise OpenShift::Utils::ShellExecutionException.new(
                      "Kernel.spawn failed for command '#{command}'")
          end

          begin
            write_stdout.close
            write_stderr.close

            out, err, status = read_results(pid, read_stdout, read_stderr, options)
            NodeLogger.logger.debug { "Shell command '#{command}' ran. rc=#{status.exitstatus}" }

            if (!options[:expected_exitstatus].nil?) && (status.exitstatus != options[:expected_exitstatus])
              raise OpenShift::Utils::ShellExecutionException.new(
                        "Shell command '#{command}' returned an error. rc=#{status.exitstatus}",
                        status.exitstatus, out, err)
            end

            return [out, err, status.exitstatus]
          rescue TimeoutExceeded => e
            self.kill_process_tree(pid)
            raise OpenShift::Utils::ShellExecutionException.new(
                      "Shell command '#{command}'' exceeded timeout of #{e.seconds}", -1, out, err)
          end
        end
      end
    end

    # kill_process_tree 2199 -> fixnum
    #
    # Given a pid find it and KILL it and all it's children
    def self.kill_process_tree(pid)
      ps_results = `ps -e -opid,ppid --no-headers`.split("\n")

      ps_tree = Hash.new { |h, k| h[k] = [k] }
      ps_results.each { |pair|
        p, pp = pair.split(' ')
        ps_tree[pp.to_i] << p.to_i
      }
      Process.kill("KILL", *(ps_tree[pid].flatten))
    end

    private
    # read_results(stdout pipe, stderr pipe, options) -> [*standard out, *standard error]
    #
    # read stdout and stderr from spawned command until timeout
    #
    # options: hash
    #   :timeout     => seconds to wait for command to finish. Default: 3600
    #   :buffer_size => how many bytes to read from pipe per iteration. Default: 32768
    def self.read_results(pid, stdout, stderr, options)
      # TODO: Are these variables thread safe...?
      out     = ''
      err     = ''
      status  = nil
      readers = [stdout, stderr]

      begin
        Timeout::timeout(options[:timeout]) do
          while readers.any?
            ready = IO.select(readers, nil, nil, 10)

            # If there is no IO to process check if child has exited...
            if ready.nil?
              _, status = Process.wait2(pid, Process::WNOHANG)
            else
              # Otherwise, process us some IO...
              ready[0].each do |fd|
                buffer = (fd == stdout) ? out : err
                begin
                  buffer << fd.readpartial(options[:buffer_size])
                  NodeLogger.trace_logger.debug { "oo_spawn buffer(#{fd.fileno}/#{fd.pid}) #{buffer}" }
                rescue Errno::EAGAIN, Errno::EINTR
                rescue EOFError
                  readers.delete(fd)
                  fd.close
                end
              end
            end
          end

          _, status = Process.wait2 pid
          [out, err, status]
        end
      rescue Timeout::Error
        raise TimeoutExceeded, options[:timeout]
      rescue Errno::ECHILD
        return [out, err, status]
      end
    end
  end
end
