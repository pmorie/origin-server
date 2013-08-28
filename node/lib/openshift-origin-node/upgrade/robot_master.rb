require 'rubygems'
require 'json'
require 'fileutils'
require 'openshift-origin-node/utils/shell_exec'
require 'openshift-origin-node/utils/node_logger'

module OpenShift
  module Runtime
  	class RobotMaster
      include NodeLogger

      def initialize(request_queue, reply_queue, path = '/tmp/oo-robo')
        @request_queue = request_queue
        @reply_queue = reply_queue
        @path = path
      end

      def initialize_store
        FileUtils.mkdir_p('/tmp/oo-robo')
      end

      def scale_to(count)
      	current_count = robot_count
      	workers_to_scale = count - current_count

      	return if workers_to_scale == 0

      	if (workers_to_scale < 0)
      	  scale_down(workers_to_scale)
      	else
      	  scale_up(workers_to_scale)
        end

        "Scaled to #{count} workers"
      end

      def robot_count
        Dir.glob(File.join(@path, 'robot.pid.*')).size
      end

      def scale_up(count)
        logger.debug("Scaling up by #{count} workers")

      	count.times do |i|
      	  spawn_worker
        end
      end

      def spawn_worker()
        logger.debug("Spawning worker for request queue #{@request_queue} and reply queue: #{@reply_queue}")
        script = "/opt/rh/ruby193/root/usr/share/gems/gems/openshift-origin-node-1.14.0/lib/openshift-origin-node/upgrade/upgrade_robot.rb"
        OpenShift::Runtime::Utils.oo_spawn("#{script} #{@request_queue} #{@reply_queue} &")
      end

      def scale_down(count)
        logger.debug("Scaling down by #{count} workers")

        Dir.glob(File.join(@path, 'robot.pid.*')).each_with_index do |pidfile, i|
          pid = File.basename(pidfile)[10..-1]

          destroy_worker(pid)

          break if i == count
        end
      end

      def destroy_worker(pid)
        OpenShift::Runtime::Utils::oo_spawn("kill -TERM #{pid} && rm -f /tmp/oo-robo/robot.pid.#{pid}")
      end
  	end
  end
end