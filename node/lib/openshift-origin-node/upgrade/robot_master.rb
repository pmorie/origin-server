require 'rubygems'
require 'json'
require 'openshift-origin-node/utils/shell_exec'

module OpenShift
  module Runtime
  	class RobotMaster
      def initialize(url, request_queue, reply_queue, path = '/tmp/oo-robo')
        @url = url
        @request_queue = request_queue
        @reply_queue = reply_queue
        @path = path
      end

      def initialize_store
        Dir.mkdir('/tmp/oo-robo')
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
      	count.times do |i|
      	  spawn_worker
        end
      end

      def spawn_worker()
        OpenShift::Runtime::Utils.oo_spawn("upgrade_robot.rb #{@url} #{@request_queue} #{@reply_queue} &")
      end

      def scale_down(count)
        Dir.glob(File.join(@path, 'robot.pid.*')).each_with_index do |pidfile, i|
          pid = File.basename(pidfile)[10..-1]

          destroy_worker(pid)

          break if i == count
        end
      end

      def destroy_worker(pid)
        OpenShift::Runtime::Utils::oo_spawn("kill -9 #{pid} && rm -f /tmp/oo-robo/robot.pid.#{pid}")
      end
  	end
  end
end