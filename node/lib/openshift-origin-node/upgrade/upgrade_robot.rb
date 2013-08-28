require 'rubygems'
require 'json'
require 'openshift-origin-node/model/upgrade'


module OpenShift
  module Runtime
  	class UpgradeRobot
      def initialize(client, request_queue, reply_queue)
      	@client = client
        @request_queue = request_queue
        @reply_queue = reply_queue
      end

      def execute
      	@client.subscribe(queue_name) do |msg|
          content = JSON.load(msg)

          uuid = content['uuid']
          namespace = content['namespace']
          target_version = content['target_version']
          node = content['node']
          attempt = content['attempt']
          ignore_cartridge_version = content['ignore_cartridge_version']

          output = ''
	      exitcode = 0

          begin
            upgrader = OpenShift::Runtime::Upgrader.new(uuid, namespace, target_version, node, ignore_cartridge_version, OpenShift::Runtime::Utils::Hourglass.new(235))
            result = upgrader.execute
          rescue OpenShift::Runtime::Utils::ShellExecutionException => e
            exitcode = 127
            output += "Gear failed to upgrade: #{e.message}\n#{e.stdout}\n#{e.stderr}"
          rescue Exception => e
            exitcode = 1
            output += "Gear failed to upgrade with exception: #{e.message}\n#{e.backtrace}\n"
          end

          reply = { 'uuid' => uuid,
          	        'output' => output,
          	        'exitcode' => exitcode,
                    'attempt' => attempt,
          	        'upgrade_result_json' => JSON.dump(result)
          	      }

          @client.publish(reply_queue, reply)
        end
      end

    end
  end
end
