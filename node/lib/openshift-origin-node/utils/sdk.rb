require 'node_logger'

module OpenShift
  module Utils
    class Sdk
      GEAR_MARKER = 'CARTRIDGE_VERSION_2'

      def self.new_sdk_app?(gear_home)
        File.exists?(File.join(gear_home, '.env', GEAR_MARKER))
      end

      def self.mark_new_sdk_app(gear_home) 
        NodeLogger.logger.info("Marking v2 cart format in #{gear_home}/.env/#{GEAR_MARKER}")
        FileUtils.touch(File.join(gear_home, '.env', GEAR_MARKER))
      end

      def self.v2_node?(config)
        v1_marker_exist = File.exist?(File.join(config.get('GEAR_BASE_DIR'), '.settings', 'v1_cartridge_format'))
        v2_marker_exist = File.exist?(File.join(config.get('GEAR_BASE_DIR'), '.settings', 'v2_cartridge_format'))

        if  v1_marker_exist and v2_marker_exist
          raise 'Node cannot create both v1 and v2 formatted cartridges. Delete one of the cartridge format marker files'
        end

        # TODO: When v2 is the default cartridge format change this test...
        v2_marker_exist
      end
    end
  end
end
