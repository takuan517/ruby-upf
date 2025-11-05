require 'yaml'

module Ruby
  module Upf
    module Config
      def self.load(path = 'etc/ruby-upf.yml')
        YAML.load_file(path)
      rescue Errno::ENOENT
        puts "[WARN] Config file not found: #{path}"
        {}
      end
    end
  end
end
