# frozen_string_literal: true

require 'ipaddr'

module Ruby
  module Upf
    module Pfcp
      #
      # PFCP Information Elements (IE)
      #   - TLV構造のエンコード／デコードを提供
      #
      class IE
        IE_RECOVERY_TIME_STAMP = 96
        IE_NODE_ID             = 60
        IE_CAUSE               = 19

        def self.encode_tlv(type, value, instance: 0)
          [type, value.bytesize, (instance & 0x0F)].pack('nnC') + value
        end

        def self.node_id_ipv4(ipv4_str)
          ip = IPAddr.new(ipv4_str).to_i
          value = [0].pack('C') + [ip].pack('N')
          encode_tlv(IE_NODE_ID, value)
        end

        def self.recovery_time_stamp(ntp32)
          value = [ntp32].pack('N')
          encode_tlv(IE_RECOVERY_TIME_STAMP, value)
        end

        def self.cause(val)
          value = [val].pack('C')
          encode_tlv(IE_CAUSE, value)
        end

        def self.parse_all(payload)
          ies = []
          i = 0
          while i + 5 <= payload.bytesize
            ie_type, ie_len, inst = payload.byteslice(i, 5).unpack('nnC')
            i += 5
            break if i + ie_len > payload.bytesize
            val = payload.byteslice(i, ie_len)
            i += ie_len
            ies << { type: ie_type, len: ie_len, instance: (inst & 0x0F), value: val }
          end
          ies
        end
      end
    end
  end
end
