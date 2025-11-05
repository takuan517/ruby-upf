# frozen_string_literal: true

require 'ipaddr'

module Ruby
  module Upf
    module Pfcp
      #
      # PFCP Message ヘッダ構造のエンコード／デコード
      #
      class Message
        PFCP_VER = 1

        def self.parse(data)
          return nil if data.bytesize < 8

          flags, msg_type, length = data.unpack('CCn')
          ver = (flags >> 5) & 0x7
          s_flag = (flags >> 2) & 0x1
          seid = nil
          offset = 4
          if s_flag == 1
            return nil if data.bytesize < 16
            seid = data.byteslice(4, 8).unpack1('Q>')
            offset = 12
          end
          seq_b = data.byteslice(offset, 3).unpack('C3')
          seq = (seq_b[0] << 16) | (seq_b[1] << 8) | seq_b[2]
          hdr_len = s_flag == 1 ? 16 : 8
          payload = data.byteslice(hdr_len, length - hdr_len)

          new(
            message_type: msg_type,
            version: ver,
            s_flag: s_flag,
            seid: seid,
            seq: seq,
            payload: payload
          )
        end

        attr_reader :message_type, :version, :s_flag, :seid, :seq, :payload

        def initialize(message_type:, version:, s_flag:, seid:, seq:, payload:)
          @message_type = message_type
          @version = version
          @s_flag = s_flag
          @seid = seid
          @seq = seq
          @payload = payload
        end

        def self.build(msg_type:, payload_len:, seq:, seid: nil)
          s_flag = seid ? 1 : 0
          flags = ((PFCP_VER & 0x7) << 5) | (s_flag << 2)

          if seid
            length = 4 + 8 + 4 + payload_len
            hdr = [flags, msg_type, length].pack('CCn')
            hdr << [seid].pack('Q>')
            hdr << [seq >> 16, seq >> 8, seq, 0].pack('C3C')
          else
            length = 8 + payload_len
            hdr = [flags, msg_type, length].pack('CCn')
            hdr << [seq >> 16, seq >> 8, seq, 0].pack('C3C')
          end
          hdr
        end
      end
    end
  end
end
