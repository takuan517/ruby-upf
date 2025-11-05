# lib/ruby/upf/pfcp/server.rb
# frozen_string_literal: true

require 'socket'
require 'ipaddr'

module Ruby
  module Upf
    module Pfcp
      #
      # PFCP Server (Phase 1)
      #   - Heartbeat Request (1) → Heartbeat Response (2)
      #   - Association Setup Request (50) → Association Setup Response (51)
      #
      class Server
        PFCP_PORT = 8805
        PFCP_VER  = 1

        HB_REQ  = 1
        HB_RESP = 2
        ASSOC_SETUP_REQ  = 50
        ASSOC_SETUP_RESP = 51

        IE_RECOVERY_TIME_STAMP = 96
        IE_NODE_ID             = 60
        IE_CAUSE               = 19

        CAUSE_REQUEST_ACCEPTED = 1

        def initialize(bind: '0.0.0.0', node_ip: '127.0.0.1', port: PFCP_PORT)
          @bind = bind
          @node_ip = node_ip
          @port = port
          @seq = 1
          @sock = UDPSocket.new
          @sock.bind(@bind, @port)
          puts "[PFCP] listening on #{@bind}:#{@port}, node_id=#{@node_ip}"
        end

        def next_seq
          @seq = (@seq + 1) & 0xFFFFFF
        end

        def run
          loop do
            data, addr = @sock.recvfrom(65535)
            from_host, from_port = addr[3], addr[1]
            hdr = parse_header(data)
            next warn "[PFCP] invalid header from #{from_host}:#{from_port}" if hdr.nil?

            puts "[PFCP] <- type=#{hdr[:message_type]} seq=#{hdr[:seq]} len=#{hdr[:length]} from=#{from_host}"

            case hdr[:message_type]
            when HB_REQ
              send_hb_resp(hdr[:seq], from_host, from_port)
            when ASSOC_SETUP_REQ
              ies = parse_ies(hdr[:payload] || '')
              log_ies(ies)
              send_assoc_setup_resp(hdr[:seq], from_host, from_port)
            else
              puts "[PFCP] (not implemented) msg_type=#{hdr[:message_type]}"
            end
          end
        end

        private

        # -----------------------------
        # Header encode/decode
        # -----------------------------
        def build_header(msg_type:, payload_len:, seq:, seid: nil)
          s_flag = seid ? 1 : 0
          flags = ((PFCP_VER & 0x7) << 5) | (s_flag << 2)
          if seid
            length = 4 + 8 + 4 + payload_len
            hdr = [flags, msg_type, length].pack('CCn')
            hdr << [seid].pack('Q>')
            hdr << [seq >> 16, seq >> 8, seq, 0].pack('C3C')
            hdr
          else
            length = 8 + payload_len
            hdr = [flags, msg_type, length].pack('CCn')
            hdr << [seq >> 16, seq >> 8, seq, 0].pack('C3C')
            hdr
          end
        end

        def parse_header(data)
          return nil if data.bytesize < 8
          flags, msg_type, length = data.unpack('CCn')
          ver = (flags >> 5) & 0x7
          s_flag = (flags >> 2) & 0x1
          offset = s_flag == 1 ? 12 : 4
          seid = s_flag == 1 ? data.byteslice(4, 8).unpack1('Q>') : nil
          seq_b = data.byteslice(offset, 3).unpack('C3')
          seq = (seq_b[0] << 16) | (seq_b[1] << 8) | seq_b[2]
          hdr_len = s_flag == 1 ? 16 : 8
          payload = data.byteslice(hdr_len, length - hdr_len)
          { version: ver, s_flag: s_flag, message_type: msg_type, seid: seid, seq: seq, payload: payload }
        end

        # -----------------------------
        # IE encode/decode
        # -----------------------------
        def ie_tlv(type, value, instance: 0)
          [type, value.bytesize, (instance & 0x0F)].pack('nnC') + value
        end

        def ie_node_id_ipv4(ipv4_str)
          ip = IPAddr.new(ipv4_str).to_i
          value = [0].pack('C') + [ip].pack('N')
          ie_tlv(IE_NODE_ID, value)
        end

        def ie_recovery_time_stamp(ntp32)
          value = [ntp32].pack('N')
          ie_tlv(IE_RECOVERY_TIME_STAMP, value)
        end

        def ie_cause(val)
          value = [val].pack('C')
          ie_tlv(IE_CAUSE, value)
        end

        def parse_ies(payload)
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

        def log_ies(ies)
          ies.each do |ie|
            case ie[:type]
            when IE_NODE_ID
              t = ie[:value].getbyte(0)
              if t == 0 && ie[:value].bytesize >= 5
                ip = ie[:value].byteslice(1, 4).unpack1('N')
                ip_s = IPAddr.new(ip, Socket::AF_INET).to_s
                puts "  IE NodeID IPv4=#{ip_s}"
              else
                puts "  IE NodeID type=#{t} len=#{ie[:len]}"
              end
            when IE_RECOVERY_TIME_STAMP
              ntp = ie[:value].unpack1('N')
              unix = ntp - 2_208_988_800
              puts "  IE RecoveryTimeStamp ntp=#{ntp} (unix=#{Time.at(unix)})"
            else
              puts "  IE type=#{ie[:type]} len=#{ie[:len]}"
            end
          end
        end

        # -----------------------------
        # Message senders
        # -----------------------------
        def send_hb_resp(req_seq, host, port)
          payload = ie_recovery_time_stamp(now_ntp32)
          hdr = build_header(msg_type: HB_RESP, payload_len: payload.bytesize, seq: req_seq)
          pkt = hdr + payload
          @sock.send(pkt, 0, host, port)
          puts "[PFCP] -> HeartbeatResponse seq=#{req_seq} to #{host}:#{port}"
        end

        def send_assoc_setup_resp(req_seq, host, port)
          payload = ''
          payload << ie_node_id_ipv4(@node_ip)
          payload << ie_cause(CAUSE_REQUEST_ACCEPTED)
          payload << ie_recovery_time_stamp(now_ntp32)
          hdr = build_header(msg_type: ASSOC_SETUP_RESP, payload_len: payload.bytesize, seq: req_seq)
          pkt = hdr + payload
          @sock.send(pkt, 0, host, port)
          puts "[PFCP] -> AssocSetupResponse seq=#{req_seq} to #{host}:#{port}"
        end

        # -----------------------------
        # Utilities
        # -----------------------------
        def now_ntp32
          unix = Time.now.to_i
          ntp = unix + 2_208_988_800
          ntp & 0xFFFFFFFF
        end
      end
    end
  end
end
