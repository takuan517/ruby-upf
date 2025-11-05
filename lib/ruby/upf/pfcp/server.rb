# frozen_string_literal: true

require 'ruby/upf/pfcp/message'
require 'ruby/upf/pfcp/ie'
require 'ruby/upf/pfcp/session'

module Ruby
  module Upf
    module Pfcp
      class Server
        PFCP_PORT = 8805

        HB_REQ  = 1
        ASSOC_SETUP_REQ  = 50
        SESSION_EST_REQ  = 50
        SESSION_EST_RESP = 51
        CAUSE_REQUEST_ACCEPTED = 1

        def initialize(bind: '0.0.0.0', node_ip: '127.0.0.1', port: PFCP_PORT)
          @bind = bind
          @node_ip = node_ip
          @port = port
          @seq = 1
          @sock = UDPSocket.new
          @sock.bind(@bind, @port)
          @session_mgr = Session.new
          puts "[PFCP] listening on #{@bind}:#{@port}, node_id=#{@node_ip}"
        end

        def run
          loop do
            data, addr = @sock.recvfrom(65535)
            from_host, from_port = addr[3], addr[1]
            hdr = Message.parse(data)
            next warn "[PFCP] invalid header from #{from_host}:#{from_port}" if hdr.nil?

            puts "[PFCP] <- type=#{hdr.message_type} seq=#{hdr.seq} len=#{hdr.payload&.bytesize} from=#{from_host}"

            case hdr.message_type
            when HB_REQ
              send_hb_resp(hdr.seq, from_host, from_port)
            when ASSOC_SETUP_REQ
              send_assoc_setup_resp(hdr.seq, from_host, from_port)
            when SESSION_EST_REQ
              @session_mgr.handle_establishment(hdr, from_host, from_port, @sock)
            else
              puts "[PFCP] (not implemented) msg_type=#{hdr.message_type}"
            end
          end
        end

        private

        def send_hb_resp(seq, host, port)
          payload = IE.recovery_time_stamp(now_ntp32)
          hdr = Message.build(msg_type: 2, payload_len: payload.bytesize, seq: seq)
          pkt = hdr + payload
          @sock.send(pkt, 0, host, port)
          puts "[PFCP] -> HeartbeatResponse seq=#{seq} to #{host}:#{port}"
        end

        def send_assoc_setup_resp(seq, host, port)
          payload = ''
          payload << IE.node_id_ipv4(@node_ip)
          payload << IE.cause(CAUSE_REQUEST_ACCEPTED)
          payload << IE.recovery_time_stamp(now_ntp32)
          hdr = Message.build(msg_type: 51, payload_len: payload.bytesize, seq: seq)
          pkt = hdr + payload
          @sock.send(pkt, 0, host, port)
          puts "[PFCP] -> AssocSetupResponse seq=#{seq} to #{host}:#{port}"
        end

        def now_ntp32
          unix = Time.now.to_i
          ntp = unix + 2_208_988_800
          ntp & 0xFFFFFFFF
        end
      end
    end
  end
end
