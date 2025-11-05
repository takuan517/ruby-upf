# frozen_string_literal: true

require 'ruby/upf/pfcp/message'
require 'ruby/upf/pfcp/ie'

module Ruby
  module Upf
    module Pfcp
      #
      # PFCP Session Manager
      #  - Handles PFCP Session Establishment, Modification, Deletion
      #  - Stores PDR/FAR information in memory
      #
      class Session
        SESSION_EST_REQ  = 50
        SESSION_EST_RESP = 51
        CREATE_PDR       = 1
        CREATE_FAR       = 3
        CAUSE_REQUEST_ACCEPTED = 1

        attr_reader :seid, :pdrs, :fars

        def initialize
          @sessions = {}
        end

        #
        # Handle incoming PFCP Session Establishment Request
        #
        def handle_establishment(request, from_host, from_port, sock)
          ies = IE.parse_all(request.payload || '')
          seid = rand(1..0xFFFFFFFFFFFF)
          @sessions[seid] = { pdrs: [], fars: [] }

          puts "[PFCP][Session] <- SessionEstablishmentRequest from #{from_host}"
          ies.each do |ie|
            parse_ie(ie, seid)
          end

          payload = ''
          payload << IE.cause(CAUSE_REQUEST_ACCEPTED)
          payload << IE.recovery_time_stamp(now_ntp32)

          hdr = Message.build(msg_type: SESSION_EST_RESP, payload_len: payload.bytesize, seq: request.seq, seid: seid)
          pkt = hdr + payload
          sock.send(pkt, 0, from_host, from_port)

          puts "[PFCP][Session] -> SessionEstablishmentResponse (SEID=#{seid}) sent"
        end

        private

        def parse_ie(ie, seid)
          case ie[:type]
          when CREATE_PDR
            puts "  IE CreatePDR (len=#{ie[:len]})"
            @sessions[seid][:pdrs] << ie
          when CREATE_FAR
            puts "  IE CreateFAR (len=#{ie[:len]})"
            @sessions[seid][:fars] << ie
          else
            # For debug
            puts "  IE type=#{ie[:type]} len=#{ie[:len]}"
          end
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
