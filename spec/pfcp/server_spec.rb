# frozen_string_literal: true

require 'ruby/upf/pfcp/server'

RSpec.describe Ruby::Upf::Pfcp::Server do
  it 'can initialize PFCP server without error' do
    expect {
      Ruby::Upf::Pfcp::Server.new(bind: '127.0.0.1', node_ip: '127.0.0.1')
    }.not_to raise_error
  end
end
