#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'

require 'sftp_server'

dsa_key = File.expand_path('../keys/ssh_host_dsa_key', __FILE__)
fail "could not find dsa key file: #{dsa_key}" unless File.exist?(dsa_key)

rsa_key = File.expand_path('../keys/ssh_host_rsa_key', __FILE__)
fail "could not find rsa key file: #{rsa_key}" unless File.exist?(rsa_key)

server_pid = fork do
  server = SFTPServer::Server.new(
    dsa_key: dsa_key,
    rsa_key: rsa_key,
    user_name: 'test',
    password: 'test',
    port: '2299',
    listen_address: '0.0.0.0'
  )
  server.open
end

puts 'Waiting for server to close'

Process.wait(server_pid)

puts 'Server closed'
