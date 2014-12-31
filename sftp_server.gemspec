# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'sftp_server/version'

Gem::Specification.new do |spec|
  spec.name          = "sftp_server"
  spec.version       = SFTPServer::VERSION
  spec.authors       = ["M. Scott Ford"]
  spec.email         = ["scott@corgibytes.com"]
  spec.summary       = %q{A simple SFTP server for testing clients}
  spec.description   = %q{Uses libssh via FFI to create an SFTP server. Useful for testing interactions with a remote SFTP server.}
  spec.homepage      = "https://github.com/corgibytes/sftp_server"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.7"
  spec.add_development_dependency "rake", "~> 10.0"

  spec.add_dependency 'ffi', '~> 1.9'
end
