# SFTPServer

A simple SFTP server for testing clients:

Uses libssh via FFI to create an SFTP server. Useful for testing interactions with a remote SFTP server.

## Installation

### Installing libssh

This gem was developed against libssh 0.6.3. It will **not work** when using an older version.

To install libssh using Homebrew on Mac OS X:

```
brew install libssh
```

To install on Ubuntu 12.04 or Ubuntu 14.04, you'll need to build the library from source, because the versions that are available in Ubuntu package repositories are too old.

### Installing the gem

Add this line to your application's Gemfile:

```ruby
gem 'sftp_server'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install sftp_server

## Usage

TODO: Write usage instructions here

## Contributing

1. Fork it ( https://github.com/corgibytes/sftp_server/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
