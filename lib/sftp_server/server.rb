require 'sftp_server/ssh/api'
require 'sftp_server/c/api'

require 'pry'

module SFTPServer
  class Server
    attr_accessor :user_name
    attr_accessor :password
    attr_accessor :rsa_key
    attr_accessor :dsa_key
    attr_accessor :port
    attr_accessor :listen_address

    def initialize(options = {})
      @user_name = options[:user_name]
      @password = options[:password]
      @rsa_key = options[:rsa_key]
      @dsa_key = options[:dsa_key]
      @port = options[:port]
      @listen_address = options[:listen_address]

      @authenticated = false
      @handles = {}
    end

    def set_bind_option(sshbind, key_type, key_value, value_type, value_value)
      result = SSH::API.ssh_bind_options_set(
        sshbind, key_type, key_value, value_type, value_value
      )
      fail SSH::API.ssh_get_error(sshbind) if result < 0
    end

    def bind_listen(bind)
      result = SSH::API.ssh_bind_listen(bind)
      fail SSH::API.ssh_get_error(bind) if result < 0
    end

    def bind_accept(bind, session)
      result = SSH::API.ssh_bind_accept(bind, session)
      fail SSH::API.ssh_get_error(bind) if result < 0
    end

    def handle_key_exchange(session)
      result = SSH::API.ssh_handle_key_exchange(session)
      fail SSH::API.ssh_get_error(session) if result < 0
    end

    def handle_auth(message)
    end

    def respond_auth_required(message)
      SSH::API.ssh_message_auth_set_methods(message, SSH::API::MessageAuthTypes::SSH_AUTH_METHOD_PASSWORD)
      SSH::API.ssh_message_reply_default(message)
    end

    def sftp_channel_request(session)
      sftp_channel_requested = false
      while !sftp_channel_requested
        message = SSH::API.ssh_message_get(session)
        if message
          message_type = SSH::API.ssh_message_type(message)
          puts "open sftp session message_type: #{message_type}"
          if message_type == SSH::API::MessageTypes::SSH_REQUEST_CHANNEL
            message_subtype = SSH::API.ssh_message_subtype(message)
            puts "open sftp session message_subtype: #{message_subtype}"

            case message_subtype
            when SSH::API::ChannelRequestTypes::SSH_CHANNEL_REQUEST_ENV
              env_name = SSH::API.ssh_message_channel_request_env_name(message)
              puts "request env name: #{env_name}"

              env_value = SSH::API.ssh_message_channel_request_env_value(message)
              puts "request env value: #{env_value}"
            when SSH::API::ChannelRequestTypes::SSH_CHANNEL_REQUEST_SUBSYSTEM
              subsystem_name = SSH::API.ssh_message_channel_request_subsystem(message)
              puts "request subsystem: #{subsystem_name}"
              if subsystem_name == 'sftp'
                SSH::API.ssh_message_channel_request_reply_success(message)
                sftp_channel_requested = true
              end
            end
          end
        end

        unless sftp_channel_requested
          SSH::API.ssh_message_reply_default(message)
        end
        SSH::API.ssh_message_free(message)
      end
      sftp_channel_requested
    end

    def open_channel(session)
      channel = nil
      while channel.nil?
        message = SSH::API.ssh_message_get(session)
        next unless message

        message_type = SSH::API.ssh_message_type(message)
        puts "channel message_type: #{message_type}"
        next unless message_type > -1

        case message_type
        when SSH::API::MessageTypes::SSH_REQUEST_CHANNEL_OPEN
          message_subtype = SSH::API.ssh_message_subtype(message)
          puts "channel message_subtype: #{message_subtype}"
          if message_subtype == SSH::API::ChannelTypes::SSH_CHANNEL_SESSION
            channel = SSH::API.ssh_message_channel_request_open_reply_accept(message)
            break
          end
        else
          SSH::API.ssh_message_reply_default(message)
        end
        SSH::API.ssh_message_free(message)
      end
      channel
    end

    def authenticate(session)
      authenticated = false
      while !authenticated
        message = SSH::API.ssh_message_get(session)
        next unless message

        message_type = SSH::API.ssh_message_type(message)
        puts "message_type: #{message_type}"
        next unless message_type > -1

        case message_type
        when SSH::API::MessageTypes::SSH_REQUEST_AUTH
          message_subtype = SSH::API.ssh_message_subtype(message)
          puts "auth message_subtype: #{message_subtype}"
          case message_subtype
          when SSH::API::MessageAuthTypes::SSH_AUTH_METHOD_PASSWORD
            request_user_name = SSH::API.ssh_message_auth_user(message)
            request_password = SSH::API.ssh_message_auth_password(message)
            puts user_name
            puts password
            if user_name == request_user_name && password == request_password
              SSH::API.ssh_message_auth_reply_success(message, 0)
              SSH::API.ssh_message_free(message)
              authenticated = true
              break
            else
              SSH::API.ssh_message_reply_default(message)
              next
            end
          else
            respond_auth_required(message) unless @authenticated
          end
        else
          SSH::API.ssh_message_reply_default(message)
        end
      end
      authenticated
    end

    def init_sftp_session(sftp_session)
      result = SSH::API.sftp_server_init(sftp_session)
      fail SSH::API.ssh_get_error(sftp_session) unless result == 0
    end

    def sftp_message_loop(sftp_session)
      while true
        client_message = SSH::API.sftp_get_client_message(sftp_session)
        puts "client_message: #{client_message}"
        return if client_message.null?

        client_message_type = SSH::API.sftp_client_message_get_type(client_message)
        next unless client_message_type
        puts "client_message_type: #{client_message_type}"

        case client_message_type
        when SSH::API::SFTPCommands::SSH_FXP_REALPATH
          puts "realpath"

          file_name = SSH::API.sftp_client_message_get_filename(client_message)
          puts "file_name: #{file_name}"

          long_file_name = File.expand_path(file_name)

          SSH::API.sftp_reply_names_add(client_message, long_file_name, long_file_name, SSH::API::SFTPAttributes.new.to_ptr)
          SSH::API.sftp_reply_names(client_message)
        when SSH::API::SFTPCommands::SSH_FXP_OPENDIR
          puts "opendir"

          dir_name = SSH::API.sftp_client_message_get_filename(client_message)
          long_dir_name = File.expand_path(dir_name)
          puts "long_dir_name: #{long_dir_name}"

          @handles[long_dir_name] = :open

          long_dir_name_pointer = FFI::MemoryPointer.from_string(long_dir_name)
          handle = SSH::API.sftp_handle_alloc(sftp_session, long_dir_name_pointer)

          SSH::API.sftp_reply_handle(client_message, handle)
        when SSH::API::SFTPCommands::SSH_FXP_READDIR
          puts "readdir"

          client_message_data = SSH::API::SFTPClientMessage.new(client_message)
          handle = SSH::API.sftp_handle(sftp_session, client_message_data[:handle])
          long_dir_name = handle.read_string
          puts "long_dir_name: #{long_dir_name}"

          if @handles[long_dir_name] == :open
            Dir.entries(long_dir_name).each do |entry|
              SSH::API.sftp_reply_names_add(
                client_message,
                entry,
                entry,
                SSH::API::SFTPAttributes.new.to_ptr
              )
            end
            @handles[long_dir_name] = :read
            SSH::API.sftp_reply_names(client_message)
          else
            SSH::API.sftp_reply_status(client_message, SSH::API::SFTPStatus::SSH_FX_EOF, 'End-of-file encountered')
          end
        when SSH::API::SFTPCommands::SSH_FXP_CLOSE
          puts 'close'

          client_message_data = SSH::API::SFTPClientMessage.new(client_message)
          handle = SSH::API.sftp_handle(sftp_session, client_message_data[:handle])
          long_dir_name = handle.read_string
          puts "long_dir_name: #{long_dir_name}"

          @handles.delete(long_dir_name)

          SSH::API.sftp_reply_status(client_message, SSH::API::SFTPStatus::SSH_FX_OK, 'Success')
        when SSH::API::SFTPCommands::SSH_FXP_LSTAT
          puts 'lstat'

          file_name = SSH::API.sftp_client_message_get_filename(client_message)
          puts "file_name: #{file_name}"

          long_file_name = File.expand_path(file_name)

          file_stat = File.lstat(long_file_name)

          attributes = SSH::API::SFTPAttributes.new

          attributes[:flags] = 0
          attributes[:flags] |= SSH::API::Attributes::SSH_FILEXFER_ATTR_SIZE
          attributes[:size] = file_stat.size
          attributes[:flags] |= SSH::API::Attributes::SSH_FILEXFER_ATTR_UIDGID
          attributes[:uid] = file_stat.uid
          attributes[:gid] = file_stat.gid
          attributes[:flags] |= SSH::API::Attributes::SSH_FILEXFER_ATTR_PERMISSIONS
          attributes[:permissions] = file_stat.mode
          attributes[:flags] |= SSH::API::Attributes::SSH_FILEXFER_ATTR_ACMODTIME
          attributes[:atime] = file_stat.atime.to_i
          attributes[:mtime] = file_stat.mtime.to_i

          SSH::API.sftp_reply_attr(client_message, attributes.to_ptr)
        when SSH::API::SFTPCommands::SSH_FXP_STAT
          puts 'stat'

          file_name = SSH::API.sftp_client_message_get_filename(client_message)
          puts "file_name: #{file_name}"

          long_file_name = File.expand_path(file_name)

          file_stat = File.stat(long_file_name)

          attributes = SSH::API::SFTPAttributes.new

          attributes[:flags] = 0
          attributes[:flags] |= SSH::API::Attributes::SSH_FILEXFER_ATTR_SIZE
          attributes[:size] = file_stat.size
          attributes[:flags] |= SSH::API::Attributes::SSH_FILEXFER_ATTR_UIDGID
          attributes[:uid] = file_stat.uid
          attributes[:gid] = file_stat.gid
          attributes[:flags] |= SSH::API::Attributes::SSH_FILEXFER_ATTR_PERMISSIONS
          attributes[:permissions] = file_stat.mode
          attributes[:flags] |= SSH::API::Attributes::SSH_FILEXFER_ATTR_ACMODTIME
          attributes[:atime] = file_stat.atime.to_i
          attributes[:mtime] = file_stat.mtime.to_i

          SSH::API.sftp_reply_attr(client_message, attributes.to_ptr)
        when SSH::API::SFTPCommands::SSH_FXP_OPEN
          file_name = SSH::API.sftp_client_message_get_filename(client_message)
          long_file_name = File.expand_path(file_name)
          puts "long_file_name: #{long_file_name}"

          client_message_data = SSH::API::SFTPClientMessage.new(client_message)
          message_flags = client_message_data[:flags]
          flags = 0
          if (message_flags & SSH::API::Flags::SSH_FXF_READ == SSH::API::Flags::SSH_FXF_READ) &&
            (message_flags & SSH::API::Flags::SSH_FXF_WRITE == SSH::API::Flags::SSH_FXF_WRITE)
            flags = File::Constants::RDWR
          elsif (message_flags & SSH::API::Flags::SSH_FXF_READ == SSH::API::Flags::SSH_FXF_READ)
            flags = File::Constants::RDONLY
          elsif (message_flags & SSH::API::Flags::SSH_FXF_WRITE == SSH::API::Flags::SSH_FXF_WRITE)
            flags = File::Constants::WRONLY
          end

          if (message_flags & SSH::API::Flags::SSH_FXF_APPEND == SSH::API::Flags::SSH_FXF_APPEND)
            flags |= File::Constants::APPEND
          end

          if (message_flags & SSH::API::Flags::SSH_FXF_CREAT == SSH::API::Flags::SSH_FXF_CREAT)
            flags |= File::Constants::CREAT
          end

          if (message_flags & SSH::API::Flags::SSH_FXF_TRUNC == SSH::API::Flags::SSH_FXF_TRUNC)
            flags |= File::Constants::TRUNC
          end

          if (message_flags & SSH::API::Flags::SSH_FXF_EXCL == SSH::API::Flags::SSH_FXF_EXCL)
            flags |= File::Constants::EXCL
          end

          @handles[long_file_name] = File.open(long_file_name, flags)

          long_file_name_pointer = FFI::MemoryPointer.from_string(long_file_name)
          handle = SSH::API.sftp_handle_alloc(sftp_session, long_file_name_pointer)

          SSH::API.sftp_reply_handle(client_message, handle)
        when SSH::API::SFTPCommands::SSH_FXP_READ
          client_message_data = SSH::API::SFTPClientMessage.new(client_message)
          handle = SSH::API.sftp_handle(sftp_session, client_message_data[:handle])
          long_file_name = handle.read_string
          puts "long_file_name: #{long_file_name}"

          file = @handles[long_file_name]
          if file
            file.seek(client_message_data[:offset])
            data = file.read(client_message_data[:len])
            if data
              buffer = FFI::MemoryPointer.new(:char, data.size)
              buffer.put_bytes(0, data)
              SSH::API.sftp_reply_data(client_message, buffer, data.size)
            else
              SSH::API.sftp_reply_status(client_message, SSH::API::SFTPStatus::SSH_FX_EOF, 'End-of-file encountered')
            end
          end
        when SSH::API::SFTPCommands::SSH_FXP_WRITE
          client_message_data = SSH::API::SFTPClientMessage.new(client_message)
          handle = SSH::API.sftp_handle(sftp_session, client_message_data[:handle])
          long_file_name = handle.read_string
          puts "long_file_name: #{long_file_name}"

          file = @handles[long_file_name]
          if file
            file.seek(client_message_data[:offset])
            buffer = SSH::API.sftp_client_message_get_data(client_message)
            file.write(buffer.read_string)
            SSH::API.sftp_reply_status(client_message, SSH::API::SFTPStatus::SSH_FX_OK, 'Success')
          end
        end

        SSH::API.sftp_client_message_free(client_message)
      end
    end

    def open
      ssh_bind = SSH::API.ssh_bind_new
      session = SSH::API.ssh_new

      set_bind_option(ssh_bind, :int, SSH::API::BindOptions::SSH_BIND_OPTIONS_BINDADDR, :string, listen_address) if listen_address
      set_bind_option(ssh_bind, :int, SSH::API::BindOptions::SSH_BIND_OPTIONS_BINDPORT_STR, :string, port) if port
      set_bind_option(ssh_bind, :int, SSH::API::BindOptions::SSH_BIND_OPTIONS_RSAKEY, :string, rsa_key) if rsa_key
      set_bind_option(ssh_bind, :int, SSH::API::BindOptions::SSH_BIND_OPTIONS_DSAKEY, :string, dsa_key) if dsa_key

      bind_listen(ssh_bind)
      bind_accept(ssh_bind, session)
      handle_key_exchange(session)

      if authenticate(session)
        channel = open_channel(session)
        if channel
          if sftp_channel_request(session)
            sftp_session = SSH::API.sftp_server_new(session, channel)
            init_sftp_session(sftp_session)
            sftp_message_loop(sftp_session)
          end
        end
      end
    end
  end
end
