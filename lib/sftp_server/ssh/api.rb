require 'ffi'

module SFTPServer
  module SSH
    # Private
    module API
      extend FFI::Library
      ffi_lib_flags :now, :global
      ffi_lib 'ssh'

      class Bind < FFI::Struct
      end

      module BindOptions
        SSH_BIND_OPTIONS_BINDADDR = 0
        SSH_BIND_OPTIONS_BINDPORT = 1
        SSH_BIND_OPTIONS_BINDPORT_STR = 2
        SSH_BIND_OPTIONS_HOSTKEY = 3
        SSH_BIND_OPTIONS_DSAKEY = 4
        SSH_BIND_OPTIONS_RSAKEY = 5
        SSH_BIND_OPTIONS_BANNER = 6
        SSH_BIND_OPTIONS_LOG_VERBOSITY = 7
        SSH_BIND_OPTIONS_LOG_VERBOSITY_STR = 8
        SSH_BIND_OPTIONS_ECDSAKEY = 9
      end

      class Session < FFI::Struct
      end

      class Message < FFI::Struct
      end

      class String < FFI::Struct
        pack 1
        layout :size, :uint32,
          :data, :pointer
      end

      module MessageTypes
        SSH_REQUEST_AUTH = 1
        SSH_REQUEST_CHANNEL_OPEN = 2
        SSH_REQUEST_CHANNEL = 3
        SSH_REQUEST_SERVICE = 4
        SSH_REQUEST_GLOBAL = 5
      end

      module MessageAuthTypes
        SSH_AUTH_METHOD_UNKNOWN = 0
        SSH_AUTH_METHOD_NONE = 0x0001
        SSH_AUTH_METHOD_PASSWORD = 0x0002
        SSH_AUTH_METHOD_PUBLICKEY = 0x0004
        SSH_AUTH_METHOD_HOSTBASED = 0x0008
        SSH_AUTH_METHOD_INTERACTIVE = 0x0010
        SSH_AUTH_METHOD_GSSAPI_MIC = 0x0020
      end

      class Channel < FFI::Struct
      end

      module ChannelTypes
        SSH_CHANNEL_UNKNOWN = 0
        SSH_CHANNEL_SESSION = 1
        SSH_CHANNEL_DIRECT_TCPIP = 2
        SSH_CHANNEL_FORWARDED_TCPIP = 3
        SSH_CHANNEL_X11 = 4
      end

      module ChannelRequestTypes
        SSH_CHANNEL_REQUEST_UNKNOWN = 0
        SSH_CHANNEL_REQUEST_PTY = 1
        SSH_CHANNEL_REQUEST_EXEC = 2
        SSH_CHANNEL_REQUEST_SHELL = 3
        SSH_CHANNEL_REQUEST_ENV = 4
        SSH_CHANNEL_REQUEST_SUBSYSTEM = 5
        SSH_CHANNEL_REQUEST_WINDOW_CHANGE = 6
        SSH_CHANNEL_REQUEST_X11 = 7
      end

      PublicKeyState = enum(:error, -1, :none, :valid, :wrong)
      enum :keycmp, [:public, 0, :private]
      enum :keytypes, [:unknown, 0, :dss, :rsa, :rsa1, :ecdsa, :ed25519]

      attach_function :ssh_init, [], :int
      attach_function :ssh_bind_new, [], Bind
      attach_function :ssh_bind_free, [Bind], :int
      attach_function :ssh_new, [], Session
      attach_function :ssh_bind_options_set, [Bind, :varargs], :int
      attach_function :ssh_options_set, [Bind, :varargs], :int
      attach_function :ssh_bind_listen, [Bind], :int
      attach_function :ssh_disconnect, [Session], :int
      attach_function :ssh_bind_accept, [Bind, Session], :int
      attach_function :ssh_get_error, [Session], :string
      attach_function :ssh_handle_key_exchange, [Session], :int
      attach_function :ssh_message_get, [Session], Message
      attach_function :ssh_message_type, [Message], :int
      attach_function :ssh_bind_accept_fd, [:pointer, :pointer, :int], :string

      attach_function :ssh_message_subtype, [Message], :int

      attach_function	:ssh_message_auth_user, [:string], :string
      attach_function	:ssh_message_auth_password, [:string], :string
      attach_function :ssh_message_auth_pubkey, [Message], :pointer
      attach_function :ssh_message_auth_publickey_state, [Message], PublicKeyState
      attach_function :ssh_message_free, [Message], :int
      attach_function :ssh_message_auth_set_methods, [Message, :int], :int
      attach_function :ssh_message_reply_default, [Message], :int
      attach_function :ssh_message_auth_user, [Message], :string
      attach_function :ssh_message_auth_password, [Message], :string
      attach_function :ssh_message_auth_reply_success, [Message, :int], :int
      attach_function :ssh_message_channel_request_open_reply_accept, [Message],
                      Channel

      attach_function :ssh_message_channel_request_reply_success, [Message],
                      :int

      # LIBSSH_API const char *ssh_message_channel_request_subsystem(ssh_message msg);
      attach_function :ssh_message_channel_request_subsystem, [Message], :string

      # LIBSSH_API int ssh_channel_close(ssh_channel channel);
      attach_function :ssh_channel_close, [Channel], :int
      # LIBSSH_API void ssh_channel_free(ssh_channel channel);
      attach_function :ssh_channel_free, [Channel], :int

      # LIBSSH_API const char *ssh_message_channel_request_env_name(ssh_message msg);
      attach_function :ssh_message_channel_request_env_name, [Message], :string
      # LIBSSH_API const char *ssh_message_channel_request_env_value(ssh_message msg);
      attach_function :ssh_message_channel_request_env_value, [Message], :string

      # typedef struct sftp_attributes_struct* sftp_attributes;
      # typedef struct sftp_client_message_struct* sftp_client_message;
      # typedef struct sftp_dir_struct* sftp_dir;
      # typedef struct sftp_ext_struct *sftp_ext;
      # typedef struct sftp_file_struct* sftp_file;
      # typedef struct sftp_message_struct* sftp_message;
      # typedef struct sftp_packet_struct* sftp_packet;
      # typedef struct sftp_request_queue_struct* sftp_request_queue;
      # typedef struct sftp_session_struct* sftp_session;
      # typedef struct sftp_status_message_struct* sftp_status_message;
      # typedef struct sftp_statvfs_struct* sftp_statvfs_t;

      attach_function :ssh_pki_import_pubkey_base64, [:string, :keytypes, :pointer], :int
      attach_function :ssh_key_cmp, [:pointer, :pointer, :keycmp], :int

      class SFTPSession < FFI::Struct
      end
      # struct sftp_session_struct {
      #   ssh_session session;
      #   ssh_channel channel;
      #   int server_version;
      #   int client_version;
      #   int version;
      #   sftp_request_queue queue;
      #   uint32_t id_counter;
      #   int errnum;
      #   void **handles;
      #   sftp_ext ext;
      # };

      class SFTPPacket < FFI::Struct
      end
      # struct sftp_packet_struct {
      #   sftp_session sftp;
      #   uint8_t type;
      #   ssh_buffer payload;
      # };

      class SFTPFile < FFI::Struct
      end
      # /* file handler */
      # struct sftp_file_struct {
      #   sftp_session sftp;
      #   char *name;
      #   uint64_t offset;
      #   ssh_string handle;
      #   int eof;
      #   int nonblocking;
      # };

      class SFTPDir < FFI::Struct
      end
      # struct sftp_dir_struct {
      #   sftp_session sftp;
      #   char *name;
      #   ssh_string handle; /* handle to directory */
      #   ssh_buffer buffer; /* contains raw attributes from server which haven't been parsed */
      #   uint32_t count; /* counts the number of following attributes structures into buffer */
      #   int eof; /* end of directory listing */
      # };

      class SFTPMessage < FFI::Struct
      end
      # struct sftp_message_struct {
      #   sftp_session sftp;
      #   uint8_t packet_type;
      #   ssh_buffer payload;
      #   uint32_t id;
      # };

      class SFTPAttributes < FFI::Struct
        layout :name, :string,
        :longname, :string,
        :flags, :uint32,
        :type, :uint8,
        :size, :uint64,
        :uid, :uint32,
        :gid, :uint32,
        :owner, :string, # set if openssh and version 4
        :group, :string, # set if openssh and version 4
        :permissions, :uint32,
        :atime64, :uint64,
        :atime, :uint32,
        :atime_nseconds, :uint32,
        :createtime, :uint64,
        :createtime_nseconds, :uint32,
        :mtime64, :uint64,
        :mtime, :uint32,
        :mtime_nseconds, :uint32,
        :acl, :string,
        :extended_count, :uint32,
        :extended_type, String.ptr,
        :extended_data, String.ptr
      end
      # struct sftp_attributes_struct {
      #   char *name;
      #   char *longname; /* ls -l output on openssh, not reliable else */
      #   uint32_t flags;
      #   uint8_t type;
      #   uint64_t size;
      #   uint32_t uid;
      #   uint32_t gid;
      #   char *owner; /* set if openssh and version 4 */
      #   char *group; /* set if openssh and version 4 */
      #   uint32_t permissions;
      #   uint64_t atime64;
      #   uint32_t atime;
      #   uint32_t atime_nseconds;
      #   uint64_t createtime;
      #   uint32_t createtime_nseconds;
      #   uint64_t mtime64;
      #   uint32_t mtime;
      #   uint32_t mtime_nseconds;
      #   ssh_string acl;
      #   uint32_t extended_count;
      #   ssh_string extended_type;
      #   ssh_string extended_data;
      # };

      class SFTPClientMessage < FFI::Struct
        layout :sftp, SFTPSession.ptr,
          :type, :uint8,
          :id, :uint32,
          :filename, :string, # can be "path"
          :flags, :uint32,
          :attr, SFTPAttributes.ptr,
          :handle, String.ptr,
          :offset, :uint64,
          :len, :uint32,
          :attr_num, :int,
          # TODO: define Buffer < FFI::Struct
          # ssh_buffer attrbuf; /* used by sftp_reply_attrs */
          :attrbuf, :pointer,
          :data, String.ptr, # can be newpath of rename()
          # TODO: define Buffer < FFI::Struct
          # ssh_buffer complete_message; /* complete message in case of retransmission*/
          :complete_message, :pointer,
          :str_data, :string # cstring version of data
      end
      # /* this is a bunch of all data that could be into a message */
      # struct sftp_client_message_struct {
      #   sftp_session sftp;
      #   uint8_t type;
      #   uint32_t id;
      #   char *filename; /* can be "path" */
      #   uint32_t flags;
      #   sftp_attributes attr;
      #   ssh_string handle;
      #   uint64_t offset;
      #   uint32_t len;
      #   int attr_num;
      #   ssh_buffer attrbuf; /* used by sftp_reply_attrs */
      #   ssh_string data; /* can be newpath of rename() */
      #   ssh_buffer complete_message; /* complete message in case of retransmission*/
      #     char *str_data; /* cstring version of data */
      # };

      class SFTPRequestQueue < FFI::Struct
      end
      # struct sftp_request_queue_struct {
      #   sftp_request_queue next;
      #   sftp_message message;
      # };

      class SFTPStatusMessage < FFI::Struct
      end
      # /* SSH_FXP_MESSAGE described into .7 page 26 */
      # struct sftp_status_message_struct {
      #   uint32_t id;
      #   uint32_t status;
      #   ssh_string error;
      #   ssh_string lang;
      #   char *errormsg;
      #   char *langmsg;
      # };

      class SFTPStatVFS < FFI::Struct
      end
      # /**
      # * @brief SFTP statvfs structure.
      # */
      # struct sftp_statvfs_struct {
      #   uint64_t f_bsize;   /** file system block size */
      #   uint64_t f_frsize;  /** fundamental fs block size */
      #   uint64_t f_blocks;  /** number of blocks (unit f_frsize) */
      #   uint64_t f_bfree;   /** free blocks in file system */
      #   uint64_t f_bavail;  /** free blocks for non-root */
      #   uint64_t f_files;   /** total file inodes */
      #   uint64_t f_ffree;   /** free file inodes */
      #   uint64_t f_favail;  /** free file inodes for to non-root */
      #   uint64_t f_fsid;    /** file system id */
      #   uint64_t f_flag;    /** bit mask of f_flag values */
      #   uint64_t f_namemax; /** maximum filename length */
      # };

      # /**
      # * @brief Start a new sftp session.
      # *
      # * @param session       The ssh session to use.
      # *
      # * @return              A new sftp session or NULL on error.
      # *
      # * @see sftp_free()
      # */
      # LIBSSH_API sftp_session sftp_new(ssh_session session);

      # /**
      # * @brief Start a new sftp session with an existing channel.
      # *
      # * @param session       The ssh session to use.
      # * @param channel		An open session channel with subsystem already allocated
      # *
      # * @return              A new sftp session or NULL on error.
      # *
      # * @see sftp_free()
      # */
      # LIBSSH_API sftp_session sftp_new_channel(ssh_session session, ssh_channel channel);

      # /**
      # * @brief Close and deallocate a sftp session.
      # *
      # * @param sftp          The sftp session handle to free.
      # */
      # LIBSSH_API void sftp_free(sftp_session sftp);
      #
      # /**
      # * @brief Initialize the sftp session with the server.
      # *
      # * @param sftp          The sftp session to initialize.
      # *
      # * @return              0 on success, < 0 on error with ssh error set.
      # *
      # * @see sftp_new()
      # */
      # LIBSSH_API int sftp_init(sftp_session sftp);
      #
      # /**
      # * @brief Get the last sftp error.
      # *
      # * Use this function to get the latest error set by a posix like sftp function.
      # *
      # * @param sftp          The sftp session where the error is saved.
      # *
      # * @return              The saved error (see server responses), < 0 if an error
      # *                      in the function occured.
      # *
      # * @see Server responses
      # */
      # LIBSSH_API int sftp_get_error(sftp_session sftp);
      #
      # /**
      # * @brief Get the count of extensions provided by the server.
      # *
      # * @param  sftp         The sftp session to use.
      # *
      # * @return The count of extensions provided by the server, 0 on error or
      # *         not available.
      # */
      # LIBSSH_API unsigned int sftp_extensions_get_count(sftp_session sftp);
      #
      # /**
      # * @brief Get the name of the extension provided by the server.
      # *
      # * @param  sftp         The sftp session to use.
      # *
      # * @param  indexn        The index number of the extension name you want.
      # *
      # * @return              The name of the extension.
      # */
      # LIBSSH_API const char *sftp_extensions_get_name(sftp_session sftp, unsigned int indexn);
      #
      # /**
      # * @brief Get the data of the extension provided by the server.
      # *
      # * This is normally the version number of the extension.
      # *
      # * @param  sftp         The sftp session to use.
      # *
      # * @param  indexn        The index number of the extension data you want.
      # *
      # * @return              The data of the extension.
      # */
      # LIBSSH_API const char *sftp_extensions_get_data(sftp_session sftp, unsigned int indexn);
      #
      # /**
      # * @brief Check if the given extension is supported.
      # *
      # * @param  sftp         The sftp session to use.
      # *
      # * @param  name         The name of the extension.
      # *
      # * @param  data         The data of the extension.
      # *
      # * @return 1 if supported, 0 if not.
      # *
      # * Example:
      # *
      # * @code
      # * sftp_extension_supported(sftp, "statvfs@openssh.com", "2");
      # * @endcode
      # */
      # LIBSSH_API int sftp_extension_supported(sftp_session sftp, const char *name,
      # const char *data);
      #
      # /**
      # * @brief Open a directory used to obtain directory entries.
      # *
      # * @param session       The sftp session handle to open the directory.
      # * @param path          The path of the directory to open.
      # *
      # * @return              A sftp directory handle or NULL on error with ssh and
      # *                      sftp error set.
      # *
      # * @see                 sftp_readdir
      # * @see                 sftp_closedir
      # */
      # LIBSSH_API sftp_dir sftp_opendir(sftp_session session, const char *path);
      #
      # /**
      # * @brief Get a single file attributes structure of a directory.
      # *
      # * @param session      The sftp session handle to read the directory entry.
      # * @param dir          The opened sftp directory handle to read from.
      # *
      # * @return             A file attribute structure or NULL at the end of the
      # *                     directory.
      # *
      # * @see                sftp_opendir()
      # * @see                sftp_attribute_free()
      # * @see                sftp_closedir()
      # */
      # LIBSSH_API sftp_attributes sftp_readdir(sftp_session session, sftp_dir dir);
      #
      # /**
      # * @brief Tell if the directory has reached EOF (End Of File).
      # *
      # * @param dir           The sftp directory handle.
      # *
      # * @return              1 if the directory is EOF, 0 if not.
      # *
      # * @see                 sftp_readdir()
      # */
      # LIBSSH_API int sftp_dir_eof(sftp_dir dir);
      #
      # /**
      # * @brief Get information about a file or directory.
      # *
      # * @param session       The sftp session handle.
      # * @param path          The path to the file or directory to obtain the
      # *                      information.
      # *
      # * @return              The sftp attributes structure of the file or directory,
      # *                      NULL on error with ssh and sftp error set.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API sftp_attributes sftp_stat(sftp_session session, const char *path);
      #
      # /**
      # * @brief Get information about a file or directory.
      # *
      # * Identical to sftp_stat, but if the file or directory is a symbolic link,
      # * then the link itself is stated, not the file that it refers to.
      # *
      # * @param session       The sftp session handle.
      # * @param path          The path to the file or directory to obtain the
      # *                      information.
      # *
      # * @return              The sftp attributes structure of the file or directory,
      # *                      NULL on error with ssh and sftp error set.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API sftp_attributes sftp_lstat(sftp_session session, const char *path);
      #
      # /**
      # * @brief Get information about a file or directory from a file handle.
      # *
      # * @param file          The sftp file handle to get the stat information.
      # *
      # * @return              The sftp attributes structure of the file or directory,
      # *                      NULL on error with ssh and sftp error set.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API sftp_attributes sftp_fstat(sftp_file file);
      #
      # /**
      # * @brief Free a sftp attribute structure.
      # *
      # * @param file          The sftp attribute structure to free.
      # */
      # LIBSSH_API void sftp_attributes_free(sftp_attributes file);
      #
      # /**
      # * @brief Close a directory handle opened by sftp_opendir().
      # *
      # * @param dir           The sftp directory handle to close.
      # *
      # * @return              Returns SSH_NO_ERROR or SSH_ERROR if an error occured.
      # */
      # LIBSSH_API int sftp_closedir(sftp_dir dir);
      #
      # /**
      # * @brief Close an open file handle.
      # *
      # * @param file          The open sftp file handle to close.
      # *
      # * @return              Returns SSH_NO_ERROR or SSH_ERROR if an error occured.
      # *
      # * @see                 sftp_open()
      # */
      # LIBSSH_API int sftp_close(sftp_file file);
      #
      # /**
      # * @brief Open a file on the server.
      # *
      # * @param session       The sftp session handle.
      # *
      # * @param file          The file to be opened.
      # *
      # * @param accesstype    Is one of O_RDONLY, O_WRONLY or O_RDWR which request
      # *                      opening  the  file  read-only,write-only or read/write.
      # *                      Acesss may also be bitwise-or'd with one or  more of
      # *                      the following:
      # *                      O_CREAT - If the file does not exist it will be
      # *                      created.
      # *                      O_EXCL - When  used with O_CREAT, if the file already
      # *                      exists it is an error and the open will fail.
      # *                      O_TRUNC - If the file already exists it will be
      # *                      truncated.
      # *
      # * @param mode          Mode specifies the permissions to use if a new file is
      # *                      created.  It  is  modified  by  the process's umask in
      # *                      the usual way: The permissions of the created file are
      # *                      (mode & ~umask)
      # *
      # * @return              A sftp file handle, NULL on error with ssh and sftp
      # *                      error set.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API sftp_file sftp_open(sftp_session session, const char *file, int accesstype,
      # mode_t mode);
      #
      # /**
      # * @brief Make the sftp communication for this file handle non blocking.
      # *
      # * @param[in]  handle   The file handle to set non blocking.
      # */
      # LIBSSH_API void sftp_file_set_nonblocking(sftp_file handle);
      #
      # /**
      # * @brief Make the sftp communication for this file handle blocking.
      # *
      # * @param[in]  handle   The file handle to set blocking.
      # */
      # LIBSSH_API void sftp_file_set_blocking(sftp_file handle);
      #
      # /**
      # * @brief Read from a file using an opened sftp file handle.
      # *
      # * @param file          The opened sftp file handle to be read from.
      # *
      # * @param buf           Pointer to buffer to recieve read data.
      # *
      # * @param count         Size of the buffer in bytes.
      # *
      # * @return              Number of bytes written, < 0 on error with ssh and sftp
      # *                      error set.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API ssize_t sftp_read(sftp_file file, void *buf, size_t count);

      # /**
      # * @brief Start an asynchronous read from a file using an opened sftp file handle.
      # *
      # * Its goal is to avoid the slowdowns related to the request/response pattern
      # * of a synchronous read. To do so, you must call 2 functions:
      # *
      # * sftp_async_read_begin() and sftp_async_read().
      # *
      # * The first step is to call sftp_async_read_begin(). This function returns a
      # * request identifier. The second step is to call sftp_async_read() using the
      # * returned identifier.
      # *
      # * @param file          The opened sftp file handle to be read from.
      # *
      # * @param len           Size to read in bytes.
      # *
      # * @return              An identifier corresponding to the sent request, < 0 on
      # *                      error.
      # *
      # * @warning             When calling this function, the internal offset is
      # *                      updated corresponding to the len parameter.
      # *
      # * @warning             A call to sftp_async_read_begin() sends a request to
      # *                      the server. When the server answers, libssh allocates
      # *                      memory to store it until sftp_async_read() is called.
      # *                      Not calling sftp_async_read() will lead to memory
      # *                      leaks.
      # *
      # * @see                 sftp_async_read()
      # * @see                 sftp_open()
      # */
      # LIBSSH_API int sftp_async_read_begin(sftp_file file, uint32_t len);

      # /**
      # * @brief Wait for an asynchronous read to complete and save the data.
      # *
      # * @param file          The opened sftp file handle to be read from.
      # *
      # * @param data          Pointer to buffer to recieve read data.
      # *
      # * @param len           Size of the buffer in bytes. It should be bigger or
      # *                      equal to the length parameter of the
      # *                      sftp_async_read_begin() call.
      # *
      # * @param id            The identifier returned by the sftp_async_read_begin()
      # *                      function.
      # *
      # * @return              Number of bytes read, 0 on EOF, SSH_ERROR if an error
      # *                      occured, SSH_AGAIN if the file is opened in nonblocking
      # *                      mode and the request hasn't been executed yet.
      # *
      # * @warning             A call to this function with an invalid identifier
      # *                      will never return.
      # *
      # * @see sftp_async_read_begin()
      # */
      # LIBSSH_API int sftp_async_read(sftp_file file, void *data, uint32_t len, uint32_t id);
      #
      # /**
      # * @brief Write to a file using an opened sftp file handle.
      # *
      # * @param file          Open sftp file handle to write to.
      # *
      # * @param buf           Pointer to buffer to write data.
      # *
      # * @param count         Size of buffer in bytes.
      # *
      # * @return              Number of bytes written, < 0 on error with ssh and sftp
      # *                      error set.
      # *
      # * @see                 sftp_open()
      # * @see                 sftp_read()
      # * @see                 sftp_close()
      # */
      # LIBSSH_API ssize_t sftp_write(sftp_file file, const void *buf, size_t count);
      #
      # /**
      # * @brief Seek to a specific location in a file.
      # *
      # * @param file         Open sftp file handle to seek in.
      # *
      # * @param new_offset   Offset in bytes to seek.
      # *
      # * @return             0 on success, < 0 on error.
      # */
      # LIBSSH_API int sftp_seek(sftp_file file, uint32_t new_offset);
      #
      # /**
      # * @brief Seek to a specific location in a file. This is the
      # * 64bit version.
      # *
      # * @param file         Open sftp file handle to seek in.
      # *
      # * @param new_offset   Offset in bytes to seek.
      # *
      # * @return             0 on success, < 0 on error.
      # */
      # LIBSSH_API int sftp_seek64(sftp_file file, uint64_t new_offset);
      #
      # /**
      # * @brief Report current byte position in file.
      # *
      # * @param file          Open sftp file handle.
      # *
      # * @return              The offset of the current byte relative to the beginning
      # *                      of the file associated with the file descriptor. < 0 on
      # *                      error.
      # */
      # LIBSSH_API unsigned long sftp_tell(sftp_file file);
      #
      # /**
      # * @brief Report current byte position in file.
      # *
      # * @param file          Open sftp file handle.
      # *
      # * @return              The offset of the current byte relative to the beginning
      # *                      of the file associated with the file descriptor. < 0 on
      # *                      error.
      # */
      # LIBSSH_API uint64_t sftp_tell64(sftp_file file);
      #
      # /**
      # * @brief Rewinds the position of the file pointer to the beginning of the
      # * file.
      # *
      # * @param file          Open sftp file handle.
      # */
      # LIBSSH_API void sftp_rewind(sftp_file file);
      #
      # /**
      # * @brief Unlink (delete) a file.
      # *
      # * @param sftp          The sftp session handle.
      # *
      # * @param file          The file to unlink/delete.
      # *
      # * @return              0 on success, < 0 on error with ssh and sftp error set.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API int sftp_unlink(sftp_session sftp, const char *file);
      #
      # /**
      # * @brief Remove a directoy.
      # *
      # * @param sftp          The sftp session handle.
      # *
      # * @param directory     The directory to remove.
      # *
      # * @return              0 on success, < 0 on error with ssh and sftp error set.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API int sftp_rmdir(sftp_session sftp, const char *directory);
      #
      # /**
      # * @brief Create a directory.
      # *
      # * @param sftp          The sftp session handle.
      # *
      # * @param directory     The directory to create.
      # *
      # * @param mode          Specifies the permissions to use. It is modified by the
      # *                      process's umask in the usual way:
      # *                      The permissions of the created file are (mode & ~umask)
      # *
      # * @return              0 on success, < 0 on error with ssh and sftp error set.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API int sftp_mkdir(sftp_session sftp, const char *directory, mode_t mode);
      #
      # /**
      # * @brief Rename or move a file or directory.
      # *
      # * @param sftp          The sftp session handle.
      # *
      # * @param original      The original url (source url) of file or directory to
      # *                      be moved.
      # *
      # * @param newname       The new url (destination url) of the file or directory
      # *                      after the move.
      # *
      # * @return              0 on success, < 0 on error with ssh and sftp error set.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API int sftp_rename(sftp_session sftp, const char *original, const  char *newname);
      #
      # /**
      # * @brief Set file attributes on a file, directory or symbolic link.
      # *
      # * @param sftp          The sftp session handle.
      # *
      # * @param file          The file which attributes should be changed.
      # *
      # * @param attr          The file attributes structure with the attributes set
      # *                      which should be changed.
      # *
      # * @return              0 on success, < 0 on error with ssh and sftp error set.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API int sftp_setstat(sftp_session sftp, const char *file, sftp_attributes attr);
      #
      # /**
      # * @brief Change the file owner and group
      # *
      # * @param sftp          The sftp session handle.
      # *
      # * @param file          The file which owner and group should be changed.
      # *
      # * @param owner         The new owner which should be set.
      # *
      # * @param group         The new group which should be set.
      # *
      # * @return              0 on success, < 0 on error with ssh and sftp error set.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API int sftp_chown(sftp_session sftp, const char *file, uid_t owner, gid_t group);
      #
      # /**
      # * @brief Change permissions of a file
      # *
      # * @param sftp          The sftp session handle.
      # *
      # * @param file          The file which owner and group should be changed.
      # *
      # * @param mode          Specifies the permissions to use. It is modified by the
      # *                      process's umask in the usual way:
      # *                      The permissions of the created file are (mode & ~umask)
      # *
      # * @return              0 on success, < 0 on error with ssh and sftp error set.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API int sftp_chmod(sftp_session sftp, const char *file, mode_t mode);
      #
      # /**
      # * @brief Change the last modification and access time of a file.
      # *
      # * @param sftp          The sftp session handle.
      # *
      # * @param file          The file which owner and group should be changed.
      # *
      # * @param times         A timeval structure which contains the desired access
      # *                      and modification time.
      # *
      # * @return              0 on success, < 0 on error with ssh and sftp error set.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API int sftp_utimes(sftp_session sftp, const char *file, const struct timeval *times);
      #
      # /**
      # * @brief Create a symbolic link.
      # *
      # * @param  sftp         The sftp session handle.
      # *
      # * @param  target       Specifies the target of the symlink.
      # *
      # * @param  dest         Specifies the path name of the symlink to be created.
      # *
      # * @return              0 on success, < 0 on error with ssh and sftp error set.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API int sftp_symlink(sftp_session sftp, const char *target, const char *dest);
      #
      # /**
      # * @brief Read the value of a symbolic link.
      # *
      # * @param  sftp         The sftp session handle.
      # *
      # * @param  path         Specifies the path name of the symlink to be read.
      # *
      # * @return              The target of the link, NULL on error.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API char *sftp_readlink(sftp_session sftp, const char *path);
      #
      # /**
      # * @brief Get information about a mounted file system.
      # *
      # * @param  sftp         The sftp session handle.
      # *
      # * @param  path         The pathname of any file within the mounted file system.
      # *
      # * @return A statvfs structure or NULL on error.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API sftp_statvfs_t sftp_statvfs(sftp_session sftp, const char *path);
      #
      # /**
      # * @brief Get information about a mounted file system.
      # *
      # * @param  file         An opened file.
      # *
      # * @return A statvfs structure or NULL on error.
      # *
      # * @see sftp_get_error()
      # */
      # LIBSSH_API sftp_statvfs_t sftp_fstatvfs(sftp_file file);
      #
      # /**
      # * @brief Free the memory of an allocated statvfs.
      # *
      # * @param  statvfs_o      The statvfs to free.
      # */
      # LIBSSH_API void sftp_statvfs_free(sftp_statvfs_t statvfs_o);
      #
      # /**
      # * @brief Canonicalize a sftp path.
      # *
      # * @param sftp          The sftp session handle.
      # *
      # * @param path          The path to be canonicalized.
      # *
      # * @return              The canonicalize path, NULL on error.
      # */
      # LIBSSH_API char *sftp_canonicalize_path(sftp_session sftp, const char *path);
      #
      # /**
      # * @brief Get the version of the SFTP protocol supported by the server
      # *
      # * @param sftp          The sftp session handle.
      # *
      # * @return              The server version.
      # */
      # LIBSSH_API int sftp_server_version(sftp_session sftp);
      #
      # #ifdef WITH_SERVER
      # /**
      # * @brief Create a new sftp server session.
      # *
      # * @param session       The ssh session to use.
      # *
      # * @param chan          The ssh channel to use.
      # *
      # * @return              A new sftp server session.
      # */
      # LIBSSH_API sftp_session sftp_server_new(ssh_session session, ssh_channel chan);
      attach_function :sftp_server_new, [Session, Channel], SFTPSession

      #
      # /**
      # * @brief Intialize the sftp server.
      # *
      # * @param sftp         The sftp session to init.
      # *
      # * @return             0 on success, < 0 on error.
      # */
      # LIBSSH_API int sftp_server_init(sftp_session sftp);
      attach_function :sftp_server_init, [SFTPSession], :int

      # #endif  /* WITH_SERVER */
      #
      # /* this is not a public interface */
      # #define SFTP_HANDLES 256
      # sftp_packet sftp_packet_read(sftp_session sftp);
      # int sftp_packet_write(sftp_session sftp,uint8_t type, ssh_buffer payload);
      # void sftp_packet_free(sftp_packet packet);
      # int buffer_add_attributes(ssh_buffer buffer, sftp_attributes attr);
      # sftp_attributes sftp_parse_attr(sftp_session session, ssh_buffer buf,int expectname);
      # /* sftpserver.c */
      #
      # LIBSSH_API sftp_client_message sftp_get_client_message(sftp_session sftp);
      attach_function :sftp_get_client_message, [SFTPSession], SFTPClientMessage

      # LIBSSH_API void sftp_client_message_free(sftp_client_message msg);
      attach_function :sftp_client_message_free, [SFTPClientMessage], :void

      # LIBSSH_API uint8_t sftp_client_message_get_type(sftp_client_message msg);
      attach_function :sftp_client_message_get_type, [SFTPClientMessage], :int

      # LIBSSH_API const char *sftp_client_message_get_filename(sftp_client_message msg);
      attach_function :sftp_client_message_get_filename, [SFTPClientMessage], :string

      # LIBSSH_API void sftp_client_message_set_filename(sftp_client_message msg, const char *newname);

      # LIBSSH_API const char *sftp_client_message_get_data(sftp_client_message msg);
      attach_function :sftp_client_message_get_data, [SFTPClientMessage], :pointer

      # LIBSSH_API uint32_t sftp_client_message_get_flags(sftp_client_message msg);

      # LIBSSH_API int sftp_send_client_message(sftp_session sftp, sftp_client_message msg);

      # int sftp_reply_name(sftp_client_message msg, const char *name, sftp_attributes attr);

      # int sftp_reply_handle(sftp_client_message msg, ssh_string handle);
      attach_function :sftp_reply_handle, [SFTPClientMessage, String], :int

      # ssh_string sftp_handle_alloc(sftp_session sftp, void *info);
      attach_function :sftp_handle_alloc, [SFTPSession, :pointer], String

      # int sftp_reply_attr(sftp_client_message msg, sftp_attributes attr);
      attach_function :sftp_reply_attr, [SFTPClientMessage, SFTPAttributes], :int

      # void *sftp_handle(sftp_session sftp, ssh_string handle);
      attach_function :sftp_handle, [SFTPSession, String], :pointer

      # int sftp_reply_status(sftp_client_message msg, uint32_t status, const char *message);
      attach_function :sftp_reply_status, [SFTPClientMessage, :uint32, :string], :int

      # int sftp_reply_names_add(sftp_client_message msg, const char *file, const char *longname, sftp_attributes attr);
      attach_function :sftp_reply_names_add, [SFTPClientMessage, :string, :string, SFTPAttributes], :int

      # int sftp_reply_names(sftp_client_message msg);
      attach_function :sftp_reply_names, [SFTPClientMessage], :int

      # int sftp_reply_data(sftp_client_message msg, const void *data, int len);
      attach_function :sftp_reply_data, [SFTPClientMessage, :pointer, :int], :int

      # void sftp_handle_remove(sftp_session sftp, void *handle);
      #
      # /* SFTP commands and constants */
      module SFTPCommands
        SSH_FXP_INIT = 1
        SSH_FXP_VERSION = 2
        SSH_FXP_OPEN = 3
        SSH_FXP_CLOSE = 4
        SSH_FXP_READ = 5
        SSH_FXP_WRITE = 6
        SSH_FXP_LSTAT = 7
        SSH_FXP_FSTAT = 8
        SSH_FXP_SETSTAT = 9
        SSH_FXP_FSETSTAT = 10
        SSH_FXP_OPENDIR = 11
        SSH_FXP_READDIR = 12
        SSH_FXP_REMOVE = 13
        SSH_FXP_MKDIR = 14
        SSH_FXP_RMDIR = 15
        SSH_FXP_REALPATH = 16
        SSH_FXP_STAT = 17
        SSH_FXP_RENAME = 18
        SSH_FXP_READLINK = 19
        SSH_FXP_SYMLINK = 20

        SSH_FXP_STATUS = 101
        SSH_FXP_HANDLE = 102
        SSH_FXP_DATA = 103
        SSH_FXP_NAME = 104
        SSH_FXP_ATTRS = 105

        SSH_FXP_EXTENDED = 200
        SSH_FXP_EXTENDED_REPLY = 201
      end
      #
      # /* attributes */
      # /* sftp draft is completely braindead : version 3 and 4 have different flags for same constants */
      # /* and even worst, version 4 has same flag for 2 different constants */
      # /* follow up : i won't develop any sftp4 compliant library before having a clarification */

      module Attributes
        SSH_FILEXFER_ATTR_SIZE = 0x00000001
        SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004
        SSH_FILEXFER_ATTR_ACCESSTIME = 0x00000008
        SSH_FILEXFER_ATTR_ACMODTIME =  0x00000008
        SSH_FILEXFER_ATTR_CREATETIME = 0x00000010
        SSH_FILEXFER_ATTR_MODIFYTIME = 0x00000020
        SSH_FILEXFER_ATTR_ACL = 0x00000040
        SSH_FILEXFER_ATTR_OWNERGROUP = 0x00000080
        SSH_FILEXFER_ATTR_SUBSECOND_TIMES = 0x00000100
        SSH_FILEXFER_ATTR_EXTENDED = 0x80000000
        SSH_FILEXFER_ATTR_UIDGID = 0x00000002
      end
      #
      # /* types */
      # #define SSH_FILEXFER_TYPE_REGULAR 1
      # #define SSH_FILEXFER_TYPE_DIRECTORY 2
      # #define SSH_FILEXFER_TYPE_SYMLINK 3
      # #define SSH_FILEXFER_TYPE_SPECIAL 4
      # #define SSH_FILEXFER_TYPE_UNKNOWN 5

      # /**
      # * @name Server responses
      # *
      # * @brief Responses returned by the sftp server.
      # * @{
      # */
      module SFTPStatus
        # /** No error */
        SSH_FX_OK = 0
        # /** End-of-file encountered */
        SSH_FX_EOF = 1
        # /** File doesn't exist */
        SSH_FX_NO_SUCH_FILE = 2
        # /** Permission denied */
        SSH_FX_PERMISSION_DENIED = 3
        # /** Generic failure */
        SSH_FX_FAILURE = 4
        # /** Garbage received from server */
        SSH_FX_BAD_MESSAGE = 5
        # /** No connection has been set up */
        SSH_FX_NO_CONNECTION = 6
        # /** There was a connection, but we lost it */
        SSH_FX_CONNECTION_LOST = 7
        # /** Operation not supported by the server */
        SSH_FX_OP_UNSUPPORTED = 8
        # /** Invalid file handle */
        SSH_FX_INVALID_HANDLE = 9
        # /** No such file or directory path exists */
        SSH_FX_NO_SUCH_PATH = 10
        # /** An attempt to create an already existing file or directory has been made */
        SSH_FX_FILE_ALREADY_EXISTS = 11
        # /** We are trying to write on a write-protected filesystem */
        SSH_FX_WRITE_PROTECT = 12
        # /** No media in remote drive */
        SSH_FX_NO_MEDIA = 13
      end
      #
      # /** @} */
      #
      # /* file flags */
      module Flags
        SSH_FXF_READ = 0x01
        SSH_FXF_WRITE = 0x02
        SSH_FXF_APPEND = 0x04
        SSH_FXF_CREAT = 0x08
        SSH_FXF_TRUNC = 0x10
        SSH_FXF_EXCL = 0x20
        SSH_FXF_TEXT = 0x40
      end
      #
      # /* rename flags */
      # #define SSH_FXF_RENAME_OVERWRITE  0x00000001
      # #define SSH_FXF_RENAME_ATOMIC     0x00000002
      # #define SSH_FXF_RENAME_NATIVE     0x00000004
      #
      # #define SFTP_OPEN SSH_FXP_OPEN
      # #define SFTP_CLOSE SSH_FXP_CLOSE
      # #define SFTP_READ SSH_FXP_READ
      # #define SFTP_WRITE SSH_FXP_WRITE
      # #define SFTP_LSTAT SSH_FXP_LSTAT
      # #define SFTP_FSTAT SSH_FXP_FSTAT
      # #define SFTP_SETSTAT SSH_FXP_SETSTAT
      # #define SFTP_FSETSTAT SSH_FXP_FSETSTAT
      # #define SFTP_OPENDIR SSH_FXP_OPENDIR
      # #define SFTP_READDIR SSH_FXP_READDIR
      # #define SFTP_REMOVE SSH_FXP_REMOVE
      # #define SFTP_MKDIR SSH_FXP_MKDIR
      # #define SFTP_RMDIR SSH_FXP_RMDIR
      # #define SFTP_REALPATH SSH_FXP_REALPATH
      # #define SFTP_STAT SSH_FXP_STAT
      # #define SFTP_RENAME SSH_FXP_RENAME
      # #define SFTP_READLINK SSH_FXP_READLINK
      # #define SFTP_SYMLINK SSH_FXP_SYMLINK
      #
      # /* openssh flags */
      # #define SSH_FXE_STATVFS_ST_RDONLY 0x1 /* read-only */
      # #define SSH_FXE_STATVFS_ST_NOSUID 0x2 /* no setuid */

    end
  end
end
