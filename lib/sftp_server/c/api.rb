require 'ffi'

module SFTPServer
  module C
    module API
      extend FFI::Library
      ffi_lib_flags :now, :global
      ffi_lib 'c'

      attach_function :opendir, [:string], :pointer
    end
  end
end
