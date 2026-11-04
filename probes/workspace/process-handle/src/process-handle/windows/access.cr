{% if flag?(:win32) %}
  class ProcessHandle::Windows
    # Native rights that a Windows-specific consumer may request for a scoped
    # process HANDLE. The handle is re-opened by PID and checked against this
    # ProcessHandle's creation-time identity before it is yielded.
    @[Flags]
    enum Access : UInt32
      Terminate               =     0x0001
      SetQuota                =     0x0100
      QueryLimitedInformation =     0x1000
      Synchronize             = 0x00100000
    end
  end
{% end %}
