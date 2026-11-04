{% if flag?(:win32) %}
  class ProcessHandle::Windows < ProcessHandle
  end
{% end %}
