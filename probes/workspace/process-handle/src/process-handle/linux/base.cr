{% if flag?(:linux) %}
  class ProcessHandle::Linux < ProcessHandle
  end
{% end %}
