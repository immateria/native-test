{% if flag?(:win32) %}
  module ProcessSupervision::Windows
    class Job < ProcessSupervision::Group
    end
  end
{% end %}
