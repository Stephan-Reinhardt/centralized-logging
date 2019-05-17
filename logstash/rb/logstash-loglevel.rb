require "logstash/filters/base"
require "logstash/namespace"

#
# Filter plugin to normalize log levels from various logging frameworks
#
# The output field (log_level by default) will contain a number between
# 100 and 999, inclusive, with higher numbers indicating higher
# importance or severity.
#
# This allows elasticsearch queries like log_level:>700 to display only
# the most important log messages, or to expire debug messages after a
# short time, across all logging sources.
#
# If multiple input log level fields are set on an event, the output
# field will be derived from one of the inputs. Consider placing this
# filter where that situation cannot occur, such as inside an if block.
#
# Example usage:
#
# filter {
#     if [type] == "jul" {
#         grok {
#             match => { message => "%{TIMESTAMP_ISO8601} \[%{WORD:jul_log_level}\] %{GREEDYDATA:message}" }
#         }
#     }
#     if [type] == "syslog" {
#         grok {
#             match => { message => "<%{NONNEGINT:syslog_pri}>%{TIMESTAMP_ISO8601:syslog_timestamp} etc." }
#         }
#         syslog_pri { }
#     }
#     loglevel {
#         syslog_severity_code_field => syslog_severity_code
#         jul_log_level_field => jul_log_level
#         log_level_field => log_level
#         remove_field => [ "syslog_severity_code" ]
#     }
# }
#

class LogStash::Filters::LogLevel < LogStash::Filters::Base

  config_name "loglevel"
  milestone 1

  # Name of the field containing the numeric syslog severity code
  config :syslog_severity_code_field, :validate => :string, :default => "syslog_severity_code"

  # Name of the field containing the textual java.util.logging log level
  config :jul_log_level_field, :validate => :string, :default => "jul_log_level"

  # Name of the field containing the textual Commons Logging log level
  config :jcl_log_level_field, :validate => :string, :default => "jcl_log_level"

  # Name of the field that is to contain the normalized log level
  config :log_level_field, :valudate => :string, :default => "log_level"

  public
  def register
  end

  # References:
  # http://tools.ietf.org/html/rfc5424#section-6.2.1
  # http://docs.oracle.com/javase/7/docs/api/java/util/logging/Level.html
  # http://commons.apache.org/proper/commons-logging/guide.html#Message_PrioritiesLevels
  #
  #   Level   JUL         syslog      JCL
  #
  #    900    SEVERE      0-Emergency FATAL
  #    850                1-Alert     ERROR
  #    800                2-Critical
  #    750                3-Error
  #    700    WARNING     4-Warning   WARN
  #    600                5-Notice
  #    500    INFO        6-Info      INFO
  #    400    CONFIG
  #    300    FINE        7-Debug     DEBUG
  #    200    FINER
  #    100    FINEST                  TRACE

  @@syslog_level = {
    0 => 900,
    1 => 850,
    2 => 800,
    3 => 750,
    4 => 700,
    5 => 600,
    6 => 500,
    7 => 300,
  }

  @@jcl_level = {
    'FATAL' => 900,
    'ERROR' => 850,
    'WARN' => 700,
    'INFO' => 500,
    'DEBUG' => 300,
    'TRACE' => 100,
  }

  @@jul_level = {
    'SEVERE' => 900,
    'WARNING' => 700,
    'INFO' => 500,
    'CONFIG' => 400,
    'FINE' => 300,
    'FINER' => 200,
    'FINEST' => 100,
  }

  public
  def filter(event)
    return unless filter?(event)

    if !event[@syslog_severity_code_field].nil?
      event[@log_level_field] = @@syslog_level[event[@syslog_severity_code_field]]
    end

    if !event[@jul_log_level_field].nil?
      event[@log_level_field] = @@jul_level[event[@jul_log_level_field]]
    end

    if !event[@jcl_log_level_field].nil?
      event[@log_level_field] = @@jcl_level[event[@jcl_log_level_field]]
    end

    filter_matched(event)
  end

end


# Copyright 2014 William Ono
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
