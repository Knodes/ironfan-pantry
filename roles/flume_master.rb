name        'flume_master'
description 'flume master'

run_list(*%w[
  flume	
  flume::jars
  flume::plugin-hbase_sink
  flume::master
  flume::config_files
  flume_integration::jruby
])
