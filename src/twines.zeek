# Core logs (usually loaded by default)
@load base/protocols/dhcp
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/snmp

@load policy/protocols/conn/mac-logging
@load icsnpp/bacnet
@load icsnpp-modbus

redef Log::default_rotation_interval = 30mins;
redef Log::default_logdir = "/opt/zeek/logs";
