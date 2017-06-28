# check_cisco_ip_sla
Monitoring plugin for checking the status of IP SLAs on Cisco devices


## Overview
This plugin can check the status of one or more IP SLA entries on a Cisco IOS device. IP SLAs can be used to monitor
IP service levels for various IP applications and services. See the Cisco website for more details on SLA entries
and their use. One simple usage example is to monitor a multi-connection failover routing setup to monitor SLAs which
ping the other end of each line. SLA's can be set up to monitor a line/route and when this line goes down, the
corresponding SLA will go down which this plugin can monitor. This is just one example, however SLAs can be configured
for various other tasks. For more info on IP SLA's, see the manual for your Cisco device on IP SLA's. An example is
[the manual for a Cisco 4500 series](http://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst4500/12-2/44sg/configuration/guide/Wrapper-44SG/swipsla.html)
At the moment, rtt-types echo, pathEcho and jitter are supported and tested (aka icmp-echo, path-echo and udp-jitter). 
Other types need to be implemented or at least tested. Suggestions and/or help is always welcome.


## Changelist
* v1.0.0 (2016-02-08)
  * Initial release
* v1.0.1 (2017-02-22)
  * Fixed bug which appeared when OID's were returned in text form when 
the RTT-MIB was installed on the system.
* v1.0.2 (2017-03-12)
  * Added round trip time perf data. 
  * Added warning when checking unsupported IP SLA types.
  * IMPORTANT backward incompatible change: Repurposed the '--version' parameter from setting the snmp-version to displaying the scripts version. 
    To specify the snmp version, use '-v' or '--snmp-version'
* v1.1.0 (2017-06-28)
  * Added support for rtt-type jitter with MOS and ICPIF thresholds and extensive perf data
  * Removed sla tag suffix in perf data when checking only one entry


## Installation
Requirements:
* Python version 2 or 3 (tested on 2.7+ or 3.4+)
* easysnmp (lightweight and fast snmp library for python, see https://github.com/fgimian/easysnmp)
    See http://easysnmp.readthedocs.org/en/latest/ for installation instructions

Place the check script anywhere you'd like (eg /usr/local/lib/nagios/plugins) and run it


## Usage
You can use this plugin to check a single SLA or multiple SLA's of the same type.

Checking multiple SLA's is mostly useful to check general internet connectivity. For example, 
you could set up an echo SLA to 4 IP's with expected near 100% uptime. Then you could use the 
either the --warning or the --warning-pct parameter to let the script issue a warning if say 2 go down 
and in the same way use a critical parameter to issue a critical when more than 2 go down.

Use "--mode list" to do a quick check of available SLA's on your Cisco device.
Use "--mode check" to do the actual checking.

Performance data is output when using the --perf parameter.
See the Output chapter for a description on performance values.

For a complete overview of command-line options, run the check with the parameter --help.

```
$ ./check_cisco_ip_sla.py  --help
usage: check_cisco_ip_sla.py [-h] [--version] [-H HOSTNAME] [-v {1,2,3}]
                             [-c COMMUNITY] [-u SECURITY_NAME]
                             [-l {noAuthNoPriv,authNoPriv,authPriv}]
                             [-p PASSWORD] [-a {MD5,SHA}] [-A AUTH_PASSWORD]
                             [-x {DES,AES}] [-X PRIV_PASSWORD]
                             [-m {list,check}] [-e ENTRIES] [--perf]
                             [--critical-pct CRITICAL_PCT]
                             [--warning-pct WARNING_PCT] [--critical CRITICAL]
                             [--warning WARNING] [--critical-mos CRITICAL_MOS]
                             [--warning-mos WARNING_MOS]
                             [--critical-icpif CRITICAL_ICPIF]
                             [--warning-icpif WARNING_ICPIF]
                             [--verbose {0,1,2}]

Monitoring check plugin to check Cisco SLA status for one or more entries. If
a checked SLA entry is not in active state, the status is raised to WARNING.
The script returns the worst status found for each checked SLA entry where
UNKNOWN is worse than CRITICAL and CRITICAL is worse than WARNING.

optional arguments:
  -h, --help            show this help message and exit
  --version             The version of this script
  -H HOSTNAME, --hostname HOSTNAME
                        Hostname or ip-address
  -v {1,2,3}, --snmp-version {1,2,3}
                        SNMP version (default '2')
  -c COMMUNITY, --community COMMUNITY
                        SNMP v1/v2 Community string (default 'public')
  -u SECURITY_NAME, --security-name SECURITY_NAME
                        SNMP v3 security name (username)
  -l {noAuthNoPriv,authNoPriv,authPriv}, --security-level {noAuthNoPriv,authNoPriv,authPriv}
                        SNMP v3 security level (default 'authPriv')
  -p PASSWORD, --password PASSWORD
                        SNMP v3 password (used for both authentication and
                        privacy)
  -a {MD5,SHA}, --auth-protocol {MD5,SHA}
                        SNMP v3 authentication protocol (default 'SHA')
  -A AUTH_PASSWORD, --auth-password AUTH_PASSWORD
                        SNMP v3 authentication password, overrides --password
                        if set
  -x {DES,AES}, --priv-protocol {DES,AES}
                        SNMP v3 privacy protocol (default 'AES')
  -X PRIV_PASSWORD, --priv-password PRIV_PASSWORD
                        SNMP v3 privacy password, overrides --password if set
  -m {list,check}, --mode {list,check}
                        Operation mode
  -e ENTRIES, --entries ENTRIES
                        SLA entry (or entries) to check, specify a single
                        value, a comma-separated list or 'all' to check all
                        entries available. All entries must be of the same
                        type. (default 'all')
  --perf                Return performance data (failed percentage, round-trip
                        times)
  --critical-pct CRITICAL_PCT
                        Critical threshold in percentage of failed SLAs
                        (default '100')
  --warning-pct WARNING_PCT
                        Warning threshold in percentage of failed SLAs
                        (default '50')
  --critical CRITICAL   Critical threshold in amount of failed SLAs
  --warning WARNING     Warning threshold in amount of failed SLAs
  --critical-mos CRITICAL_MOS
                        Critical threshold for the MOS value of jitter SLAs
                        (1.00 .. 5.00)
  --warning-mos WARNING_MOS
                        Warning threshold for the MOS value of jitter SLAs
                        (1.00 .. 5.00)
  --critical-icpif CRITICAL_ICPIF
                        Critical threshold for the ICPIF value of jitter SLAs
  --warning-icpif WARNING_ICPIF
                        Warning threshold for the ICPIF value of jitter SLAs
  --verbose {0,1,2}     Verbose output

```


## Output

This monitoring plugin follows the Nagios plugin guidelines for output.
In check-mode the return value indicates the status (0 = OK, 1 = WARNING, 2 = CRITICAL and 3 = UNKNOWN)
The status will also be printed as output, as well as some textual description about the status
Examples can be seen below.


**Performance data**

Use the --perf parameter to make the script output performance data.

For all SLA types the Round Trip Time of the latest operation is returned:
* 'rtt': The RTT of the latest operation

or when checking multiple SLA entries at once:
* 'rtt <entry-tag>': The RTT of the latest operation for each entry (e.g. 'rtt 10')

For jitter-SLA's the following additional values are returned:
* 'RTT avg': The average, min and max of the successfully measured RTT's (example 'RTT avg'=12.2ms;9;24)
* 'RTT variance': The variance of measured RTT's (example: 'RTT variance'=571.4)
* 'RTT std dev': The standard deviation of measured RTT's (example: 'RTT std dev'=23.9)
* 'Avg jitter': The average jitter (example: 'Avg jitter'=2)
* 'Avg jitter SD': The average jitter from Source to Destination (example: 'Avg jitter  SD'=3)
* 'Avg jitter DS': The average jitter from Destination to Source (example: 'Avg jitter  DS'=1)
* 'Avg latency SD': The average latency from Source to Destination (example: 'Avg latency SD'=7)
* 'Avg latency DS': The average latency from Destination to Source (example: 'Avg latency DS'=10)
* 'MOS': The Mean Opinion Score value (example: 'MOS'=4.23)
* 'ICPIF': The Impairment Calculated Planning Impairment Factor value (example: 'ICPIF'=11)
* 'Packet loss SD': Packet loss from Source to Destination (example: 'Packet loss SD'=0)
* 'Packet loss DS': Packet loss from Destination to Source (example: 'Packet loss DS'=0)
* 'Packet out of seq': The number of packets arrived out of sequence (example: 'Packet out of seq'=0)
* 'Packet MIA': The number of packets that are lost for which the direction cannot be determined (example: 'Packet MIA'=0)
* 'Packet late arrival': The number of packets that arrived after the timeout (example: 'Packet late arrival'=0)


## Examples

General use cases:

Get a list of all SLAs available on a device
```
$ ./check_cisco_ip_sla.py --hostname 192.168.0.1 --community public --mode list

SLAs available:
   ID  Type    Tag
  ----  ------  ----------------------------
    10  echo    New York
    20  echo    Tokio
    30  echo    Amsterdam
    40  echo    London
  2600  jitter  Jitter from Site-X to Site-Y
```

Check an SLA
```
$ ./check_cisco_ip_sla.py --hostname 192.168.0.1 --community public --mode check --entries 10

OK - 1 OK
```

Check multiple SLAs, warning if one goes down, critical if two go down
```
$ ./check_cisco_ip_sla.py --hostname 192.168.0.1 --community public --mode check --entries 10,20,30,40 \
        --warning-pct 25 --critical-pct 50

OK - 4 OK
```

Check via SNMPv3
```
$ ./check_cisco_ip_sla.py --hostname 192.168.0.1 -v 3 -m list \
        --security-name example_user --security-level authPriv --password example_passsword \
        --auth-protocol SHA --priv-protocol AES

SLAs available:
   ID  Type    Tag
  ---  ------  --------
   10  echo    New York
```

Check with performance data
```
$ ./check_cisco_ip_sla.py --hostname 192.168.0.1 -v 2 -c public --mode check --perf

OK - 4 OK | 'Failed%'=0.0%;50;100;0;100 'rtt 10'=1ms 'rtt 20'=4ms 'rtt 30'=1ms 'rtt 40'=12ms
```

Check jitter with performance data
```
$ ./check_cisco_ip_sla.py --hostname 192.168.0.1 -v 2 -c public --mode check --entries 2600 --perf

OK - 1 OK | 'RTT avg'=24.6;17;31 'RTT variance'=571.4 'RTT std dev'=23.9 'Avg jitter'=2 'Avg jitter SD'=3 'Avg jitter DS'=1 'Avg latency SD'=7 'Avg latency DS'=10 'MOS'=4.23 'ICPIF'=11 'Packet loss SD'=0 'Packet loss DS'=0 'Packet out of seq'=0 'Packet MIA'=0 'Packet late arrival'=0 'rtt'=17ms
```


## Nagios configuration examples
Command definition examples:
```
define command {
    command_name                    check_cisco_sla
    command_line                    path/to/check_cisco_ip_sla.py --hostname $HOSTADDRESS$ -v 3 --security-name "$ARG1$" --password "$ARG2$"  --mode check --entries "$ARG3$" --warning-pct "$ARG4$" --critical-pct "$ARG5$"
    ;command_example                !username!password!10,20!60!80
    ;$ARG1$                         SNMP-v3 Username
    ;$ARG2$                         SNMP-v3 auth and priv password
    ;$ARG3$                         SLA(s) as comma separated list
    ;$ARG4$                         Warning threshold (percentage SLAs failed)
    ;$ARG5$                         Critical threshold (percentage SLAs failed)
}

define command {
    command_name                    check_cisco_sla_jitter
    command_line                    path/to/check_cisco_ip_sla.py --hostname $HOSTADDRESS$ -v 3 --security-name "$ARG1$" --password "$ARG2$"  --mode check --entries "$ARG3$" --warning-mos "$ARG4$" --critical-mos "$ARG5$" --perf
    ;command_example                !username!password!10,20!3!2
    ;$ARG1$                         SNMP-v3 Username
    ;$ARG2$                         SNMP-v3 auth and priv password
    ;$ARG3$                         SLA(s) as comma separated list
    ;$ARG4$                         Warning threshold (MOS value)
    ;$ARG5$                         Critical threshold (MOS value)
}

define command {
    command_name                    check_cisco_sla_v2
    command_line                    path/to/check_cisco_ip_sla.py --hostname $HOSTADDRESS$ -v 2 --community "$ARG1$" --mode check --entries "$ARG2$" --warning-pct "$ARG3$" --critical-pct "$ARG4$"
    ;command_example                !public!10,20!60!80
    ;$ARG1$                         SNMP Community
    ;$ARG2$                         SLA(s) as comma separated list
    ;$ARG3$                         Warning threshold (percentage SLAs failed)
    ;$ARG4$                         Critical threshold (percentage SLAs failed)
}

define command {
    command_name                    check_cisco_sla_v2_all
    command_line                    path/to/check_cisco_ip_sla.py --hostname $HOSTADDRESS$ -v 2 --community "$ARG1$" --mode check --entries all --warning-pct "$ARG3$" --critical-pct "$ARG4$" --perf
    ;command_example                !public!60!80
    ;$ARG1$                         SNMP Community
    ;$ARG2$                         Warning threshold (percentage SLAs failed)
    ;$ARG3$                         Critical threshold (percentage SLAs failed)
}
```

Service template examples:
```
define service {
    name                            cisco-sla-check
    service_description             Cisco SLA - Check entries
    use                             generic-service
    process_perf_data               0
    check_command                   check_cisco_sla!~!~!~!~!~
    ;$ARG1$                         SNMP-v3 Username
    ;$ARG2$                         SNMP-v3 auth and priv password
    ;$ARG3$                         SLA(s) as comma separated list
    ;$ARG4$                         Warning threshold (percentage SLAs failed)
    ;$ARG5$                         Critical threshold (percentage SLAs failed)
    register                        0
}

define service {
    name                            cisco-sla-check-jitter
    service_description             Cisco SLA - Check jitter
    use                             generic-service
    check_command                   check_cisco_sla_jitter!~!~!~!~!~
    ;$ARG1$                         SNMP-v3 Username
    ;$ARG2$                         SNMP-v3 auth and priv password
    ;$ARG3$                         SLA(s) as comma separated list
    ;$ARG4$                         Warning threshold (MOS value)
    ;$ARG5$                         Critical threshold (MOS value)
    register                        0
}

define service {
    name                            cisco-sla-check-v2-all
    service_description             Cisco SLA - Check entries
    use                             generic-service
    check_command                   check_cisco_sla_v2_all!~!~!~
    ;$ARG1$                         SNMP Community
    ;$ARG3$                         Warning level (in percent SLAs failed)
    ;$ARG4$                         Critical level (in percent SLAs failed)
    register                        0
}
```

Service definition examples:
```
define service {
    host_name                       cisco03.example.com
    service_description             Cisco SLA - Check line to NY
    use                             cisco-sla-check
    check_command                   check_cisco_sla!$USER11$!$USER12$!10!60!80
}

define service {
    host_name                       cisco03.example.com
    service_description             Cisco SLA - Check jitter
    use                             cisco-sla-check-jitter
    check_command                   check_cisco_sla_jitter!$USER11$!$USER12$!2600!60!80
}

define service {
    host_name                       cisco02.example.com
    service_description             Cisco SLA - Check entries
    use                             cisco-sla-check-v2-all
    check_command                   check_cisco_sla_v2_all!$USER10$!60!80
}
```


