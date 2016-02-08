# check_cisco_ip_sla
Monitoring plugin for checking the status of IP SLAs on Cisco devices

## Overview
This plugin can check the status of one or more IP SLA entries on a Cisco IOS device. IP SLAs can be used to monitor
IP service levels for various IP applications and services. See the Cisco website for more details on SLA entries and their use.
One simple usage example is to monitor a multi-connection failover routing setup to monitor SLAs which ping the other
end of each line. SLA's can be set up to monitor a line/route and when this line goes down, the corresponding SLA will go down which this plugin can monitor.
This is just one example, however SLAs can be configured for various other tasks. For more info on IP SLA's, see the manual
for your Cisco device on IP SLA's. An example is
[the manual for a Cisco 4500 series](http://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst4500/12-2/44sg/configuration/guide/Wrapper-44SG/swipsla.html)

## Installation
Requirements:
* Python (version 2.7+, easysnmp requirement)
* easysnmp (lightweight and fast snmp library for python, see https://github.com/fgimian/easysnmp)
    See http://easysnmp.readthedocs.org/en/latest/ for installation instructions

Place the check script anywhere you'd like (eg /usr/local/lib/nagios/plugins) and run it

## Usage
For a complete overview run the check with the parameter "--help".

```
$ ./check_cisco_ip_sla.py --help
usage: check_cisco_ip_sla.py [-h] [-H HOSTNAME] [-v {1,2}] [-c COMMUNITY]
                             [-m {list,check}] [-e ENTRIES] [--perf]
                             [--critical-pct CRITICAL_PCT]
                             [--warning-pct WARNING_PCT] [--critical CRITICAL]
                             [--warning WARNING] [--verbose {0,1,2}]

Monitoring check plugin to check Cisco SLA status for one or more entries

optional arguments:
  -h, --help            show this help message and exit
  -H HOSTNAME, --hostname HOSTNAME
                        Hostname or ip-address
  -v {1,2}, --version {1,2}
                        SNMP version (default '1')
  -c COMMUNITY, --community COMMUNITY
                        SNMP Community (default 'public')
  -m {list,check}, --mode {list,check}
                        Operation mode
  -e ENTRIES, --entries ENTRIES
                        SLA entry (or entries) to check, specify as 'all', a
                        single value or comma-separated list
  --perf                Return perfdata
  --critical-pct CRITICAL_PCT
                        Critical threshold in percentage of failed SLAs
                        (default '100')
  --warning-pct WARNING_PCT
                        Warning threshold in percentage of failed SLAs
                        (default '50')
  --critical CRITICAL   Critical threshold in amount of failed SLAs
  --warning WARNING     Warning threshold in amount of failed SLAs
  --verbose {0,1,2}     Verbose output

```

General use cases:
Get a list of all SLAs available on a device
```
./check_cisco_ip_sla.py --hostname 192.168.0.1 --community public --mode list
```
Example output:
```
SLAs available:
  10 (tag: New York)
  20 (tag: Tokio)
  30 (tag: Amsterdam)
  40 (tag: London)
```

Check a SLA
```
./check_cisco_ip_sla.py --hostname 192.168.0.1 --community public --mode check --entries 10
```
Example output:
```
OK - 1 OK
```

Check multiple SLAs, warning if one goes down, critical if two go down
```
./check_cisco_ip_sla.py --hostname 192.168.0.1 --community public --mode check --entries 10,20,30,40 \
    --warning-pct 25 --critical-pct 50
```
Example output:
```
OK - 4 OK
```

Check the available disk space of a device
```
./check_cisco_ip_sla.py -h nas01.example.com -c nas01.conf -t disk-usage \
    --disk-usage-warning 80 --disk-usage-critical 90
```

## Nagios configuration examples
Command definition examples:
```
define command {
    command_name                    check_cisco_sla
    command_line                    path/to/check_cisco_ip_sla.py --hostname $HOSTADDRESS$ -v 2 --community "$ARG1$" --mode check --entries "$ARG2$" --warning-pct "$ARG3$" --critical-pct "$ARG4$"
    ;command_example                !public!10,20!60!80
    ;$ARG1$                         SNMP Community
    ;$ARG2$                         SLA(s) as comma separated list
    ;$ARG3$                         Warning threshold (percentage SLAs failed)
    ;$ARG4$                         Critical threshold (percentage SLAs failed)
}
```

Service template examples:
```
define service {
    name                            cisco-sla-check
    service_description             Cisco SLA - Check entries
    use                             cisco-sla-check-generic-no-perf
    check_command                   check_cisco_sla_all!~!~!~!~
    ;$ARG1$                         SNMP Community
    ;$ARG2$                         SLA(s) as comma separated list
    ;$ARG3$                         Warning level (in percent SLAs failed)
    ;$ARG4$                         Critical level (in percent SLAs failed)
    register                        0
}
```

Service definition examples:
```
define service {
    host_name                       cisco01.example.com
    service_description             Cisco SLA - Check entries
    use                             cisco-sla-check
    check_command                   check_cisco_sla!$USER10$!10,20,30,40,50,60!60!80
}
```


