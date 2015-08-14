#!/usr/bin/python

__author__ = "m.hoogveld@elevate.nl"

import argparse
from easysnmp import Session


class CiscoIpSlaChecker:
    STATUS_OK = 0
    STATUS_WARNING = 1
    STATUS_CRITICAL = 2
    STATUS_UNKNOWN = 3

    def __init__(self):
        self.status = self.STATUS_OK
        self.message = None
        self.perfdata = None
        self.session = None
        self.options = None
        self.rtt_dict = None

    def run(self):
        self.parse_options()
        self.create_snmp_session()
        self.read_rtt_entries()

        if "list" == self.options.mode:
            self.list_rtt()
        elif "check" == self.options.mode:
            self.check()
            self.print_output()

        return self.status

    def parse_options(self):
        parser = argparse.ArgumentParser(
            description="Monitoring check plugin to check Cisco SLA status for one or more entries"
        )
        parser.add_argument("-H", "--hostname",
                            help="Hostname or ip-address")
        parser.add_argument("-v", "--version",
                            default="1", choices=["1", "2"], help="SNMP version (default '1')")
        parser.add_argument("-c", "--community",
                            default="public", help="SNMP Community (default 'public')")
        parser.add_argument("-m", "--mode",
                            choices=["list", "check"], help="Operation mode")
        parser.add_argument("-e", "--entries",
                            default="all",
                            help="SLA entry (or entries) to check, specify as 'all', "
                                 "a single value or comma-separated list")
        parser.add_argument("--perf",
                            action="store_true", help="Return perfdata")
        parser.add_argument("--critical-pct",
                            default=100.0, type=float,
                            help="Critical threshold in percentage of failed SLAs (default '100')")
        parser.add_argument("--warning-pct",
                            default=50.0, type=float,
                            help="Warning threshold in percentage of failed SLAs (default '50')")
        parser.add_argument("--critical",
                            default=1, type=int, help="Critical threshold in amount of failed SLAs")
        parser.add_argument("--warning",
                            default=1, type=int, help="Warning threshold in amount of failed SLAs")
        parser.add_argument("--verbose",
                            help="Verbose output")
        self.options = parser.parse_args()
        if not self.are_options_valid():
            print("Run with --help for usage information")
            print("")
            exit(0)

    def are_options_valid(self):
        if not self.options.hostname:
            print("You must specify a hostname")
            return False
        if not self.options.mode:
            print("You must specify a operation mode")
            return False
        if self.options.mode == "check" and not self.options.entries:
            print("You must specify SLA-entries for check-mode (use list-mode to list existing entries)")
            return False
        return True

    def print_output(self):
        if self.status == self.STATUS_OK:
            output = 'OK'
        elif self.status == self.STATUS_WARNING:
            output = 'Warning'
        elif self.status == self.STATUS_CRITICAL:
            output = 'Critical'
        else:
            output = 'Unknown'

        if self.message:
            output += ' - {0}'.format(self.message)

        if self.perfdata:
            output += ' | {0}'.format(self.perfdata)

        print(output)

    def create_snmp_session(self):
        self.session = Session(
            hostname=self.options.hostname,
            community=self.options.community,
            version=int(self.options.version)
        )

    def read_rtt_entries(self):
        self.rtt_dict = dict()
        rtt_ctrl_admin_entries = self.session.walk(".1.3.6.1.4.1.9.9.42.1.2.1.1")
        for item in rtt_ctrl_admin_entries:
            oid_parts = str(item.oid).split(".")
            rtt_entry = oid_parts[-1]
            rtt_info_type = oid_parts[-2]

            if rtt_entry not in self.rtt_dict:
                self.rtt_dict[rtt_entry] = dict()

            if "2" == rtt_info_type:
                # rttMonCtrlAdminOwner (2)
                self.rtt_dict[rtt_entry]['owner'] = str(item.value)
            elif "3" == rtt_info_type:
                # rttMonCtrlAdminTag (3)
                self.rtt_dict[rtt_entry]['tag'] = str(item.value)
            elif "4" == rtt_info_type:
                # rttMonCtrlAdminRttType (3)
                self.rtt_dict[rtt_entry]['type'] = str(item.value)

        # rtt_rtt_types = self.session.walk(".1.3.6.1.4.1.9.9.42.1.2.1.1.3")
        # for item in rtt_rtt_types:
        #     oid_parts = str(item.oid).split(".")
        #     rtt_entry = oid_parts[-1]
        #     rtt_type = item.value
        #     self.rtt_dict[rtt_entry] = {"entry": rtt_entry, "type": rtt_type}

        rtt_ctrl_oper_entries = self.session.walk(".1.3.6.1.4.1.9.9.42.1.2.9.1")
        for item in rtt_ctrl_oper_entries:
            oid_parts = str(item.oid).split(".")
            rtt_entry = oid_parts[-1]
            rtt_info_type = oid_parts[-2]

            if "5" == rtt_info_type:
                # rttMonCtrlOperConnectionLostOccurred (5)
                if item.value == "1":
                    self.rtt_dict[rtt_entry]["conn_lost_occured"] = True
                else:
                    self.rtt_dict[rtt_entry]["conn_lost_occured"] = False

            elif "6" == rtt_info_type:
                # rttMonCtrlOperTimeoutOccurred (6)
                if item.value == "1":
                    self.rtt_dict[rtt_entry]["timeout_occured"] = True
                else:
                    self.rtt_dict[rtt_entry]["timeout_occured"] = False

            elif "7" == rtt_info_type:
                # rttMonCtrlOperOverThresholdOccurred (7)
                if item.value == "1":
                    self.rtt_dict[rtt_entry]["over_thres_occured"] = True
                else:
                    self.rtt_dict[rtt_entry]["over_thres_occured"] = False

            elif "10" == rtt_info_type:
                # rttMonCtrlOperState (10)
                # http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?local=en&translate=Translate&objectInput=1.3.6.1.4.1.9.9.42.1.2.9.1.10
                if item.value == "6":
                    self.rtt_dict[rtt_entry]["in_active_state"] = True
                else:
                    self.rtt_dict[rtt_entry]["in_active_state"] = False

    def list_rtt(self):
        print("Rtt's available:")
        for rtt_entry in self.rtt_dict:
            rtt_id = "{0}".format(rtt_entry)
            if self.rtt_dict[rtt_entry]["tag"]:
                rtt_id += " (tag: {0})".format(self.rtt_dict[rtt_entry]["tag"])
            print("  {0}".format(rtt_id))
        for rtt_entry in self.rtt_dict:
            rtt_id = "{0}".format(rtt_entry)
            if self.rtt_dict[rtt_entry]["tag"]:
                rtt_id += " (tag: {0})".format(self.rtt_dict[rtt_entry]["tag"])
            if not self.rtt_dict[rtt_entry]["in_active_state"]:
                print("  {0} (inactive)".format(rtt_entry))

    def check(self):
        messages = []
        if self.options.entries == "all":
            requested_entries = self.rtt_dict.keys()
        else:
            requested_entries = self.options.entries.replace(" ", "").split(",")

        ok_count = 0
        failed_count = 0

        for requested_entry in requested_entries:
            if requested_entry not in self.rtt_dict:
                self.message = "SLA {0} does not exist".format(requested_entry)
                self.status = self.STATUS_UNKNOWN
                return
            else:
                rtt_id = "{0}".format(requested_entry)
                if self.rtt_dict[requested_entry]["tag"]:
                    rtt_id += " (tag: {0})".format(self.rtt_dict[requested_entry]["tag"])

                if self.rtt_dict[requested_entry]["in_active_state"]:
                    if self.rtt_dict[requested_entry]["timeout_occured"]:
                        failed_count += 1
                        messages.append("Timeout for SLA {0}".format(rtt_id))
                    else:
                        ok_count += 1
                else:
                    messages.append("SLA {0} not active".format(rtt_id))
                    self.status = self.STATUS_WARNING

        if failed_count + ok_count == 0:
            messages.append("No SLAs checked")
            self.status = self.STATUS_UNKNOWN
            return

        failed_pct = round(float(failed_count) / (failed_count + ok_count) * 100, 1)

        if self.options.critical_pct or self.options.warning_pct:
            if self.options.critical_pct and failed_pct >= self.options.critical_pct:
                self.status = self.STATUS_CRITICAL
            elif self.options.warning_pct and failed_pct >= self.options.warning_pct:
                self.status = self.STATUS_WARNING
        else:
            if failed_count >= self.options.critical:
                self.status = self.STATUS_CRITICAL
            elif failed_count >= self.options.warning:
                self.status = self.STATUS_WARNING

        if failed_count:
            messages.insert(0, "{0} Failed ({1}%)".format(failed_count, failed_pct))
        if ok_count:
            messages.insert(0, "{0} OK".format(ok_count))

        if messages:
            self.message = ', '.join(messages)

        if self.options.perf:
            self.perfdata = "'Failed%'={0}%".format(failed_pct)
            if self.options.critical_pct and self.options.warning_pct:
                self.perfdata += ";{0};{1};0;100".format(self.options.warning_pct, self.options.critical_pct)

checker = CiscoIpSlaChecker()
result = checker.run()
exit(result)


# rtt_types = {
#     "echo": 1,
#     "pathEcho": 2,
#     "fileIO": 3,
#     "script": 4,
#     "udpEcho": 5,
#     "tcpConnect": 6,
#     "http": 7,
#     "dns": 8,
#     "jitter": 9,
#     "dlsw": 10,
#     "dhcp": 11,
#     "ftp": 12,
#     "voip": 13,
#     "rtp": 14,
#     "lspGroup": 15,
#     "icmpjitter": 16,
#     "lspPing": 17,
#     "lspTrace": 18,
#     "ethernetPing": 19,
#     "ethernetJitter": 20,
#     "lspPingPseudowire": 21
# }
