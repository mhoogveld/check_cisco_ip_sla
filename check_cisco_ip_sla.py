#!/usr/bin/python

"""
This plugin can check the status of one or more IP SLA entries on a Cisco IOS device.
IP SLAs can be used to monitor IP service levels for various IP applications and services. See the Cisco website
for more details on SLA entries and their use. One simple usage example is to monitor a multi-connection
failover routing setup to monitor SLAs which ping the other end of each line. SLA's can be set up to monitor
a line/route and when this line goes down, the corresponding SLA will go down which this plugin can monitor.
This is just one example, however SLAs can be configured for various other tasks.
For more info on IP SLA's, see the manual for your Cisco device on IP SLA's.
"""

import argparse
from easysnmp import Session
from easysnmp.exceptions import *

__author__ = "Maarten Hoogveld"
__version__ = "1.0.2"
__email__ = "m.hoogveld@elevate.nl"
__licence__ = "GPL-3.0"
__status__ = "Production"


class CiscoIpSlaChecker:
    STATUS_OK = 0
    STATUS_WARNING = 1
    STATUS_CRITICAL = 2
    STATUS_UNKNOWN = 3

    # Verbosity levels
    V_NONE = 0
    V_INFO = 1
    V_DEBUG = 2

    def __init__(self):
        self.status = None
        self.message = None
        self.perfdata = None
        self.session = None
        self.options = None
        self.rtt_dict = dict()

    def run(self):
        self.parse_options()
        try:
            self.create_snmp_session()
            self.read_rtt_entries()
        except EasySNMPError as e:
            self.add_status(self.STATUS_UNKNOWN)
            self.message = "SNMP error checking {}, {}".format(self.options.hostname, e)
        else:
            if "list" == self.options.mode:
                self.list_rtt()
            elif "check" == self.options.mode:
                self.check()

        self.print_output()

        return self.status

    def parse_options(self):
        parser = argparse.ArgumentParser(
            description="Monitoring check plugin to check Cisco SLA status for one or more entries. "
                        "If a checked SLA entry is not in active state, the status is raised to WARNING. "
                        "The script returns the worst status found for each checked SLA entry where "
                        "UNKNOWN is worse than CRITICAL and CRITICAL is worse than WARNING."
        )
        parser.add_argument("--version", action="version", version='%(prog)s {version}'.format(version=__version__),
                            help="The version of this script")
        parser.add_argument("-H", "--hostname",
                            help="Hostname or ip-address")
        parser.add_argument("-v", "--snmp-version",
                            default="2", choices=["1", "2", "3"], help="SNMP version (default '2')")
        parser.add_argument("-c", "--community",
                            default="public", help="SNMP v1/v2 Community string (default 'public')")
        parser.add_argument("-u", "--security-name",
                            help="SNMP v3 security name (username)")
        parser.add_argument("-l", "--security-level",
                            default="authPriv", choices=["noAuthNoPriv", "authNoPriv", "authPriv"],
                            help="SNMP v3 security level (default 'authPriv')")
        parser.add_argument("-p", "--password",
                            help="SNMP v3 password (used for both authentication and privacy)")
        parser.add_argument("-a", "--auth-protocol",
                            default="SHA", choices=["MD5", "SHA"],
                            help="SNMP v3 authentication protocol (default 'SHA')")
        parser.add_argument("-A", "--auth-password",
                            help="SNMP v3 authentication password, overrides --password if set")
        parser.add_argument("-x", "--priv-protocol",
                            default="AES", choices=["DES", "AES"],
                            help="SNMP v3 privacy protocol (default 'AES')")
        parser.add_argument("-X", "--priv-password",
                            help="SNMP v3 privacy password, overrides --password if set")
        parser.add_argument("-m", "--mode",
                            choices=["list", "check"], help="Operation mode")
        parser.add_argument("-e", "--entries",
                            default="all",
                            help="SLA entry (or entries) to check, specify as 'all', "
                                 "a single value or comma-separated list (default 'all')")
        parser.add_argument("--perf",
                            action="store_true", help="Return performance data (failed percentage, round-trip times)")
        parser.add_argument("--critical-pct",
                            default=None, type=float,
                            help="Critical threshold in percentage of failed SLAs (default '100')")
        parser.add_argument("--warning-pct",
                            default=None, type=float,
                            help="Warning threshold in percentage of failed SLAs (default '50')")
        parser.add_argument("--critical",
                            default=None, type=int, help="Critical threshold in amount of failed SLAs")
        parser.add_argument("--warning",
                            default=None, type=int, help="Warning threshold in amount of failed SLAs")
        parser.add_argument("--verbose",
                            default=0, type=int, choices=[0, 1, 2], help="Verbose output")
        self.options = parser.parse_args()

        # Set default warning and critical levels if they are not specified at all
        if self.options.critical is None and self.options.critical_pct is None:
            self.options.critical_pct = 100
        if self.options.warning is None and self.options.warning_pct is None:
            self.options.warning_pct = 50

        # Copy password to auth-password and priv-password if applicable
        if self.options.auth_password is None and self.options.password is not None:
            self.options.auth_password = self.options.password
        if self.options.priv_password is None and self.options.password is not None:
            self.options.priv_password = self.options.password

        if not self.are_options_valid():
            print("Run with --help for usage information")
            print("")
            exit(0)

        self.print_msg(self.V_DEBUG, "Using parameters:")
        self.print_msg(self.V_DEBUG, " Hostname:        {}".format(self.options.hostname))
        self.print_msg(self.V_DEBUG, " SNMP-version:    {}".format(self.options.snmp_version))
        self.print_msg(self.V_DEBUG, " Community:       {}".format(self.options.community))
        self.print_msg(self.V_DEBUG, " Security-name:   {}".format(self.options.security_name))
        self.print_msg(self.V_DEBUG, " Security-level:  {}".format(self.options.security_level))
        self.print_msg(self.V_DEBUG, " Password:        {}".format(self.options.password))
        self.print_msg(self.V_DEBUG, " Auth-protocol:   {}".format(self.options.auth_protocol))
        self.print_msg(self.V_DEBUG, " Auth-password:   {}".format(self.options.auth_password))
        self.print_msg(self.V_DEBUG, " Priv-protocol:   {}".format(self.options.priv_protocol))
        self.print_msg(self.V_DEBUG, " Priv-password:   {}".format(self.options.priv_password))
        self.print_msg(self.V_DEBUG, " Mode:            {}".format(self.options.mode))
        self.print_msg(self.V_DEBUG, " SLA entries:     {}".format(self.options.entries))
        self.print_msg(self.V_DEBUG, " Perf-data:       {}".format(self.options.perf))
        self.print_msg(self.V_DEBUG, " Critical-pct:    {}".format(self.options.critical_pct))
        self.print_msg(self.V_DEBUG, " Warning-pct:     {}".format(self.options.warning_pct))
        self.print_msg(self.V_DEBUG, " Critical:        {}".format(self.options.critical))
        self.print_msg(self.V_DEBUG, " Warning:         {}".format(self.options.warning))
        self.print_msg(self.V_DEBUG, " Verbosity:       {}".format(self.options.verbose))
        self.print_msg(self.V_DEBUG, "")

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

    def print_msg(self, minimum_verbosity_level, msg):
        """
        :param minimum_verbosity_level: Minimum verbosity level needed for the message to be printed
        :param msg: The message to print
        :return:
        """
        if self.options.verbose >= minimum_verbosity_level:
            print(msg)

    def print_output(self):
        """ Prints the final output (in Nagios plugin format if self.status is set)
        :return:
        """
        output = ""
        if self.status == self.STATUS_OK:
            output = "OK"
        elif self.status == self.STATUS_WARNING:
            output = "Warning"
        elif self.status == self.STATUS_CRITICAL:
            output = "Critical"
        elif self.status == self.STATUS_UNKNOWN:
            output = "Unknown"

        if self.message:
            if len(output):
                output += " - "
            output += self.message

        if self.perfdata:
            if len(output):
                output += " | "
            output += self.perfdata

        print(output)

    def create_snmp_session(self):
        self.session = Session(
            hostname=self.options.hostname,
            community=self.options.community,
            version=int(self.options.snmp_version),
            security_username=self.options.security_name,
            security_level=self.options.security_level,
            auth_protocol=self.options.auth_protocol,
            auth_password=self.options.auth_password,
            privacy_protocol=self.options.priv_protocol,
            privacy_password=self.options.priv_password,
            use_numeric=True,
        )

    def add_status(self, status):
        """ Set the status only if it is more severe than the present status
        The order of severity being OK, WARNING, CRITICAL, UNKNOWN
        :param status: Status to set, one of the self.STATUS_xxx constants
        :return: The current status
        """
        if self.status is None or status > self.status:
            self.status = status

    def read_rtt_entries(self):
        # Get SLA entry info
        self.rtt_dict = dict()
        rtt_ctrl_admin_entries = self.session.walk(".1.3.6.1.4.1.9.9.42.1.2.1.1")
        for item in rtt_ctrl_admin_entries:
            oid_parts = str(item.oid).split(".")
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if rtt_entry not in self.rtt_dict:
                self.rtt_dict[rtt_entry] = dict()

            if "2" == rtt_info_type:
                # rttMonCtrlAdminOwner (2)
                self.rtt_dict[rtt_entry]["owner"] = str(item.value)
            elif "3" == rtt_info_type:
                # rttMonCtrlAdminTag (3)
                self.rtt_dict[rtt_entry]["tag"] = str(item.value)
            elif "4" == rtt_info_type:
                # rttMonCtrlAdminRttType (4)
                self.rtt_dict[rtt_entry]["type"] = str(item.value)
            elif "5" == rtt_info_type:
                # rttMonCtrlAdminThreshold (5)
                self.rtt_dict[rtt_entry]["threshold"] = str(item.value)

        # Get SLA entry status
        rtt_ctrl_oper_entries = self.session.walk(".1.3.6.1.4.1.9.9.42.1.2.9.1")
        for item in rtt_ctrl_oper_entries:
            oid_parts = str(item.oid).split(".")
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if "2" == rtt_info_type:
                # rttMonCtrlOperDiagText (2)
                self.rtt_dict[rtt_entry]["diag_text"] = str(item.value)

            if "5" == rtt_info_type:
                # rttMonCtrlOperConnectionLostOccurred (5)
                if item.value == "1":
                    self.rtt_dict[rtt_entry]["conn_lost_occurred"] = True
                else:
                    self.rtt_dict[rtt_entry]["conn_lost_occurred"] = False

            elif "6" == rtt_info_type:
                # rttMonCtrlOperTimeoutOccurred (6)
                if item.value == "1":
                    self.rtt_dict[rtt_entry]["timeout_occurred"] = True
                else:
                    self.rtt_dict[rtt_entry]["timeout_occurred"] = False

            elif "7" == rtt_info_type:
                # rttMonCtrlOperOverThresholdOccurred (7)
                if item.value == "1":
                    self.rtt_dict[rtt_entry]["over_thres_occurred"] = True
                else:
                    self.rtt_dict[rtt_entry]["over_thres_occurred"] = False

            elif "10" == rtt_info_type:
                # rttMonCtrlOperState (10)
                # http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?local=en&translate=Translate&objectInput=1.3.6.1.4.1.9.9.42.1.2.9.1.10
                if item.value == "6":
                    self.rtt_dict[rtt_entry]["in_active_state"] = True
                else:
                    self.rtt_dict[rtt_entry]["in_active_state"] = False

        # Get SLA entry latest result
        latest_rtt_oper_entries = self.session.walk(".1.3.6.1.4.1.9.9.42.1.2.10.1")
        for item in latest_rtt_oper_entries:
            oid_parts = str(item.oid).split(".")
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if "1" == rtt_info_type:
                # rttMonLatestRttOperCompletionTime (1)
                self.rtt_dict[rtt_entry]["latest_completion_time"] = str(item.value)

            elif "2" == rtt_info_type:
                # rttMonLatestRttOperSense (2)
                # See http://www.circitor.fr/Mibs/Html/CISCO-RTTMON-TC-MIB.php#RttResponseSense
                self.rtt_dict[rtt_entry]["latest_sense"] = str(item.value)

    def list_rtt(self):
        """ Reads the list of available SLA entries for the device and prints out a list
        :return:
        """
        sla_list = list()
        inactive_sla_list = list()

        col_width_id = 0
        col_width_type = 0
        col_width_tag = 0

        rtt_table = list()
        for rtt_entry in self.rtt_dict:
            rtt_item = dict()
            rtt_item["id"] = str(rtt_entry)
            rtt_item["type"] = CiscoIpSlaChecker.get_rtt_type_description(self.rtt_dict[rtt_entry]["type"])
            rtt_item["tag"] = str(self.rtt_dict[rtt_entry]["tag"])
            rtt_item["active"] = self.rtt_dict[rtt_entry]["in_active_state"]
            if not rtt_item["active"]:
                rtt_item["tag"] += " (inactive)"

            col_width_id = max(col_width_id, len(str(rtt_item["id"])))
            col_width_type = max(col_width_type, len(str(rtt_item["type"])))
            col_width_tag = max(col_width_tag, len(str(rtt_item["tag"])))

            rtt_table.append(rtt_item)

        for rtt_item in rtt_table:
            rtt_line = "  " + rtt_item["id"].rjust(col_width_id)
            rtt_line += "  " + rtt_item["type"].ljust(col_width_type)
            if rtt_item["tag"]:
                rtt_line += "  " + rtt_item["tag"]

            if rtt_item["active"]:
                sla_list.append(rtt_line)
            else:
                inactive_sla_list.append(rtt_line)

        # Add the inactive SLA's at the end of the list
        sla_list.extend(inactive_sla_list)

        col_headers = "  " + "ID".rjust(col_width_id)
        col_headers += "  " + "Type".ljust(col_width_type)
        col_headers += "  " + "Tag\n"
        col_headers += "  " + ("-" * col_width_id)
        col_headers += "  " + ("-" * col_width_type)
        col_headers += "  " + ("-" * col_width_tag) + "\n"

        if len(sla_list) == 0:
            self.message = "No SLAs available"
        else:
            self.message = "SLAs available:\n"
            self.message += col_headers
            for sla in sla_list:
                self.message += str(sla) + "\n"

    @staticmethod
    def get_rtt_type_description(rtt_type):
        rtt_type = str(rtt_type)
        description = "unknown"
        if rtt_type == "1":
            description = "echo"
        elif rtt_type == "2":
            description = "pathEcho"
        elif rtt_type == "3":
            description = "fileIO"
        elif rtt_type == "4":
            description = "script"
        elif rtt_type == "5":
            description = "udpEcho"
        elif rtt_type == "6":
            description = "tcpConnect"
        elif rtt_type == "7":
            description = "http"
        elif rtt_type == "8":
            description = "dns"
        elif rtt_type == "9":
            description = "jitter"
        elif rtt_type == "10":
            description = "dlsw"
        elif rtt_type == "11":
            description = "dhcp"
        elif rtt_type == "12":
            description = "ftp"
        elif rtt_type == "13":
            description = "voip"
        elif rtt_type == "14":
            description = "rtp"
        elif rtt_type == "15":
            description = "lspGroup"
        elif rtt_type == "16":
            description = "icmpjitter"
        elif rtt_type == "17":
            description = "lspPing"
        elif rtt_type == "18":
            description = "lspTrace"
        elif rtt_type == "19":
            description = "ethernetPing"
        elif rtt_type == "20":
            description = "ethernetJitter"
        elif rtt_type == "21":
            description = "lspPingPseudowire"

        return description

    def check(self):
        messages = []
        if self.options.entries == "all":
            requested_entries = self.rtt_dict.keys()
        else:
            requested_entries = self.options.entries.replace(" ", "").split(",")
        requested_entries.sort(key=int)

        # Initialize status to OK (if status is not set yet)
        self.add_status(self.STATUS_OK)
        ok_count = 0
        failed_count = 0

        for requested_entry in requested_entries:
            if requested_entry not in self.rtt_dict:
                self.message = "SLA {0} does not exist".format(requested_entry)
                self.add_status(self.STATUS_UNKNOWN)
                return
            else:
                rtt_id = "{0}".format(requested_entry)
                rtt_type = self.rtt_dict[requested_entry]["type"]
                if rtt_type != "1" and rtt_type != "2":
                    rtt_type_description = CiscoIpSlaChecker.get_rtt_type_description(rtt_type)
                    print(
                        "Warning: RTT type {0} ({1}) not yet supported (entry {2})".format(
                            rtt_type_description,
                            rtt_type,
                            rtt_id
                        )
                    )

                if self.rtt_dict[requested_entry]["tag"]:
                    rtt_id += " (tag: {0})".format(self.rtt_dict[requested_entry]["tag"])

                if self.rtt_dict[requested_entry]["in_active_state"]:
                    if self.rtt_dict[requested_entry]["conn_lost_occurred"]:
                        failed_count += 1
                        messages.append("Connection lost for SLA {0}".format(rtt_id))
                    elif self.rtt_dict[requested_entry]["timeout_occurred"]:
                        failed_count += 1
                        messages.append("Timeout for SLA {0}".format(rtt_id))
                    elif self.rtt_dict[requested_entry]["over_thres_occurred"]:
                        failed_count += 1
                        messages.append("Threshold exceeded for SLA {0}".format(rtt_id))
                    else:
                        ok_count += 1
                else:
                    messages.append("SLA {0} not active".format(rtt_id))
                    self.add_status(self.STATUS_WARNING)

        if failed_count + ok_count == 0:
            messages.append("No SLAs checked")
            self.add_status(self.STATUS_UNKNOWN)
            return

        failed_pct = round(float(failed_count) / (failed_count + ok_count) * 100, 1)

        # Check percentage thresholds (if set)
        if self.options.critical_pct is not None and failed_pct >= self.options.critical_pct:
            self.add_status(self.STATUS_CRITICAL)
        if self.options.warning_pct is not None and failed_pct >= self.options.warning_pct:
            self.add_status(self.STATUS_WARNING)

        # Check absolute thresholds (if set)
        if self.options.critical is not None and failed_count >= self.options.critical:
            self.add_status(self.STATUS_CRITICAL)
        if self.options.warning is not None and failed_count >= self.options.warning:
            self.add_status(self.STATUS_WARNING)

        if failed_count:
            # Don't show percentage-failed when only checking one SLA
            if failed_count + ok_count == 1:
                messages.insert(0, "{0} Failed".format(failed_count))
            else:
                messages.insert(0, "{0} Failed ({1}%)".format(failed_count, failed_pct))
        if ok_count:
            messages.insert(0, "{0} OK".format(ok_count))

        if messages:
            self.message = ", ".join(messages)

        if self.options.perf:
            self.perfdata = "'Failed%'={0}%".format(failed_pct)
            if self.options.critical_pct and self.options.warning_pct:
                self.perfdata += ";{0};{1};0;100".format(self.options.warning_pct, self.options.critical_pct)

            for requested_entry in requested_entries:
                if requested_entry in self.rtt_dict:
                    self.perfdata += " 'rt {0}'={1}ms".format(
                        requested_entry,
                        self.rtt_dict[requested_entry]["latest_completion_time"]
                    )


if __name__ == "__main__":
    checker = CiscoIpSlaChecker()
    result = checker.run()
    exit(result)
