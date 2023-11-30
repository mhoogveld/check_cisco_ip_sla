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

from __future__ import division, print_function, absolute_import
import argparse
import math
from decimal import *
from collections import Counter
from easysnmp import Session
from easysnmp.exceptions import *

__author__ = "Maarten Hoogveld"
__version__ = "1.1.4"
__email__ = "maarten@hoogveld.org"
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

    rtt_types = {
        1: "echo",
        2: "pathEcho",
        3: "fileIO",
        4: "script",
        5: "udpEcho",
        6: "tcpConnect",
        7: "http",
        8: "dns",
        9: "jitter",
        10: "dlsw",
        11: "dhcp",
        12: "ftp",
        13: "voip",
        14: "rtp",
        15: "lspGroup",
        16: "icmpJitter",
        17: "lspPing",
        18: "lspTrace",
        19: "ethernetPing",
        20: "ethernetJitter",
        21: "lspPingPseudowire",
    }

    def __init__(self):
        self.status = None
        self.messages = []
        self.perfdata = []
        self.session = None
        self.options = None
        self.requested_entry_count = 0
        self.rtt_dict = dict()

    def run(self):
        self.parse_options()
        try:
            self.create_snmp_session()
            self.read_rtt_entries()
        except EasySNMPError as e:
            self.add_status(self.STATUS_UNKNOWN)
            self.set_message("SNMP error checking {}, {}".format(self.options.hostname, e))
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
        parser.add_argument("--version", action="version", version="%(prog)s {version}".format(version=__version__),
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
                            help="SLA entry (or entries) to check, specify a single value, "
                                 "a comma-separated list or 'all' to check all entries available. "
                                 "All entries must be of the same type. "
                                 "(default 'all')")
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
        parser.add_argument("--critical-jitter",
                            default=None, type=int,
                            help="Critical threshold for the Average Jitter value of jitter SLAs")
        parser.add_argument("--warning-jitter",
                            default=None, type=int,
                            help="Warning threshold for the Average Jitter value of jitter SLAs")
        parser.add_argument("--critical-mos",
                            default=None, type=Decimal,
                            help="Critical threshold for the MOS value of jitter SLAs (1.00 .. 5.00)")
        parser.add_argument("--warning-mos",
                            default=None, type=Decimal,
                            help="Warning threshold for the MOS value of jitter SLAs (1.00 .. 5.00)")
        parser.add_argument("--critical-icpif",
                            default=None, type=int, help="Critical threshold for the ICPIF value of jitter SLAs")
        parser.add_argument("--warning-icpif",
                            default=None, type=int, help="Warning threshold for the ICPIF value of jitter SLAs")
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
        self.print_msg(self.V_DEBUG, " Hostname:                {}".format(self.options.hostname))
        self.print_msg(self.V_DEBUG, " SNMP-version:            {}".format(self.options.snmp_version))
        self.print_msg(self.V_DEBUG, " Community:               {}".format(self.options.community))
        self.print_msg(self.V_DEBUG, " Security-name:           {}".format(self.options.security_name))
        self.print_msg(self.V_DEBUG, " Security-level:          {}".format(self.options.security_level))
        self.print_msg(self.V_DEBUG, " Password:                {}".format(self.options.password))
        self.print_msg(self.V_DEBUG, " Auth-protocol:           {}".format(self.options.auth_protocol))
        self.print_msg(self.V_DEBUG, " Auth-password:           {}".format(self.options.auth_password))
        self.print_msg(self.V_DEBUG, " Priv-protocol:           {}".format(self.options.priv_protocol))
        self.print_msg(self.V_DEBUG, " Priv-password:           {}".format(self.options.priv_password))
        self.print_msg(self.V_DEBUG, " Mode:                    {}".format(self.options.mode))
        self.print_msg(self.V_DEBUG, " SLA entries:             {}".format(self.options.entries))
        self.print_msg(self.V_DEBUG, " Perf-data:               {}".format(self.options.perf))
        self.print_msg(self.V_DEBUG, " Critical-pct:            {}".format(self.options.critical_pct))
        self.print_msg(self.V_DEBUG, " Warning-pct:             {}".format(self.options.warning_pct))
        self.print_msg(self.V_DEBUG, " Critical:                {}".format(self.options.critical))
        self.print_msg(self.V_DEBUG, " Warning:                 {}".format(self.options.warning))
        self.print_msg(self.V_DEBUG, " Critical Average Jitter: {}".format(self.options.critical_jitter))
        self.print_msg(self.V_DEBUG, " Warning Average Jitter:  {}".format(self.options.warning_jitter))
        self.print_msg(self.V_DEBUG, " Critical MOS:            {}".format(self.options.critical_mos))
        self.print_msg(self.V_DEBUG, " Warning MOS:             {}".format(self.options.warning_mos))
        self.print_msg(self.V_DEBUG, " Critical ICPIF:          {}".format(self.options.critical_icpif))
        self.print_msg(self.V_DEBUG, " Warning ICPIF:           {}".format(self.options.warning_icpif))
        self.print_msg(self.V_DEBUG, " Verbosity:               {}".format(self.options.verbose))
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
        if self.options.critical_mos and (self.options.critical_mos < 1 or self.options.critical_mos > 5):
            print("The critical-mos threshold value must lie between 1.00 and 5.00.")
            return False
        if self.options.warning_mos and (self.options.warning_mos < 1 or self.options.warning_mos > 5):
            print("The warning-mos threshold value must lie between 1.00 and 5.00.")
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

        if self.messages:
            if len(output):
                output += " - "
            # Join messages like sentences. Correct those messages which already ended with a period or a newline.
            output += ". ".join(self.messages).replace(".. ", ".").replace("\n. ", "\n")

        if self.perfdata:
            if len(output):
                output += " | "
            output += " ".join(self.perfdata)

        print(output)

    def create_snmp_session(self):
        kwargs = dict(
            hostname=self.options.hostname,
            version=int(self.options.snmp_version),
            community=self.options.community,
            security_username=self.options.security_name,
            security_level=self.options.security_level,
            auth_protocol=self.options.auth_protocol,
            auth_password=self.options.auth_password,
            privacy_protocol=self.options.priv_protocol,
            privacy_password=self.options.priv_password,
            use_numeric=True,
        )

        if self.options.auth_password is None:
            kwargs.pop('auth_password')
        if self.options.priv_password is None:
            kwargs.pop('privacy_password')

        self.session = Session(**kwargs)

    def add_status(self, status):
        """ Set the status only if it is more severe than the present status
        The order of severity being OK, WARNING, CRITICAL, UNKNOWN
        :param status: Status to set, one of the self.STATUS_xxx constants
        :return: The current status
        """
        if self.status is None or status > self.status:
            self.status = status

    def set_message(self, message):
        self.messages = [message]

    def add_message(self, message):
        self.messages.append(message)

    def add_perfdata(self, perfitem):
        self.perfdata.append(perfitem)

    def get_entry_output_id(self, entry):
        if self.requested_entry_count > 1:
            entry_output_id = " " + entry
        else:
            entry_output_id = ""

        return entry_output_id

    def read_rtt_entries(self):
        """ Reads all info on all RTT entries and stores found data in self.rtt_dict """
        # Get SLA entry info
        self.rtt_dict = dict()

        self.print_msg(self.V_DEBUG, "Starting SNMP-walk for rttMonCtrlAdminTable (.1.3.6.1.4.1.9.9.42.1.2.1.1)")
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
                self.rtt_dict[rtt_entry]["type"] = int(item.value)
            elif "5" == rtt_info_type:
                # rttMonCtrlAdminThreshold (5)
                self.rtt_dict[rtt_entry]["threshold"] = int(item.value)
            elif "12" == rtt_info_type:
                # rttMonCtrlAdminLongTag (12)
                self.rtt_dict[rtt_entry]["long_tag"] = str(item.value)

        # Get SLA entry status
        self.print_msg(self.V_DEBUG, "Starting SNMP-walk for rttMonCtrlOperTable (.1.3.6.1.4.1.9.9.42.1.2.9.1)")
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
        self.print_msg(self.V_DEBUG, "Starting SNMP-walk for rttMonLatestRttOperTable (.1.3.6.1.4.1.9.9.42.1.2.10.1)")
        latest_rtt_oper_entries = self.session.walk(".1.3.6.1.4.1.9.9.42.1.2.10.1")
        for item in latest_rtt_oper_entries:
            oid_parts = str(item.oid).split(".")
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if "1" == rtt_info_type:
                # rttMonLatestRttOperCompletionTime (1)
                self.rtt_dict[rtt_entry]["latest_completion_time"] = int(item.value)

            elif "2" == rtt_info_type:
                # rttMonLatestRttOperSense (2)
                # See http://www.circitor.fr/Mibs/Html/CISCO-RTTMON-TC-MIB.php#RttResponseSense
                self.rtt_dict[rtt_entry]["latest_sense"] = int(item.value)

        # Get Jitter specific data (See "-- LatestJitterOper Table" in MIB)
        self.print_msg(self.V_DEBUG, "Starting SNMP-walk for rttMonLatestJitterOperTable (.1.3.6.1.4.1.9.9.42.1.5.2.1)")
        latest_jitters = dict()
        latest_jitter_oper_entries = self.session.walk(".1.3.6.1.4.1.9.9.42.1.5.2.1")
        for item in latest_jitter_oper_entries:
            oid_parts = str(item.oid).split(".")
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if rtt_entry not in latest_jitters:
                latest_jitters[rtt_entry] = dict()

            try:
                if "1" == rtt_info_type:
                    # rttMonLatestJitterOperNumOfRTT (1)
                    latest_jitters[rtt_entry]["num_of_rtt"] = Decimal(item.value)

                elif "2" == rtt_info_type:
                    # rttMonLatestJitterOperRTTSum (2)
                    latest_jitters[rtt_entry]["rtt_sum"] = Decimal(item.value)

                elif "3" == rtt_info_type:
                    # rttMonLatestJitterOperRTTSum2 (3)
                    latest_jitters[rtt_entry]["rtt_sum2"] = Decimal(item.value)

                elif "4" == rtt_info_type:
                    # rttMonLatestJitterOperRTTMin (4)
                    latest_jitters[rtt_entry]["rtt_min"] = Decimal(item.value)

                elif "5" == rtt_info_type:
                    # rttMonLatestJitterOperRTTMax (5)
                    latest_jitters[rtt_entry]["rtt_max"] = Decimal(item.value)

                elif "6" == rtt_info_type:
                    # rttMonLatestJitterOperMinOfPositivesSD (6)
                    latest_jitters[rtt_entry]["min_of_positives_SD"] = Decimal(item.value)

                elif "7" == rtt_info_type:
                    # rttMonLatestJitterOperMaxOfPositivesSD (7)
                    latest_jitters[rtt_entry]["max_of_positives_SD"] = Decimal(item.value)

                elif "8" == rtt_info_type:
                    # rttMonLatestJitterOperNumOfPositivesSD (8)
                    latest_jitters[rtt_entry]["num_of_positives_SD"] = Decimal(item.value)

                elif "11" == rtt_info_type:
                    # rttMonLatestJitterOperMinOfNegativesSD (11)
                    latest_jitters[rtt_entry]["min_of_negatives_SD"] = Decimal(item.value)

                elif "12" == rtt_info_type:
                    # rttMonLatestJitterOperMaxOfNegativesSD (12)
                    latest_jitters[rtt_entry]["max_of_negatives_SD"] = Decimal(item.value)

                elif "13" == rtt_info_type:
                    # rttMonLatestJitterOperNumOfNegativesSD (13)
                    latest_jitters[rtt_entry]["num_of_negatives_SD"] = Decimal(item.value)

                elif "16" == rtt_info_type:
                    # rttMonLatestJitterOperMinOfPositivesDS (16)
                    latest_jitters[rtt_entry]["min_of_positives_DS"] = Decimal(item.value)

                elif "17" == rtt_info_type:
                    # rttMonLatestJitterOperMaxOfPositivesDS (17)
                    latest_jitters[rtt_entry]["max_of_positives_DS"] = Decimal(item.value)

                elif "18" == rtt_info_type:
                    # rttMonLatestJitterOperNumOfPositivesDS (18)
                    latest_jitters[rtt_entry]["num_of_positives_DS"] = Decimal(item.value)

                elif "21" == rtt_info_type:
                    # rttMonLatestJitterOperMinOfNegativesDS (21)
                    latest_jitters[rtt_entry]["min_of_negatives_DS"] = Decimal(item.value)

                elif "22" == rtt_info_type:
                    # rttMonLatestJitterOperMaxOfNegativesDS (22)
                    latest_jitters[rtt_entry]["max_of_negatives_DS"] = Decimal(item.value)

                elif "23" == rtt_info_type:
                    # rttMonLatestJitterOperNumOfNegativesDS (23)
                    latest_jitters[rtt_entry]["num_of_negatives_DS"] = Decimal(item.value)

                elif "26" == rtt_info_type:
                    # rttMonLatestJitterOperPacketLossSD (26)
                    latest_jitters[rtt_entry]["packet_loss_SD"] = Decimal(item.value)

                elif "27" == rtt_info_type:
                    # rttMonLatestJitterOperPacketLossDS (27)
                    latest_jitters[rtt_entry]["packet_loss_DS"] = Decimal(item.value)

                elif "28" == rtt_info_type:
                    # rttMonLatestJitterOperPacketOutOfSequence (28)
                    latest_jitters[rtt_entry]["packet_out_of_seq"] = Decimal(item.value)

                elif "29" == rtt_info_type:
                    # rttMonLatestJitterOperPacketMIA (29)
                    latest_jitters[rtt_entry]["packet_mia"] = Decimal(item.value)

                elif "30" == rtt_info_type:
                    # rttMonLatestJitterOperPacketLateArrival (30)
                    latest_jitters[rtt_entry]["packet_late_arrival"] = Decimal(item.value)

                elif "31" == rtt_info_type:
                    # rttMonLatestJitterOperSense (31)
                    latest_jitters[rtt_entry]["sense"] = str(item.value)

                elif "32" == rtt_info_type:
                    # rttMonLatestJitterErrorSenseDescription (32)
                    latest_jitters[rtt_entry]["sense_description"] = str(item.value)

                # One way latency skipped

                elif "42" == rtt_info_type:
                    # rttMonLatestJitterOperMOS (42)
                    mos = Decimal(item.value)
                    if mos >= 100:
                        mos = mos / 100
                    latest_jitters[rtt_entry]["MOS"] = mos

                elif "43" == rtt_info_type:
                    # rttMonLatestJitterOperICPIF (43)
                    latest_jitters[rtt_entry]["ICPIF"] = Decimal(item.value)

                elif "46" == rtt_info_type:
                    # rttMonLatestJitterOperAvgJitter (46)
                    latest_jitters[rtt_entry]["avg_jitter"] = Decimal(item.value)

                elif "47" == rtt_info_type:
                    # rttMonLatestJitterOperAvgSDJ (47)
                    latest_jitters[rtt_entry]["avg_jitter_SD"] = Decimal(item.value)

                elif "48" == rtt_info_type:
                    # rttMonLatestJitterOperAvgDSJ (48)
                    latest_jitters[rtt_entry]["avg_jitter_DS"] = Decimal(item.value)

                elif "49" == rtt_info_type:
                    # rttMonLatestJitterOperOWAvgSD (49)
                    latest_jitters[rtt_entry]["avg_latency_SD"] = Decimal(item.value)

                elif "50" == rtt_info_type:
                    # rttMonLatestJitterOperOWAvgDS (50)
                    latest_jitters[rtt_entry]["avg_latency_DS"] = Decimal(item.value)

                elif "51" == rtt_info_type:
                    # rttMonLatestJitterOperNTPState (51)
                    latest_jitters[rtt_entry]["ntp_sync"] = (int(item.value) == 1)

                elif "53" == rtt_info_type:
                    # rttMonLatestJitterOperRTTSumHigh (53)
                    latest_jitters[rtt_entry]["rtt_sum_high"] = Decimal(item.value)

                elif "54" == rtt_info_type:
                    # rttMonLatestJitterOperRTTSum2High (54)
                    latest_jitters[rtt_entry]["rtt_sum2_high"] = Decimal(item.value)

                elif "59" == rtt_info_type:
                    # rttMonLatestJitterOperNumOverThresh (59)
                    latest_jitters[rtt_entry]["num_over_threshold"] = Decimal(item.value)

            except ValueError:
                pass

        # Add jitter info for each rtt entry
        for rtt_entry in latest_jitters:
            latest_jitter = latest_jitters[rtt_entry]

            # Merge high- and low bits for applicable fields
            if "rtt_sum" in latest_jitter \
                    and "rtt_sum_high" in latest_jitter \
                    and latest_jitter["rtt_sum_high"] > 0:
                latest_jitter["rtt_sum"] = Decimal(latest_jitter["rtt_sum"] +
                                                   (latest_jitter["rtt_sum_high"] << 32))
                del latest_jitter["rtt_sum_high"]

            if "rtt_sum2" in latest_jitter \
                    and "rtt_sum2_high" in latest_jitter \
                    and latest_jitter["rtt_sum2_high"] > 0:
                latest_jitter["rtt_sum2"] = Decimal(latest_jitter["rtt_sum2"] +
                                                    (latest_jitter["rtt_sum2_high"] << 32))
                del latest_jitter["rtt_sum2_high"]

            # Add the latest jitter into to the dict
            self.rtt_dict[rtt_entry]["latest_jitter"] = latest_jitter

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
            self.add_message("No SLAs available")
        else:
            self.set_message("SLAs available:\n")
            self.add_message(col_headers)
            for sla in sla_list:
                self.add_message(str(sla) + "\n")

    def get_sla_description(self, rtt_id):
        """
        Get a human readable description identifying this SLA entry
        Consisting of the id and the tag if set
        :param rtt_id: The id of the SLA
        :return: A string describing the SLA
        """
        sla_description = str(rtt_id)
        if self.rtt_dict[rtt_id]["tag"]:
            sla_description += " (tag: {0})".format(self.rtt_dict[rtt_id]["tag"])

        return sla_description

    @staticmethod
    def get_rtt_type_description(rtt_type):
        """
        Get the string equivalent of a numeric rtt-type
        :param rtt_type: The rtt-type in numeric form as returned by an SNMP request
        :return: A string describing the rtt-type or "Unknown" if no match was found
        """
        rtt_type = int(rtt_type)
        description = "unknown"
        if rtt_type in CiscoIpSlaChecker.rtt_types:
            description = CiscoIpSlaChecker.rtt_types[rtt_type]
        return description

    @staticmethod
    def get_rtt_type_id(rtt_type_description):
        """
        Get the numeric equivalent of an rtt-type represented as a astring
        :param rtt_type_description: The rtt-type in string form
        :return: The numeric form of the rtt-type or 0 if no match was found
        """
        for rtt_type_id in CiscoIpSlaChecker.rtt_types:
            if rtt_type_description == CiscoIpSlaChecker.rtt_types[rtt_type_id]:
                return rtt_type_id
        return 0

    @staticmethod
    def is_rtt_type_supported(rtt_type):
        """
        Returns whether or not the rtt-type is supported.
        This list of supported rtt-types is planned to be expanded
        :param rtt_type: The rtt-type in numeric form
        :return: True if the rtt-type is supported, False otherwise
        """
        supported_rtt_types = [
            CiscoIpSlaChecker.get_rtt_type_id("echo"),
            CiscoIpSlaChecker.get_rtt_type_id("pathEcho"),
            CiscoIpSlaChecker.get_rtt_type_id("jitter"),
        ]
        return rtt_type in supported_rtt_types

    def validate_requested_rtt_entries_types(self, requested_entries):
        """
        Checks if the list of requested rtt-types is valid. At this time, this means that the entries
        must be of the same type. If they are not, the performance data might be returned in an invalid form.
        Requires read_rtt_entries to have been called.
        :param requested_entries: A list of (numeric) rtt-entry-ids.
        :return: True if valid, False otherwise
        """
        # Create a list of all RTT types used and their count
        rtt_type_count = Counter()

        for requested_entry in requested_entries:
            if requested_entry not in self.rtt_dict:
                self.add_message("SLA {0} does not exist".format(requested_entry))
                self.add_status(self.STATUS_UNKNOWN)
                return False

            rtt_type = self.rtt_dict[requested_entry]["type"]
            rtt_type_description = CiscoIpSlaChecker.get_rtt_type_description(rtt_type)

            if not CiscoIpSlaChecker.is_rtt_type_supported(rtt_type):
                msg = "SLA {0} is of type {1} ({2}) which is not supported (yet)."
                self.add_message(msg.format(requested_entry,
                                            rtt_type_description,
                                            rtt_type))
                self.add_status(self.STATUS_UNKNOWN)
                return False

            rtt_type_count[rtt_type] += 1

        # For now, only checking of multiple SLA's is supported if they are all of the same type
        if len(rtt_type_count) > 1:
            self.add_message("Checking multiple SLA entries is supported, but only if they are of the same type.")
            self.add_status(self.STATUS_UNKNOWN)
            return False

        return True

    def check_jitter_health(self, requested_entry):
        """
        Checks if the latest jitter entry check went OK by it's sense value,
        if time is synced between the source and destination
        and checks the MOS and ICPIF thresholds if they are set.
        Can adjust the status and messages returned by the check
        :param requested_entry: The rtt-id in numeric form
        :return:
        """
        rtt_id = self.get_sla_description(requested_entry)

        latest_jitter = self.rtt_dict[requested_entry]["latest_jitter"]
        if latest_jitter["sense"] != "1":  # ok (1)
            self.add_status(self.STATUS_WARNING)
            self.add_message("Latest jitter operation not ok for SLA {0}: {1}".format(
                rtt_id, latest_jitter["sense_description"]))

        if not latest_jitter["ntp_sync"]:
            self.add_status(self.STATUS_WARNING)
            self.add_message("NTP not synced between source and destination for SLA {0}".format(rtt_id))

        # Check Average Jitter thresholds (if set)
        if self.options.critical_jitter is not None or self.options.warning_jitter is not None:
            if latest_jitter["avg_jitter"] is None:
                self.add_status(self.STATUS_UNKNOWN)
                self.add_message("Average Jitter not known for SLA {0}, but threshold is set".format(rtt_id))
            elif self.options.critical_jitter is not None \
                    and latest_jitter["avg_jitter"] >= self.options.critical_jitter:
                self.add_status(self.STATUS_CRITICAL)
                self.add_message("Average Jitter is over critical threshold for SLA {0}".format(rtt_id))
            elif self.options.warning_jitter is not None \
                    and latest_jitter["avg_jitter"] >= self.options.warning_jitter:
                self.add_status(self.STATUS_WARNING)
                self.add_message("Average Jitter is over warning threshold for SLA {0}".format(rtt_id))

        # Check MOS thresholds (if set)
        if self.options.critical_mos is not None or self.options.warning_mos is not None:
            if latest_jitter["MOS"] is None:
                self.add_status(self.STATUS_UNKNOWN)
                self.add_message("MOS not known for SLA {0}, but threshold is set".format(rtt_id))
            elif self.options.critical_mos is not None and latest_jitter["MOS"] <= self.options.critical_mos:
                self.add_status(self.STATUS_CRITICAL)
                self.add_message("MOS is under critical threshold for SLA {0}".format(rtt_id))
            elif self.options.warning_mos is not None and latest_jitter["MOS"] <= self.options.warning_mos:
                self.add_status(self.STATUS_WARNING)
                self.add_message("MOS is under warning threshold for SLA {0}".format(rtt_id))

        # Check ICPIF thresholds (if set)
        if self.options.critical_icpif is not None or self.options.warning_icpif is not None:
            if latest_jitter["ICPIF"] is None:
                self.add_status(self.STATUS_UNKNOWN)
                self.add_message("ICPIF not known for SLA {0}, but threshold is set".format(rtt_id))
            elif self.options.critical_icpif is not None and latest_jitter["ICPIF"] >= self.options.critical_icpif:
                self.add_status(self.STATUS_CRITICAL)
                self.add_message("ICPIF is over critical threshold for SLA {0}".format(rtt_id))
            elif self.options.warning_icpif is not None and latest_jitter["ICPIF"] >= self.options.warning_icpif:
                self.add_status(self.STATUS_WARNING)
                self.add_message("ICPIF is over warning threshold for SLA {0}".format(rtt_id))

    def collect_perfdata_jitter(self, requested_entry):
        """
        Collect and save perf-data for the rtt so it gets returned by this check
        Will adjust the perfdata returned by the check
        :param requested_entry: The rtt-id in numeric form
        :return:
        """
        jitter_info = self.rtt_dict[requested_entry]["latest_jitter"]
        if jitter_info["num_of_rtt"] > 1:
            self.add_perfdata("'RTT avg{entry}'={avg}ms;{min};{max}".format(
                entry=self.get_entry_output_id(requested_entry),
                avg=round(jitter_info["rtt_sum"] / (jitter_info["num_of_rtt"] - 1), 1),
                min=jitter_info["rtt_min"],
                max=jitter_info["rtt_max"]
            ))
            self.add_perfdata("'RTT variance{entry}'={var}".format(
                entry=self.get_entry_output_id(requested_entry),
                var=round(jitter_info["rtt_sum2"] / (jitter_info["num_of_rtt"] - 1), 1),
            ))
            self.add_perfdata("'RTT std dev{entry}'={var}".format(
                entry=self.get_entry_output_id(requested_entry),
                var=round(math.sqrt(jitter_info["rtt_sum2"] / (jitter_info["num_of_rtt"] - 1)), 1),
            ))

        self.add_perfdata("'Avg jitter{entry}'={v}".format(
            entry=self.get_entry_output_id(requested_entry),
            v=jitter_info["avg_jitter"]
        ))
        self.add_perfdata("'Avg jitter SD{entry}'={v}".format(
            entry=self.get_entry_output_id(requested_entry),
            v=jitter_info["avg_jitter_SD"]
        ))
        self.add_perfdata("'Avg jitter DS{entry}'={v}".format(
            entry=self.get_entry_output_id(requested_entry),
            v=jitter_info["avg_jitter_DS"]
        ))
        self.add_perfdata("'Avg latency SD{entry}'={v}".format(
            entry=self.get_entry_output_id(requested_entry),
            v=jitter_info["avg_latency_SD"]
        ))
        self.add_perfdata("'Avg latency DS{entry}'={v}".format(
            entry=self.get_entry_output_id(requested_entry),
            v=jitter_info["avg_latency_DS"]
        ))
        self.add_perfdata("'MOS{entry}'={v}".format(
            entry=self.get_entry_output_id(requested_entry),
            v=jitter_info["MOS"]
        ))
        self.add_perfdata("'ICPIF{entry}'={v}".format(
            entry=self.get_entry_output_id(requested_entry),
            v=jitter_info["ICPIF"]
        ))
        self.add_perfdata("'Packet loss SD{entry}'={v}".format(
            entry=self.get_entry_output_id(requested_entry),
            v=jitter_info["packet_loss_SD"]
        ))
        self.add_perfdata("'Packet loss DS{entry}'={v}".format(
            entry=self.get_entry_output_id(requested_entry),
            v=jitter_info["packet_loss_DS"]
        ))
        self.add_perfdata("'Packet out of seq{entry}'={v}".format(
            entry=self.get_entry_output_id(requested_entry),
            v=jitter_info["packet_out_of_seq"]
        ))
        self.add_perfdata("'Packet MIA{entry}'={v}".format(
            entry=self.get_entry_output_id(requested_entry),
            v=jitter_info["packet_mia"]
        ))
        self.add_perfdata("'Packet late arrival{entry}'={v}".format(
            entry=self.get_entry_output_id(requested_entry),
            v=jitter_info["packet_late_arrival"]
        ))
        if "num_over_threshold" in jitter_info:
            self.add_perfdata("'Num over threshold{entry}'={v}".format(
                entry=self.get_entry_output_id(requested_entry),
                v=jitter_info["num_over_threshold"]
            ))

    def check(self):
        """
        Perform checks on the requested entries
        :return:
        """
        messages = []
        if self.options.entries == "all":
            requested_entries = list(self.rtt_dict.keys())
        else:
            requested_entries = self.options.entries.replace(" ", "").split(",")
        requested_entries.sort(key=int)
        self.requested_entry_count = len(requested_entries)

        # Initialize status to OK (if status is not set yet)
        self.add_status(self.STATUS_OK)
        ok_count = 0
        failed_count = 0

        if not self.validate_requested_rtt_entries_types(requested_entries):
            return

        for requested_entry in requested_entries:
            rtt_type = self.rtt_dict[requested_entry]["type"]
            rtt_type_desc = self.get_rtt_type_description(rtt_type)
            sla_description = self.get_sla_description(requested_entry)

            if self.rtt_dict[requested_entry]["in_active_state"]:
                if "conn_lost_occurred" in self.rtt_dict[requested_entry] \
                        and self.rtt_dict[requested_entry]["conn_lost_occurred"]:
                    # conn_lost_occurred only changes for rtt-type 'echo' and 'pathEcho'. Thanks zacsmits (Zak).
                    # Also see http://oidref.com/1.3.6.1.4.1.9.9.42.1.2.9.1.5
                    if rtt_type_desc in ["echo", "pathEcho"]:
                        failed_count += 1
                        messages.append("Connection lost for SLA {0}".format(sla_description))
                elif "timeout_occurred" in self.rtt_dict[requested_entry] \
                        and self.rtt_dict[requested_entry]["timeout_occurred"]:
                    failed_count += 1
                    messages.append("Timeout for SLA {0}".format(sla_description))
                elif "over_thres_occurred" in self.rtt_dict[requested_entry] \
                        and self.rtt_dict[requested_entry]["over_thres_occurred"]:
                    failed_count += 1
                    messages.append("Threshold exceeded for SLA {0}".format(sla_description))
                else:
                    ok_count += 1
            else:
                messages.append("SLA {0} not active".format(sla_description))
                self.add_status(self.STATUS_UNKNOWN)

            # Jitter specific threshold checks
            if rtt_type == self.get_rtt_type_id("jitter"):
                self.check_jitter_health(requested_entry)
                if self.options.perf:
                    self.collect_perfdata_jitter(requested_entry)

        if failed_count + ok_count == 0:
            self.add_message("No SLAs checked")
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
            self.add_message(", ".join(messages))

        if self.options.perf:
            if failed_count + ok_count > 1:
                failed_perf = "'Failed%'={0}%".format(failed_pct)
                if self.options.critical_pct and self.options.warning_pct:
                    failed_perf += ";{0};{1};0;100".format(self.options.warning_pct, self.options.critical_pct)
                self.add_perfdata(failed_perf)

            for requested_entry in requested_entries:
                if requested_entry in self.rtt_dict:
                    self.add_perfdata(
                        "'rtt{entry}'={v}ms".format(
                            entry=self.get_entry_output_id(requested_entry),
                            v=self.rtt_dict[requested_entry]["latest_completion_time"]
                        )
                    )


if __name__ == "__main__":
    checker = CiscoIpSlaChecker()
    result = checker.run()
    exit(result)
