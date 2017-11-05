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

__author__ = 'Maarten Hoogveld'
__version__ = '1.1.0'
__email__ = 'maarten@hoogveld.org'
__licence__ = 'GPL-3.0'
__status__ = 'Production'


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
        1: 'echo',
        2: 'pathEcho',
        3: 'fileIO',
        4: 'script',
        5: 'udpEcho',
        6: 'tcpConnect',
        7: 'http',
        8: 'dns',
        9: 'jitter',
        10: 'dlsw',
        11: 'dhcp',
        12: 'ftp',
        13: 'voip',
        14: 'rtp',
        15: 'lspGroup',
        16: 'icmpJitter',
        17: 'lspPing',
        18: 'lspTrace',
        19: 'ethernetPing',
        20: 'ethernetJitter',
        21: 'lspPingPseudowire',
    }

    def __init__(self):
        self.status = self.STATUS_OK
        self.messages = []
        self.perfdata = []
        self.session = None
        self.options = None

        ### A dictionary containing all info obtained through SNMP
        self.rtt_dict = dict()

        # A list of all RTT types requested and their use-count
        self.requested_entries = []

    def run(self):
        self.parse_options()
        try:
            self.create_snmp_session()
            self.read_all_rtt_entry_basic_info()
            if 'list' == self.options.mode:
                self.list_rtt()
            elif 'check' == self.options.mode:
                self.check()
        except EasySNMPError as e:
            self.add_status(self.STATUS_UNKNOWN)
            self.set_message('SNMP error checking {}, {}'.format(self.options.hostname, e))

        self.print_output()
        return

    def check(self):
        """
        Perform checks on the requested entries
        :return:
        """
        self.print_msg(self.V_DEBUG, 'Performing checks for requested entries')

        # Sets the self.requested_entries dict
        self.determine_requested_rtt_entries()

        if not self.validate_requested_rtt_entries_types():
            # Combination of entries not valid
            return

        if len(self.requested_entries) == 0:
            self.add_message('No SLAs checked')
            self.add_status(self.STATUS_UNKNOWN)
            return

        self.check_basic_entry_info()

        # Read rtt-type-specific data
        if self.is_rtt_type_requested(RttType.ECHO) or self.is_rtt_type_requested(RttType.PATH_ECHO) \
                or self.is_rtt_type_requested(RttType.UDP_ECHO):
            self.check_echo_entry_info()
        if self.is_rtt_type_requested(RttType.HTTP):
            self.read_rtt_http_entry_info()
            self.check_http_entry_info()
        if self.is_rtt_type_requested(RttType.JITTER) or self.is_rtt_type_requested(RttType.ICMP_JITTER):
            self.read_rtt_jitter_entry_info()
            self.check_jitter_entry_info()

        if len(self.requested_entries) > 1:
            self.check_fail_percentages()

    def check_fail_percentages(self):
        failed_count = 0
        ok_count = 0
        for requested_entry in self.requested_entries:
            if requested_entry in self.rtt_dict:
                rtt = self.rtt_dict[requested_entry]
                if rtt.failed:
                    failed_count += 1
                else:
                    ok_count += 1
                
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
                self.add_message('{0} Failed'.format(failed_count), True)
            else:
                self.add_message('{0} Failed ({1}%)'.format(failed_count, failed_pct), True)
        if ok_count:
            self.add_message('{0} OK'.format(ok_count), True)

        if self.options.perf:
            if failed_count + ok_count > 1:
                failed_perf = "'Failed%'={0}%".format(failed_pct)
                if self.options.critical_pct and self.options.warning_pct:
                    failed_perf += ';{0};{1};0;100'.format(self.options.warning_pct, self.options.critical_pct)
                self.add_perfdata(failed_perf)

    def check_basic_entry_info(self):
        self.print_msg(self.V_DEBUG, 'Checking basic info for requested entries')

        for requested_entry in self.requested_entries:
            rtt = self.rtt_dict[requested_entry]
            if rtt.in_active_state:
                if rtt.conn_lost_occurred:
                    rtt.failed = True
                    self.add_message('Connection lost for SLA {0}'.format(rtt.description))
                elif rtt.timeout_occurred:
                    rtt.failed = True
                    self.add_message('Timeout for SLA {0}'.format(rtt.description))
                elif rtt.over_thres_occurred:
                    rtt.failed = True
                    self.add_message('Threshold exceeded for SLA {0}'.format(rtt.description))
                else:
                    rtt.failed = False
            else:
                rtt.failed = True
                self.add_message('SLA {0} not active'.format(rtt.description))
                self.add_status(self.STATUS_UNKNOWN)

    def check_echo_entry_info(self):
        self.print_msg(self.V_DEBUG, 'Checking echo entries')

        if self.options.perf:
            for requested_entry in self.requested_entries:
                if requested_entry in self.rtt_dict:
                    rtt = self.rtt_dict[requested_entry]
                    self.add_perfdata(
                        "'rtt{entry}'={v}ms".format(
                            entry=self.get_entry_output_id(requested_entry),
                            v=rtt.latest_completion_time
                        )
                    )

    def check_http_entry_info(self):
        self.print_msg(self.V_DEBUG, 'Checking http entries')

        for requested_entry in self.requested_entries:
            self.print_msg(self.V_DEBUG, 'Checking entry {}'.format(requested_entry))
            rtt = self.rtt_dict[requested_entry]
            self.print_msg(self.V_DEBUG, 'Entry type {}'.format(rtt.type))
            if rtt.type == RttType.HTTP:
                self.check_http_health(rtt.id)
                if self.options.perf:
                    self.collect_perfdata_http(rtt.id)

    def check_jitter_entry_info(self):
        self.print_msg(self.V_DEBUG, 'Checking jitter entries')

        for requested_entry in self.requested_entries:
            rtt = self.rtt_dict[requested_entry]
            if (rtt.type == RttType.JITTER) or (rtt.type == RttType.ICMP_JITTER):
                self.check_jitter_health(requested_entry)
                if self.options.perf:
                    self.collect_perfdata_jitter(requested_entry)

    def parse_options(self):
        parser = argparse.ArgumentParser(
            description='Monitoring check plugin to check Cisco SLA status for one or more entries. '
                        'If a checked SLA entry is not in active state, the status is raised to WARNING. '
                        'The script returns the worst status found for each checked SLA entry where '
                        'UNKNOWN is worse than CRITICAL and CRITICAL is worse than WARNING.'
        )
        parser.add_argument('--version', action='version', version='%(prog)s {version}'.format(version=__version__),
                            help='The version of this script')
        parser.add_argument('-H', '--hostname',
                            help='Hostname or ip-address')
        parser.add_argument('-v', '--snmp-version',
                            default='2', choices=['1', '2', '3'], help='SNMP version (default "2"")')
        parser.add_argument('-c', '--community',
                            default='public', help='SNMP v1/v2 Community string (default "public")')
        parser.add_argument('-u', '--security-name',
                            help='SNMP v3 security name (username)')
        parser.add_argument('-l', '--security-level',
                            default='authPriv', choices=['noAuthNoPriv', 'authNoPriv', 'authPriv'],
                            help='SNMP v3 security level (default "authPriv")')
        parser.add_argument('-p', '--password',
                            help='SNMP v3 password (used for both authentication and privacy)')
        parser.add_argument('-a', '--auth-protocol',
                            default='SHA', choices=['MD5', 'SHA'],
                            help='SNMP v3 authentication protocol (default "SHA")')
        parser.add_argument('-A', '--auth-password',
                            help='SNMP v3 authentication password, overrides --password if set')
        parser.add_argument('-x', '--priv-protocol',
                            default='AES', choices=['DES', 'AES'],
                            help='SNMP v3 privacy protocol (default "AES")')
        parser.add_argument('-X', '--priv-password',
                            help='SNMP v3 privacy password, overrides --password if set')
        parser.add_argument('-m', '--mode',
                            choices=['list', 'check'], help='Operation mode')
        parser.add_argument('-e', '--entries',
                            default='all',
                            help='SLA entry (or entries) to check, specify a single value, '
                                 'a comma-separated list or "all" to check all entries available. '
                                 'All entries must be of the same type. '
                                 '(default "all")')
        parser.add_argument('--perf',
                            action='store_true', help='Return performance data (failed percentage, round-trip times)')
        parser.add_argument('--critical-pct',
                            default=None, type=float,
                            help='Critical threshold in percentage of failed SLAs (default "100")')
        parser.add_argument('--warning-pct',
                            default=None, type=float,
                            help='Warning threshold in percentage of failed SLAs (default "50")')
        parser.add_argument('--critical',
                            default=None, type=int, help='Critical threshold in amount of failed SLAs')
        parser.add_argument('--warning',
                            default=None, type=int, help='Warning threshold in amount of failed SLAs')
        parser.add_argument('--critical-mos',
                            default=None, type=Decimal,
                            help='Critical threshold for the MOS value of jitter SLAs (1.00 .. 5.00)')
        parser.add_argument('--warning-mos',
                            default=None, type=Decimal,
                            help='Warning threshold for the MOS value of jitter SLAs (1.00 .. 5.00)')
        parser.add_argument('--critical-icpif',
                            default=None, type=int, help='Critical threshold for the ICPIF value of jitter SLAs')
        parser.add_argument('--warning-icpif',
                            default=None, type=int, help='Warning threshold for the ICPIF value of jitter SLAs')
        parser.add_argument('--verbose',
                            default=0, type=int, choices=[0, 1, 2], help='Verbose output')
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
            print('Run with --help for usage information')
            print('')
            exit(0)

        self.print_msg(self.V_DEBUG, 'Using parameters:')
        self.print_msg(self.V_DEBUG, ' Hostname:        {}'.format(self.options.hostname))
        self.print_msg(self.V_DEBUG, ' SNMP-version:    {}'.format(self.options.snmp_version))
        self.print_msg(self.V_DEBUG, ' Community:       {}'.format(self.options.community))
        self.print_msg(self.V_DEBUG, ' Security-name:   {}'.format(self.options.security_name))
        self.print_msg(self.V_DEBUG, ' Security-level:  {}'.format(self.options.security_level))
        self.print_msg(self.V_DEBUG, ' Password:        {}'.format(self.options.password))
        self.print_msg(self.V_DEBUG, ' Auth-protocol:   {}'.format(self.options.auth_protocol))
        self.print_msg(self.V_DEBUG, ' Auth-password:   {}'.format(self.options.auth_password))
        self.print_msg(self.V_DEBUG, ' Priv-protocol:   {}'.format(self.options.priv_protocol))
        self.print_msg(self.V_DEBUG, ' Priv-password:   {}'.format(self.options.priv_password))
        self.print_msg(self.V_DEBUG, ' Mode:            {}'.format(self.options.mode))
        self.print_msg(self.V_DEBUG, ' SLA entries:     {}'.format(self.options.entries))
        self.print_msg(self.V_DEBUG, ' Perf-data:       {}'.format(self.options.perf))
        self.print_msg(self.V_DEBUG, ' Critical-pct:    {}'.format(self.options.critical_pct))
        self.print_msg(self.V_DEBUG, ' Warning-pct:     {}'.format(self.options.warning_pct))
        self.print_msg(self.V_DEBUG, ' Critical:        {}'.format(self.options.critical))
        self.print_msg(self.V_DEBUG, ' Warning:         {}'.format(self.options.warning))
        self.print_msg(self.V_DEBUG, ' Critical MOS:    {}'.format(self.options.critical_mos))
        self.print_msg(self.V_DEBUG, ' Warning MOS:     {}'.format(self.options.warning_mos))
        self.print_msg(self.V_DEBUG, ' Critical ICPIF:  {}'.format(self.options.critical_icpif))
        self.print_msg(self.V_DEBUG, ' Warning ICPIF:   {}'.format(self.options.warning_icpif))
        self.print_msg(self.V_DEBUG, ' Verbosity:       {}'.format(self.options.verbose))
        self.print_msg(self.V_DEBUG, '')

    def are_options_valid(self):
        if not self.options.hostname:
            print('You must specify a hostname')
            return False
        if not self.options.mode:
            print('You must specify a operation mode')
            return False
        if self.options.mode == 'check' and not self.options.entries:
            print('You must specify SLA-entries for check-mode (use list-mode to list existing entries)')
            return False
        if self.options.critical_mos and (self.options.critical_mos < 1 or self.options.critical_mos > 5):
            print('The critical-mos threshold value must lie between 1.00 and 5.00.')
            return False
        if self.options.warning_mos and (self.options.warning_mos < 1 or self.options.warning_mos > 5):
            print('The warning-mos threshold value must lie between 1.00 and 5.00.')
            return False
        return True

    def determine_requested_rtt_entries(self):
        if self.options.entries == 'all':
            self.requested_entries = self.rtt_dict.keys()
        else:
            self.requested_entries = self.options.entries.replace(' ', '').split(',')
        self.requested_entries.sort(key=int)

        self.print_msg(self.V_DEBUG, 'Requested entries: ' + ", ".join(self.requested_entries))

    def validate_requested_rtt_entries_types(self):
        """
        Checks if the list of requested rtt-types is valid. At this time, this means that the entries
        must be of the same type. If they are not, the performance data might be returned in an invalid form.
        Requires read_rtt_entries to have been called.
        :return: True if valid, False otherwise
        """
        # Create a list of all RTT types requested and their use-count
        rtt_type_usage_count = Counter()

        for requested_entry in self.requested_entries:
            if requested_entry not in self.rtt_dict:
                self.add_message('SLA {0} does not exist'.format(requested_entry))
                self.add_status(self.STATUS_UNKNOWN)
                return False

            rtt = self.rtt_dict[requested_entry]

            if not CiscoIpSlaChecker.is_rtt_type_supported(rtt.type):
                msg = 'SLA {0} is of type {1} ({2}) which is not supported (yet).'
                self.add_message(msg.format(requested_entry,
                                            rtt.type.description,
                                            rtt.type.id))
                self.add_status(self.STATUS_UNKNOWN)
                return False

            rtt_type_usage_count[rtt.type.id] += 1

        # For now, only checking of multiple SLA's is supported if they are all of the same type
        if len(rtt_type_usage_count) > 1:
            self.add_message('Checking multiple SLA entries is supported, but only if they are of the same type.')
            self.add_status(self.STATUS_UNKNOWN)
            return False

        return True

    def is_rtt_type_requested(self, rtt_type):
        # TODO Does this go well if rtt_type is already an RttType instance
        rtt_type = RttType(rtt_type)
        self.print_msg(self.V_DEBUG, 'Is entry type {} ({}) requested?'.format(rtt_type.description, rtt_type.id))

        for requested_entry in self.requested_entries:
            if requested_entry in self.rtt_dict:
                self.print_msg(self.V_DEBUG, 'Entry {} is of type {}'.format(
                    requested_entry,
                    self.rtt_dict[requested_entry].type)
                )
                if self.rtt_dict[requested_entry].type == rtt_type:
                    return True
        return False

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
        self.print_msg(self.V_DEBUG, 'Printing final output')
        output = ''
        if self.status == self.STATUS_OK:
            output = 'OK'
        elif self.status == self.STATUS_WARNING:
            output = 'Warning'
        elif self.status == self.STATUS_CRITICAL:
            output = 'Critical'
        elif self.status == self.STATUS_UNKNOWN:
            output = 'Unknown'

        if self.messages:
            if len(output):
                output += ' - '
            # Join messages like sentences. Correct those messages which already ended with a period or a newline.
            output += '. '.join(self.messages).replace('.. ', '.').replace('\n. ', '\n')

        if self.perfdata:
            if len(output):
                output += ' | '
            output += ' '.join(self.perfdata)

        print(output)

    def create_snmp_session(self):
        self.print_msg(self.V_DEBUG, 'Creating SNMP session')
        self.session = Session(
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

    def add_message(self, message, prepend=False):
        if prepend:
            self.messages.insert(0, message)
        else:
            self.messages.append(message)

    def add_perfdata(self, perfitem, prepend=False):
        if prepend:
            self.perfdata.insert(0, perfitem)
        else:
            self.perfdata.append(perfitem)

    def get_entry_output_id(self, entry):
        if len(self.requested_entries) > 1:
            entry_output_id = ' ' + entry
        else:
            entry_output_id = ''

        return entry_output_id

    @staticmethod
    def is_rtt_type_supported(rtt_type):
        """
        Returns whether or not the rtt-type is supported.
        This list of supported rtt-types is planned to be expanded
        :param rtt_type: The rtt-type in numeric, string or RttType form
        :return: True if the rtt-type is supported, False otherwise
        """
        supported_rtt_types = [
            RttType.ECHO,
            RttType.PATH_ECHO,
            RttType.JITTER,
            RttType.HTTP,
        ]
        if not isinstance(rtt_type, RttType):
            rtt_type = RttType(rtt_type)
        return rtt_type in supported_rtt_types

    def read_all_rtt_entry_basic_info(self):
        """ Reads all info on all RTT entries and stores found data in self.rtt_dict """
        self.print_msg(self.V_DEBUG, 'Reading basic rtt info for all entries')
        self.read_rtt_ctrl_admin_info()
        self.read_rtt_ctrl_oper_info()
        self.read_rtt_latest_oper_info()

    def read_rtt_ctrl_admin_info(self):
        self.print_msg(self.V_DEBUG, 'Starting SNMP-walk for rttMonCtrlAdminTable (.1.3.6.1.4.1.9.9.42.1.2.1.1)')
        rtt_ctrl_admin_entries = self.session.walk('.1.3.6.1.4.1.9.9.42.1.2.1.1')

        # Create an Rtt class in the rtt_dict of the correct type for each entry
        for item in rtt_ctrl_admin_entries:
            oid_parts = str(item.oid).split('.')
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if '4' == rtt_info_type:
                # rttMonCtrlAdminRttType (4)
                try:
                    self.rtt_dict[rtt_entry] = Rtt.rtt_factory(rtt_entry, item.value)
                except ValueError:
                    self.print_msg(self.V_DEBUG, 'Skipping unsupported rtt-type {}'.format(item.value))

        for item in rtt_ctrl_admin_entries:
            oid_parts = str(item.oid).split('.')
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if rtt_entry not in self.rtt_dict:
                self.print_msg(
                    self.V_INFO,
                    'Missing entry {} in rtt-list for oid {}.{}'.format(rtt_entry, item.oid, item.oid_index)
                )
                continue

            cur_rtt = self.rtt_dict[rtt_entry]

            try:
                if '2' == rtt_info_type:
                    # rttMonCtrlAdminOwner (2)
                    cur_rtt.owner = item.value
                elif '3' == rtt_info_type:
                    # rttMonCtrlAdminTag (3)
                    cur_rtt.tag = item.value
                elif '4' == rtt_info_type:
                    # rttMonCtrlAdminRttType (4)
                    pass

                elif '5' == rtt_info_type:
                    # rttMonCtrlAdminThreshold (5)
                    cur_rtt.threshold = item.value
                elif '12' == rtt_info_type:
                    # rttMonCtrlAdminLongTag (12)
                    cur_rtt.long_tag = item.value
            except ValueError as e:
                self.print_msg(
                    self.V_INFO,
                    'In read_rtt_ctrl_oper_info():\n'
                    ' Exception parsing type {} for {} with value {}\n'
                    ' {}'.format(rtt_info_type, rtt_entry, item.value, e)
                )

    def read_rtt_ctrl_oper_info(self):
        # Get SLA entry status
        self.print_msg(self.V_DEBUG, 'Starting SNMP-walk for rttMonCtrlOperTable (.1.3.6.1.4.1.9.9.42.1.2.9.1)')
        rtt_ctrl_oper_entries = self.session.walk('.1.3.6.1.4.1.9.9.42.1.2.9.1')
        for item in rtt_ctrl_oper_entries:
            oid_parts = str(item.oid).split('.')
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if rtt_entry not in self.rtt_dict:
                self.print_msg(
                    self.V_INFO,
                    'Missing entry {} in rtt-list for oid {}.{}'.format(rtt_entry, item.oid, item.oid_index)
                )
                continue

            cur_rtt = self.rtt_dict[rtt_entry]

            try:
                if '2' == rtt_info_type:
                    # rttMonCtrlOperDiagText (2)
                    cur_rtt.diag_text = item.value

                if '5' == rtt_info_type:
                    # rttMonCtrlOperConnectionLostOccurred (5)
                    cur_rtt.conn_lost_occurred = (item.value == '1')

                elif '6' == rtt_info_type:
                    # rttMonCtrlOperTimeoutOccurred (6)
                    cur_rtt.timeout_occurred = (item.value == '1')

                elif '7' == rtt_info_type:
                    # rttMonCtrlOperOverThresholdOccurred (7)
                    cur_rtt.over_thres_occurred = (item.value == '1')

                elif '10' == rtt_info_type:
                    # rttMonCtrlOperState (10)
                    # http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?local=en&translate=Translate&objectInput=1.3.6.1.4.1.9.9.42.1.2.9.1.10
                    cur_rtt.in_active_state = (item.value == '6')

            except ValueError as e:
                self.print_msg(
                    self.V_INFO,
                    'In read_rtt_ctrl_oper_info():\n'
                    ' Exception parsing type {} for {} with value {}\n'
                    ' {}'.format(rtt_info_type, rtt_entry, item.value, e)
                )

    def read_rtt_latest_oper_info(self):
        # Get SLA entry latest result
        self.print_msg(self.V_DEBUG, 'Starting SNMP-walk for rttMonLatestRttOperTable (.1.3.6.1.4.1.9.9.42.1.2.10.1)')
        latest_rtt_oper_entries = self.session.walk('.1.3.6.1.4.1.9.9.42.1.2.10.1')
        for item in latest_rtt_oper_entries:
            oid_parts = str(item.oid).split('.')
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if rtt_entry not in self.rtt_dict:
                self.print_msg(
                    self.V_INFO,
                    'Missing entry {} in rtt-list for oid {}.{}'.format(rtt_entry, item.oid, item.oid_index)
                )
                continue

            cur_rtt = self.rtt_dict[rtt_entry]

            try:
                if '1' == rtt_info_type:
                    # rttMonLatestRttOperCompletionTime (1)
                    cur_rtt.latest_completion_time = item.value

                elif '2' == rtt_info_type:
                    # rttMonLatestRttOperSense (2)
                    # See http://www.circitor.fr/Mibs/Html/CISCO-RTTMON-TC-MIB.php#RttResponseSense
                    cur_rtt.latest_sense = item.value

            except ValueError as e:
                self.print_msg(
                    self.V_INFO,
                    'In read_rtt_latest_oper_info():\n'
                    ' Exception parsing type {} for {} with value {}\n'
                    ' {}'.format(rtt_info_type, rtt_entry, item.value, e)
                )

    def read_rtt_http_entry_info(self):
        self.print_msg(self.V_DEBUG, 'Reading http-specific info for requested entries')
        # Get Http specific data (See '-- LatestHttpOper Table' in MIB)
        self.print_msg(self.V_DEBUG,
                       'Starting SNMP-walk for rttMonLatestHttpOperTable (.1.3.6.1.4.1.9.9.42.1.5.1.1)')
        latest_http_oper_entries = self.session.walk('.1.3.6.1.4.1.9.9.42.1.5.1.1')
        for item in latest_http_oper_entries:
            oid_parts = str(item.oid).split('.')
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if rtt_entry not in self.rtt_dict:
                self.print_msg(
                    self.V_INFO,
                    'Missing entry {} in rtt-list for oid {}.{}'.format(rtt_entry, item.oid, item.oid_index)
                )
                continue

            cur_rtt = self.rtt_dict[rtt_entry]

            try:
                if '1' == rtt_info_type:
                    # rttMonLatestHTTPOperRTT (1)
                    cur_rtt.latest_http.rtt = Decimal(item.value)

                if '2' == rtt_info_type:
                    # rttMonLatestHTTPOperDNSRTT (2)
                    cur_rtt.latest_http.rtt_dns = Decimal(item.value)

                if '3' == rtt_info_type:
                    # rttMonLatestHTTPOperTCPConnectRTT (3)
                    cur_rtt.latest_http.rtt_tcp_connect = Decimal(item.value)

                if '4' == rtt_info_type:
                    # rttMonLatestHTTPOperTransactionRTT (4)
                    cur_rtt.latest_http.rtt_trans = Decimal(item.value)

                if '5' == rtt_info_type:
                    # rttMonLatestHTTPOperMessageBodyOctets (5)
                    cur_rtt.latest_http.body_octets = Decimal(item.value)

                if '6' == rtt_info_type:
                    # rttMonLatestHTTPOperSense (6)
                    cur_rtt.latest_http.sense = int(item.value)

                if '7' == rtt_info_type:
                    # rttMonLatestHTTPErrorSenseDescription (7)
                    cur_rtt.latest_http.sense_description = str(item.value)

            except ValueError as e:
                self.print_msg(
                    self.V_INFO,
                    'In read_rtt_http_entry_info():\n'
                    ' Exception parsing type {} for {} with value {}\n'
                    ' {}'.format(rtt_info_type, rtt_entry, item.value, e)
                )

    def read_rtt_jitter_entry_info(self):
        self.print_msg(self.V_DEBUG, 'Reading jitter-specific info for all requested entries')

        # Get Jitter specific data (See '-- LatestJitterOper Table' in MIB)
        self.print_msg(self.V_DEBUG, 'Starting SNMP-walk for rttMonLatestJitterOperTable (.1.3.6.1.4.1.9.9.42.1.5.2.1)')
        latest_jitter_oper_entries = self.session.walk('.1.3.6.1.4.1.9.9.42.1.5.2.1')
        for item in latest_jitter_oper_entries:
            oid_parts = str(item.oid).split('.')
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if rtt_entry not in self.rtt_dict:
                self.print_msg(
                    self.V_INFO,
                    'Missing entry {} in rtt-list for oid {}.{}'.format(rtt_entry, item.oid, item.oid_index)
                )
                continue

            cur_rtt = self.rtt_dict[rtt_entry]

            try:
                if '1' == rtt_info_type:
                    # rttMonLatestJitterOperNumOfRTT (1)
                    cur_rtt.latest_jitter.num_of_rtt = item.value

                elif '2' == rtt_info_type:
                    # rttMonLatestJitterOperRTTSum (2)
                    cur_rtt.latest_jitter.rtt_sum = item.value

                elif '3' == rtt_info_type:
                    # rttMonLatestJitterOperRTTSum2 (3)
                    cur_rtt.latest_jitter.rtt_sum2 = item.value

                elif '4' == rtt_info_type:
                    # rttMonLatestJitterOperRTTMin (4)
                    cur_rtt.latest_jitter.rtt_min = item.value

                elif '5' == rtt_info_type:
                    # rttMonLatestJitterOperRTTMax (5)
                    cur_rtt.latest_jitter.rtt_max = item.value

                elif '6' == rtt_info_type:
                    # rttMonLatestJitterOperMinOfPositivesSD (6)
                    cur_rtt.latest_jitter.min_of_positives_SD = item.value

                elif '7' == rtt_info_type:
                    # rttMonLatestJitterOperMaxOfPositivesSD (7)
                    cur_rtt.latest_jitter.max_of_positives_sd = item.value

                elif '8' == rtt_info_type:
                    # rttMonLatestJitterOperNumOfPositivesSD (8)
                    cur_rtt.latest_jitter.num_of_positives_sd = item.value

                elif '11' == rtt_info_type:
                    # rttMonLatestJitterOperMinOfNegativesSD (11)
                    cur_rtt.latest_jitter.min_of_negatives_sd = item.value

                elif '12' == rtt_info_type:
                    # rttMonLatestJitterOperMaxOfNegativesSD (12)
                    cur_rtt.latest_jitter.max_of_negatives_sd = item.value

                elif '13' == rtt_info_type:
                    # rttMonLatestJitterOperNumOfNegativesSD (13)
                    cur_rtt.latest_jitter.num_of_negatives_sd = item.value

                elif '16' == rtt_info_type:
                    # rttMonLatestJitterOperMinOfPositivesDS (16)
                    cur_rtt.latest_jitter.min_of_positives_ds = item.value

                elif '17' == rtt_info_type:
                    # rttMonLatestJitterOperMaxOfPositivesDS (17)
                    cur_rtt.latest_jitter.max_of_positives_ds = item.value

                elif '18' == rtt_info_type:
                    # rttMonLatestJitterOperNumOfPositivesDS (18)
                    cur_rtt.latest_jitter.num_of_positives_ds = item.value

                elif '21' == rtt_info_type:
                    # rttMonLatestJitterOperMinOfNegativesDS (21)
                    cur_rtt.latest_jitter.min_of_negatives_ds = item.value

                elif '22' == rtt_info_type:
                    # rttMonLatestJitterOperMaxOfNegativesDS (22)
                    cur_rtt.latest_jitter.max_of_negatives_ds = item.value

                elif '23' == rtt_info_type:
                    # rttMonLatestJitterOperNumOfNegativesDS (23)
                    cur_rtt.latest_jitter.num_of_negatives_ds = item.value

                elif '26' == rtt_info_type:
                    # rttMonLatestJitterOperPacketLossSD (26)
                    cur_rtt.latest_jitter.packet_loss_sd = item.value

                elif '27' == rtt_info_type:
                    # rttMonLatestJitterOperPacketLossDS (27)
                    cur_rtt.latest_jitter.packet_loss_ds = item.value

                elif '28' == rtt_info_type:
                    # rttMonLatestJitterOperPacketOutOfSequence (28)
                    cur_rtt.latest_jitter.packet_out_of_seq = item.value

                elif '29' == rtt_info_type:
                    # rttMonLatestJitterOperPacketMIA (29)
                    cur_rtt.latest_jitter.packet_mia = item.value

                elif '30' == rtt_info_type:
                    # rttMonLatestJitterOperPacketLateArrival (30)
                    cur_rtt.latest_jitter.packet_late_arrival = item.value

                elif '31' == rtt_info_type:
                    # rttMonLatestJitterOperSense (31)
                    cur_rtt.latest_jitter.sense = item.value

                elif '32' == rtt_info_type:
                    # rttMonLatestJitterErrorSenseDescription (32)
                    cur_rtt.latest_jitter.sense_description = item.value

                # One way latency skipped

                elif '42' == rtt_info_type:
                    # rttMonLatestJitterOperMOS (42)
                    cur_rtt.latest_jitter.mos = item.value

                elif '43' == rtt_info_type:
                    # rttMonLatestJitterOperICPIF (43)
                    cur_rtt.latest_jitter.icpif = item.value

                elif '46' == rtt_info_type:
                    # rttMonLatestJitterOperAvgJitter (46)
                    cur_rtt.latest_jitter.avg_jitter = item.value

                elif '47' == rtt_info_type:
                    # rttMonLatestJitterOperAvgSDJ (47)
                    cur_rtt.latest_jitter.avg_jitter_sd = item.value

                elif '48' == rtt_info_type:
                    # rttMonLatestJitterOperAvgDSJ (48)
                    cur_rtt.latest_jitter.avg_jitter_ds = item.value

                elif '49' == rtt_info_type:
                    # rttMonLatestJitterOperOWAvgSD (49)
                    cur_rtt.latest_jitter.avg_latency_sd = item.value

                elif '50' == rtt_info_type:
                    # rttMonLatestJitterOperOWAvgDS (50)
                    cur_rtt.latest_jitter.avg_latency_ds = item.value

                elif '51' == rtt_info_type:
                    # rttMonLatestJitterOperNTPState (51)
                    cur_rtt.latest_jitter.ntp_sync = item.value

                elif '53' == rtt_info_type:
                    # rttMonLatestJitterOperRTTSumHigh (53)
                    cur_rtt.latest_jitter.rtt_sum_high = item.value

                elif '54' == rtt_info_type:
                    # rttMonLatestJitterOperRTTSum2High (54)
                    cur_rtt.latest_jitter.rtt_sum2_hig = item.value

                elif '59' == rtt_info_type:
                    # rttMonLatestJitterOperNumOverThresh (59)
                    cur_rtt.latest_jitter.num_over_threshold = item.value

            except ValueError as e:
                self.print_msg(
                    self.V_INFO,
                    'In read_rtt_jitter_entry_info():\n'
                    ' Exception parsing type {} for {} with value {}\n'
                    ' {}'.format(rtt_info_type, rtt_entry, item.value, e)
                )

    def list_rtt(self):
        """ Reads the list of available SLA entries for the device and prints out a list
        :return:
        """
        self.print_msg(self.V_DEBUG, 'Listing all rtt entries')
        sla_list = list()
        inactive_sla_list = list()

        col_width_id = 0
        col_width_type = 0
        col_width_tag = 0

        # Determine the column widths
        for rtt in self.rtt_dict.values():
            col_width_id = max(col_width_id, len(str(rtt.id)))
            col_width_type = max(col_width_type, len(rtt.type.description))
            if not rtt.active:
                col_width_tag = max(col_width_tag, len(rtt.tag))
            else:
                col_width_tag = max(col_width_tag, len(rtt.tag + ' (inactive)'))

        # for rtt_item in rtt_table:
        for rtt in self.rtt_dict:
            rtt_line = '  ' + rtt.id.rjust(col_width_id)
            rtt_line += '  ' + rtt.type.description.ljust(col_width_type)
            tag_text = str(rtt.tag)
            if not rtt.active:
                tag_text += ' (inactive)'
            rtt_line += '  ' + tag_text.strip()

            if rtt.active:
                sla_list.append(rtt_line)
            else:
                inactive_sla_list.append(rtt_line)

        # Add the inactive SLA's at the end of the list
        sla_list.extend(inactive_sla_list)

        col_headers = '  ' + 'ID'.rjust(col_width_id)
        col_headers += '  ' + 'Type'.ljust(col_width_type)
        col_headers += '  ' + 'Tag\n'
        col_headers += '  ' + ('-' * col_width_id)
        col_headers += '  ' + ('-' * col_width_type)
        col_headers += '  ' + ('-' * col_width_tag) + '\n'

        if len(sla_list) == 0:
            self.add_message('No SLAs available')
        else:
            self.set_message('SLAs available:\n')
            self.add_message(col_headers)
            for sla in sla_list:
                self.add_message(str(sla) + '\n')

    def check_http_health(self, requested_entry):
        """
        Checks if the latest http entry check went OK by it's sense value
        Can adjust the status and messages returned by the check
        :param requested_entry: The rtt-id in numeric form
        :return:
        """
        self.print_msg(self.V_DEBUG, 'Checking health for http entry')

        rtt = self.rtt_dict[requested_entry]
        if not isinstance(rtt, RttHttp):
            raise RuntimeError('collect_perfdata_http() requested for entry which is not of type RttHttp')

        if rtt.latest_http.sense == 15:  # httpError (15)
            self.add_status(self.STATUS_WARNING)
            self.add_message('HTTP error for SLA {0}. HTTP response: {1}'.format(
                rtt.description, rtt.latest_http.sense_description))
        elif rtt.latest_http.sense != 1:  # ok (1)
            self.add_status(self.STATUS_WARNING)
            self.add_message('Latest http operation not ok for SLA {0}. Description: {1}'.format(
                rtt.description, rtt.latest_http.sense_description))

        # TODO Needs to be implemented
        # Check rtt thresholds (if set)
        # if self.options.critical_mos is not None or self.options.warning_mos is not None:
        #     if latest_http['MOS'] is None:
        #         self.add_status(self.STATUS_UNKNOWN)
        #         self.add_message('MOS not known for SLA {0}, but threshold is set'.format(rtt_id))
        #     elif self.options.critical_mos is not None and latest_http['MOS'] <= self.options.critical_mos:
        #         self.add_status(self.STATUS_CRITICAL)
        #         self.add_message('MOS is under critical threshold for SLA {0}'.format(rtt_id))
        #     elif self.options.warning_mos is not None and latest_http['MOS'] <= self.options.warning_mos:
        #         self.add_status(self.STATUS_WARNING)
        #         self.add_message('MOS is under warning threshold for SLA {0}'.format(rtt_id))

    def collect_perfdata_http(self, requested_entry):
        """
        Collect and save perf-data for the rtt so it gets returned by this check
        Will adjust the perfdata returned by the check
        :param requested_entry: The rtt-id in numeric form
        :return:
        """
        self.print_msg(self.V_DEBUG, 'Collecting perfdata for http entry')

        rtt = self.rtt_dict.get(requested_entry)
        if not isinstance(rtt, RttHttp):
            raise RuntimeError('collect_perfdata_http() requested for entry which is not of type RttHttp')

        self.add_perfdata("'DNS rtt{entry}'={v}ms".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_http.rtt_dns
        ))
        self.add_perfdata("'TCP connect rtt{entry}'={v}ms".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_http.rtt_tcp_connect
        ))
        self.add_perfdata("'Transaction rtt{entry}'={v}ms".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_http.rtt_trans
        ))
        self.add_perfdata("'Total rtt{entry}'={v}ms".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_http.rtt
        ))

    def check_jitter_health(self, requested_entry):
        """
        Checks if the latest jitter entry check went OK by it's sense value,
        if time is synced between the source and destination
        and checks the MOS and ICPIF thresholds if they are set.
        Can adjust the status and messages returned by the check
        :param requested_entry: The rtt-id in numeric form
        :return:
        """
        self.print_msg(self.V_DEBUG, 'Checking health for jitter entry')

        rtt = self.rtt_dict.get(requested_entry)
        if not isinstance(rtt, RttJitter):
            raise RuntimeError('check_jitter_health() requested for entry which is not of type RttJitter')

        if rtt.latest_jitter.sense != 1:  # ok (1)
            self.add_status(self.STATUS_WARNING)
            self.add_message('Latest jitter operation not ok for SLA {0}: {1}'.format(
                rtt.description, rtt.latest_jitter.sense_description))

        if not rtt.latest_jitter.ntp_sync:
            self.add_status(self.STATUS_WARNING)
            self.add_message('NTP not synced between source and destination for SLA {0}'.format(rtt.description))

        # Check MOS thresholds (if set)
        if self.options.critical_mos is not None or self.options.warning_mos is not None:
            if rtt.latest_jitter.mos is None:
                self.add_status(self.STATUS_UNKNOWN)
                self.add_message('MOS not known for SLA {0}, but threshold is set'.format(rtt.description))
            elif self.options.critical_mos is not None and rtt.latest_jitter.mos <= self.options.critical_mos:
                self.add_status(self.STATUS_CRITICAL)
                self.add_message('MOS is under critical threshold for SLA {0}'.format(rtt.description))
            elif self.options.warning_mos is not None and rtt.latest_jitter.mos <= self.options.warning_mos:
                self.add_status(self.STATUS_WARNING)
                self.add_message('MOS is under warning threshold for SLA {0}'.format(rtt.description))

        # Check ICPIF thresholds (if set)
        if self.options.critical_icpif is not None or self.options.warning_icpif is not None:
            if rtt.latest_jitter.icpif is None:
                self.add_status(self.STATUS_UNKNOWN)
                self.add_message('ICPIF not known for SLA {0}, but threshold is set'.format(rtt.description))
            elif self.options.critical_icpif is not None and rtt.latest_jitter.icpif >= self.options.critical_icpif:
                self.add_status(self.STATUS_CRITICAL)
                self.add_message('ICPIF is over critical threshold for SLA {0}'.format(rtt.description))
            elif self.options.warning_icpif is not None and rtt.latest_jitter.icpif >= self.options.warning_icpif:
                self.add_status(self.STATUS_WARNING)
                self.add_message('ICPIF is over warning threshold for SLA {0}'.format(rtt.description))

    def collect_perfdata_jitter(self, requested_entry):
        """
        Collect and save perf-data for the rtt so it gets returned by this check
        Will adjust the perfdata returned by the check
        :param requested_entry: The rtt-id in numeric form
        :return:
        """
        self.print_msg(self.V_DEBUG, 'Collecting perfdata for jitter entry')

        rtt = self.rtt_dict.get(requested_entry)
        if not isinstance(rtt, RttJitter):
            raise RuntimeError('check_jitter_health() requested for entry which is not of type RttJitter')

        if rtt.latest_jitter.num_of_rtt > 1:
            self.add_perfdata("'RTT avg{entry}'={avg}ms;{min};{max}".format(
                entry=self.get_entry_output_id(rtt.id),
                avg=round(rtt.latest_jitter.rtt_sum / (rtt.latest_jitter.num_of_rtt - 1), 1),
                min=rtt.latest_jitter.rtt_min,
                max=rtt.latest_jitter.rtt_max
            ))
            self.add_perfdata("'RTT variance{entry}'={var}".format(
                entry=self.get_entry_output_id(rtt.id),
                var=round(rtt.latest_jitter.rtt_sum2 / (rtt.latest_jitter.num_of_rtt - 1), 1),
            ))
            self.add_perfdata("'RTT std dev{entry}'={var}".format(
                entry=self.get_entry_output_id(rtt.id),
                var=round(math.sqrt(rtt.latest_jitter.rtt_sum2 / (rtt.latest_jitter.num_of_rtt - 1)), 1),
            ))

        self.add_perfdata("'Avg jitter{entry}'={v}".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_jitter.avg_jitter
        ))
        self.add_perfdata("'Avg jitter SD{entry}'={v}".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_jitter.avg_jitter_sd
        ))
        self.add_perfdata("'Avg jitter DS{entry}'={v}".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_jitter.avg_jitter_ds
        ))
        self.add_perfdata("'Avg latency SD{entry}'={v}".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_jitter.avg_latency_sd
        ))
        self.add_perfdata("'Avg latency DS{entry}'={v}".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_jitter.avg_latency_ds
        ))
        self.add_perfdata("'MOS{entry}'={v}".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_jitter.mos
        ))
        self.add_perfdata("'ICPIF{entry}'={v}".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_jitter.icpif
        ))
        self.add_perfdata("'Packet loss SD{entry}'={v}".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_jitter.packet_loss_sd
        ))
        self.add_perfdata("'Packet loss DS{entry}'={v}".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_jitter.packet_loss_ds
        ))
        self.add_perfdata("'Packet out of seq{entry}'={v}".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_jitter.packet_out_of_seq
        ))
        self.add_perfdata("'Packet MIA{entry}'={v}".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_jitter.packet_mia
        ))
        self.add_perfdata("'Packet late arrival{entry}'={v}".format(
            entry=self.get_entry_output_id(rtt.id),
            v=rtt.latest_jitter.packet_late_arrival
        ))
        if rtt.latest_jitter.num_over_threshold is not None:
            self.add_perfdata("'Num over threshold{entry}'={v}".format(
                entry=self.get_entry_output_id(rtt.id),
                v=rtt.latest_jitter.num_over_threshold
            ))


class RttType:
    ECHO = 1
    PATH_ECHO = 2
    FILE_IO = 3
    SCRIPT = 4
    UDP_ECHO = 5
    TCP_CONNECT = 6
    HTTP = 7
    DNS = 8
    JITTER = 9
    DLSW = 10
    DHCP = 11
    FTP = 12
    VOIP = 13
    RTP = 14
    LSP_GROUP = 15
    ICMP_JITTER = 16
    LSP_PING = 17
    LSP_TRACE = 18
    ETHERNET_PING = 19
    ETHERNET_JITTER = 20
    LSP_PING_PSEUDOWIRE = 21

    rtt_types = {
        ECHO: 'echo',
        PATH_ECHO: 'pathEcho',
        FILE_IO: 'fileIO',
        SCRIPT: 'script',
        UDP_ECHO: 'udpEcho',
        TCP_CONNECT: 'tcpConnect',
        HTTP: 'http',
        DNS: 'dns',
        JITTER: 'jitter',
        DLSW: 'dlsw',
        DHCP: 'dhcp',
        FTP: 'ftp',
        VOIP: 'voip',
        RTP: 'rtp',
        LSP_GROUP: 'lspGroup',
        ICMP_JITTER: 'icmpJitter',
        LSP_PING: 'lspPing',
        LSP_TRACE: 'lspTrace',
        ETHERNET_PING: 'ethernetPing',
        ETHERNET_JITTER: 'ethernetJitter',
        LSP_PING_PSEUDOWIRE: 'lspPingPseudowire',
    }

    def __init__(self, rtt_type):
        try:
            rtt_type_id = int(rtt_type)
        except ValueError:
            rtt_type_id = RttType.id_from_description(rtt_type)

        if int(rtt_type_id) in self.rtt_types:
            self._type_id = int(rtt_type_id)
        else:
            raise ValueError('Invalid rtt-type')

    def __eq__(self, other):
        if not isinstance(other, RttType):
            other = RttType(other)
        return self.id == other.id

    def __ne__(self, other):
        if not isinstance(other, RttType):
            other = RttType(other)
        return self.id != other.id

    def __str__(self):
        return self.description

    def __repr__(self):
        return 'RttType(id=' + self.id + ', description=' + self.description + ')'

    @property
    def description(self):
        return RttType.description_from_id(self._type_id)

    @property
    def id(self):
        return self._type_id

    @staticmethod
    def id_from_description(rtt_type_description):
        """
        Get the numeric equivalent of an rtt-type represented as a astring
        :param rtt_type_description: The rtt-type in string form
        :return: The numeric form of the rtt-type or 0 if no match was found
        """
        for rtt_type_id in RttType.rtt_types:
            if rtt_type_description == RttType.rtt_types[rtt_type_id]:
                return rtt_type_id
        return 0

    @staticmethod
    def description_from_id(rtt_type_id):
        """
        Get the string equivalent of a numeric rtt-type
        :param rtt_type_id: The rtt-type in numeric form as returned by an SNMP request
        :return: A string describing the rtt-type or 'Unknown' if no match was found
        """
        rtt_type_id = int(rtt_type_id)
        description = 'unknown'
        if rtt_type_id in RttType.rtt_types:
            description = RttType.rtt_types[rtt_type_id]
        return description


class Rtt:
    def __init__(self, id):
        self._id = id
        self._owner = None
        self._tag = None
        self._type = None
        self._threshold = None
        self._long_tag = None
        self._diag_text = None
        self._conn_lost_occurred = None
        self._timeout_occurred = None
        self._over_thres_occurred = None
        self._latest_completion_time = None
        self._latest_sense = None
        pass

    @staticmethod
    def rtt_factory(rtt_id, rtt_type):
        if not isinstance(rtt_type, RttType):
            rtt_type = RttType(rtt_type)

        if rtt_type == RttType.ECHO or rtt_type == RttType.PATH_ECHO or rtt_type == RttType.UDP_ECHO:
            return RttEcho(rtt_id, rtt_type)
        elif rtt_type == RttType.JITTER or rtt_type == RttType.ICMP_JITTER:
            return RttJitter(rtt_id, rtt_type)
        elif rtt_type == RttType.HTTP:
            return RttHttp(rtt_id, rtt_type)
        else:
            raise ValueError('Unsupported rtt-type')

    @property
    def description(self):
        """
        Get a human readable description identifying this SLA entry
        Consisting of the id and the tag if set
        :return: A string describing the SLA
        """
        sla_description = str(self.id)
        if self.tag:
            sla_description += ' (tag: {0})'.format(self.tag)

        return sla_description

    @property
    def id(self):
        return self._id

    @property
    def owner(self):
        return self._owner

    @owner.setter
    def owner(self, value):
        self._owner = str(value)

    @property
    def tag(self):
        return self._tag

    @tag.setter
    def tag(self, value):
        self._tag = str(value)

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        if isinstance(value, RttType):
            self._type = value
        else:
            raise ValueError('Invalid rtt-type')

    @property
    def threshold(self):
        return self._threshold

    @threshold.setter
    def threshold(self, value):
        self._threshold = int(value)

    @property
    def long_tag(self):
        return self._long_tag

    @long_tag.setter
    def long_tag(self, value):
        self._long_tag = str(value)

    @property
    def diag_text(self):
        return self._diag_text

    @diag_text.setter
    def diag_text(self, value):
        self._diag_text = str(value)

    @property
    def conn_lost_occurred(self):
        return self._conn_lost_occurred

    @conn_lost_occurred.setter
    def conn_lost_occurred(self, value):
        self._conn_lost_occurred = bool(value)

    @property
    def timeout_occurred(self):
        return self._timeout_occurred

    @timeout_occurred.setter
    def timeout_occurred(self, value):
        self._timeout_occurred = bool(value)

    @property
    def over_thres_occurred(self):
        return self._over_thres_occurred

    @over_thres_occurred.setter
    def over_thres_occurred(self, value):
        self._over_thres_occurred = bool(value)

    @property
    def latest_completion_time(self):
        return self._latest_completion_time

    @latest_completion_time.setter
    def latest_completion_time(self, value):
        self._latest_completion_time = int(value)

    @property
    def latest_sense(self):
        return self._latest_sense

    @latest_sense.setter
    def latest_sense(self, value):
        self._latest_sense = int(value)


class RttEcho(Rtt):
    def __init__(self, id, rtt_type):
        Rtt.__init__(self, id)
        self.type = rtt_type


class RttJitter(Rtt):
    def __init__(self, id, rtt_type):
        Rtt.__init__(self, id)
        self.type = rtt_type
        self.latest_jitter = self.LatestJitter()

    class LatestJitter:
        def __init__(self):
            self._num_of_rtt = None
            self._rtt_sum = None
            self._rtt_sum2 = None
            self._rtt_min = None
            self._rtt_max = None
            self._min_of_positives_sd = None
            self._max_of_positives_sd = None
            self._num_of_positives_sd = None
            self._min_of_negatives_sd = None
            self._max_of_negatives_sd = None
            self._num_of_negatives_sd = None
            self._min_of_positives_ds = None
            self._max_of_positives_ds = None
            self._num_of_positives_ds = None
            self._min_of_negatives_ds = None
            self._max_of_negatives_ds = None
            self._num_of_negatives_ds = None
            self._packet_loss_sd = None
            self._packet_loss_ds = None
            self._packet_out_of_seq = None
            self._packet_mia = None
            self._packet_late_arrival = None
            self._sense = None
            self._sense_description = None
            self._mos = None
            self._icpif = None
            self._avg_jitter = None
            self._avg_jitter_sd = None
            self._avg_jitter_ds = None
            self._avg_latency_sd = None
            self._avg_latency_ds = None
            self._ntp_sync = None
            self._rtt_sum_high = None
            self._rtt_sum2_high = None
            self._num_over_threshold = None

        @property
        def num_of_rtt(self):
            return self._num_of_rtt

        @num_of_rtt.setter
        def num_of_rtt(self, value):
            self._num_of_rtt = Decimal(value)

        @property
        def rtt_sum(self):
            if self._rtt_sum is None:
                return None
            if self._rtt_sum_high > 0:
                # Merge high- and low bits for applicable fields
                return self._rtt_sum + (self._rtt_sum_high << 32)
            else:
                return self._rtt_sum

        @rtt_sum.setter
        def rtt_sum(self, value):
            self._rtt_sum = Decimal(value)

        @property
        def rtt_sum2(self):
            if self._rtt_sum2 is None:
                return None
            if self._rtt_sum2_high > 0:
                # Merge high- and low bits for applicable fields
                return self._rtt_sum2 + (self._rtt_sum2_high << 32)
            else:
                return self._rtt_sum2

        @rtt_sum2.setter
        def rtt_sum2(self, value):
            self._rtt_sum2 = Decimal(value)

        @property
        def rtt_min(self):
            return self._rtt_min

        @rtt_min.setter
        def rtt_min(self, value):
            self._rtt_min = Decimal(value)

        @property
        def rtt_max(self):
            return self._rtt_max

        @rtt_max.setter
        def rtt_max(self, value):
            self._rtt_max = Decimal(value)

        @property
        def min_of_positives_sd(self):
            return self._min_of_positives_sd

        @min_of_positives_sd.setter
        def min_of_positives_sd(self, value):
            self._min_of_positives_sd = Decimal(value)

        @property
        def max_of_positives_sd(self):
            return self._max_of_positives_sd

        @max_of_positives_sd.setter
        def max_of_positives_sd(self, value):
            self._max_of_positives_sd = Decimal(value)

        @property
        def num_of_positives_sd(self):
            return self._num_of_positives_sd

        @num_of_positives_sd.setter
        def num_of_positives_sd(self, value):
            self._num_of_positives_sd = Decimal(value)

        @property
        def min_of_negatives_sd(self):
            return self._min_of_negatives_sd

        @min_of_negatives_sd.setter
        def min_of_negatives_sd(self, value):
            self._min_of_negatives_sd = Decimal(value)

        @property
        def max_of_negatives_sd(self):
            return self._max_of_negatives_sd

        @max_of_negatives_sd.setter
        def max_of_negatives_sd(self, value):
            self._max_of_negatives_sd = Decimal(value)

        @property
        def num_of_negatives_sd(self):
            return self._num_of_negatives_sd

        @num_of_negatives_sd.setter
        def num_of_negatives_sd(self, value):
            self._num_of_negatives_sd = Decimal(value)

        @property
        def min_of_positives_ds(self):
            return self._min_of_positives_ds

        @min_of_positives_ds.setter
        def min_of_positives_ds(self, value):
            self._min_of_positives_ds = Decimal(value)

        @property
        def max_of_positives_ds(self):
            return self._max_of_positives_ds

        @max_of_positives_ds.setter
        def max_of_positives_ds(self, value):
            self._max_of_positives_ds = Decimal(value)

        @property
        def num_of_positives_ds(self):
            return self._num_of_positives_ds

        @num_of_positives_ds.setter
        def num_of_positives_ds(self, value):
            self._num_of_positives_ds = Decimal(value)

        @property
        def min_of_negatives_ds(self):
            return self._min_of_negatives_ds

        @min_of_negatives_ds.setter
        def min_of_negatives_ds(self, value):
            self._min_of_negatives_ds = Decimal(value)

        @property
        def max_of_negatives_ds(self):
            return self._max_of_negatives_ds

        @max_of_negatives_ds.setter
        def max_of_negatives_ds(self, value):
            self._max_of_negatives_ds = Decimal(value)

        @property
        def num_of_negatives_ds(self):
            return self._num_of_negatives_ds

        @num_of_negatives_ds.setter
        def num_of_negatives_ds(self, value):
            self._num_of_negatives_ds = Decimal(value)

        @property
        def packet_loss_sd(self):
            return self._packet_loss_sd

        @packet_loss_sd.setter
        def packet_loss_sd(self, value):
            self._packet_loss_sd = Decimal(value)

        @property
        def packet_loss_ds(self):
            return self._packet_loss_ds

        @packet_loss_ds.setter
        def packet_loss_ds(self, value):
            self._packet_loss_ds = Decimal(value)

        @property
        def packet_out_of_seq(self):
            return self._packet_out_of_seq

        @packet_out_of_seq.setter
        def packet_out_of_seq(self, value):
            self._packet_out_of_seq = Decimal(value)

        @property
        def packet_mia(self):
            return self._packet_mia

        @packet_mia.setter
        def packet_mia(self, value):
            self._packet_mia = Decimal(value)

        @property
        def packet_late_arrival(self):
            return self._packet_late_arrival

        @packet_late_arrival.setter
        def packet_late_arrival(self, value):
            self._packet_late_arrival = Decimal(value)

        @property
        def sense(self):
            return self._sense

        @sense.setter
        def sense(self, value):
            self._sense = int(value)

        @property
        def sense_description(self):
            return self._sense_description

        @sense_description.setter
        def sense_description(self, value):
            self._sense_description = str(value)

        @property
        def mos(self):
            return self._mos

        @mos.setter
        def mos(self, value):
            mos = Decimal(value)
            if mos >= 100:
                mos = mos / 100
            self._mos = mos

        @property
        def icpif(self):
            return self._icpif

        @icpif.setter
        def icpif(self, value):
            self._icpif = Decimal(value)

        @property
        def avg_jitter(self):
            return self._avg_jitter

        @avg_jitter.setter
        def avg_jitter(self, value):
            self._avg_jitter = Decimal(value)

        @property
        def avg_jitter_sd(self):
            return self._avg_jitter_sd

        @avg_jitter_sd.setter
        def avg_jitter_sd(self, value):
            self._avg_jitter_sd = Decimal(value)

        @property
        def avg_jitter_ds(self):
            return self._avg_jitter_ds

        @avg_jitter_ds.setter
        def avg_jitter_ds(self, value):
            self._avg_jitter_ds = Decimal(value)

        @property
        def avg_latency_sd(self):
            return self._avg_latency_sd

        @avg_latency_sd.setter
        def avg_latency_sd(self, value):
            self._avg_latency_sd = Decimal(value)

        @property
        def avg_latency_ds(self):
            return self._avg_latency_ds

        @avg_latency_ds.setter
        def avg_latency_ds(self, value):
            self._avg_latency_ds = Decimal(value)

        @property
        def ntp_sync(self):
            return self._ntp_sync

        @ntp_sync.setter
        def ntp_sync(self, value):
            self._ntp_sync = (int(value) == 1)

        @property
        def rtt_sum_high(self):
            return self._rtt_sum_high

        @rtt_sum_high.setter
        def rtt_sum_high(self, value):
            self._rtt_sum_high = Decimal(value)

        @property
        def rtt_sum2_high(self):
            return self._rtt_sum2_high

        @rtt_sum2_high.setter
        def rtt_sum2_high(self, value):
            self._rtt_sum2_high = Decimal(value)

        @property
        def num_over_threshold(self):
            return self._num_over_threshold

        @num_over_threshold.setter
        def num_over_threshold(self, value):
            self._num_over_threshold = Decimal(value)

        def __repr__(self):
            repr_str = 'LatestJitter('
            repr_str += 'num_of_rtt=' + str(self.num_of_rtt)
            repr_str += ', rtt_sum=' + str(self.rtt_sum)
            repr_str += ', rtt_sum2' + str(self.rtt_sum2)
            repr_str += ', rtt_min=' + str(self.rtt_min)
            repr_str += ', rtt_max=' + str(self.rtt_max)
            repr_str += ', min_of_positives_sd=' + str(self.min_of_positives_sd)
            repr_str += ', max_of_positives_sd=' + str(self.max_of_positives_sd)
            repr_str += ', num_of_positives_sd=' + str(self.num_of_positives_sd)
            repr_str += ', min_of_negatives_sd=' + str(self.min_of_negatives_sd)
            repr_str += ', max_of_negatives_sd=' + str(self.max_of_negatives_sd)
            repr_str += ', num_of_negatives_sd=' + str(self.num_of_negatives_sd)
            repr_str += ', min_of_positives_ds=' + str(self.min_of_positives_ds)
            repr_str += ', max_of_positives_ds=' + str(self.max_of_positives_ds)
            repr_str += ', num_of_positives_ds=' + str(self.num_of_positives_ds)
            repr_str += ', min_of_negatives_ds=' + str(self.min_of_negatives_ds)
            repr_str += ', max_of_negatives_ds=' + str(self.max_of_negatives_ds)
            repr_str += ', num_of_negatives_ds=' + str(self.num_of_negatives_ds)
            repr_str += ', packet_loss_sd=' + str(self.packet_loss_sd)
            repr_str += ', packet_loss_ds=' + str(self.packet_loss_ds)
            repr_str += ', packet_out_of_seq=' + str(self.packet_out_of_seq)
            repr_str += ', packet_mia=' + str(self.packet_mia)
            repr_str += ', packet_late_arrival=' + str(self.packet_late_arrival)
            repr_str += ', sense=' + str(self.sense)
            repr_str += ', sense_description=' + str(self.sense_description)
            repr_str += ', mos=' + str(self.mos)
            repr_str += ', icpif=' + str(self.icpif)
            repr_str += ', avg_jitter=' + str(self.avg_jitter)
            repr_str += ', avg_jitter_sd=' + str(self.avg_jitter_sd)
            repr_str += ', avg_jitter_ds=' + str(self.avg_jitter_ds)
            repr_str += ', avg_latency_sd=' + str(self.avg_latency_sd)
            repr_str += ', avg_latency_ds=' + str(self.avg_latency_ds)
            repr_str += ', ntp_sync=' + str(self.ntp_sync)
            repr_str += ', rtt_sum_high=' + str(self.rtt_sum_high)
            repr_str += ', rtt_sum2_high=' + str(self.rtt_sum2_high)
            repr_str += ', num_over_threshold=' + str(self.num_over_threshold)
            repr_str += ')'
            return repr_str


class RttHttp(Rtt):
    def __init__(self, id, rtt_type):
        Rtt.__init__(self, id)
        self.type = rtt_type
        self.latest_http = self.LatestHttp()

    class LatestHttp:
        def __init__(self):
            self._rtt = None
            self._rtt_dns = None
            self._rtt_tcp_connect = None
            self._rtt_trans = None
            self._body_octets = None
            self._sense = None
            self._sense_description = None
            pass

        @property
        def rtt(self):
            return self._rtt

        @rtt.setter
        def rtt(self, value):
            self._rtt = Decimal(value)

        @property
        def rtt_dns(self):
            return self._rtt_dns

        @rtt_dns.setter
        def rtt_dns(self, value):
            self._rtt_dns = Decimal(value)

        @property
        def rtt_tcp_connect(self):
            return self._rtt_tcp_connect

        @rtt_tcp_connect.setter
        def rtt_tcp_connect(self, value):
            self._rtt_tcp_connect = Decimal(value)

        @property
        def rtt_trans(self):
            return self._rtt_trans

        @rtt_trans.setter
        def rtt_trans(self, value):
            self._rtt_trans = Decimal(value)

        @property
        def body_octets(self):
            return self._body_octets

        @body_octets.setter
        def body_octets(self, value):
            self._body_octets = Decimal(value)

        @property
        def sense(self):
            return self._sense

        @sense.setter
        def sense(self, value):
            self._sense = int(value)

        @property
        def sense_description(self):
            return self._sense_description

        @sense_description.setter
        def sense_description(self, value):
            self._sense_description = str(value)

        def __repr__(self):
            repr_str = 'LatestHttp('
            repr_str += 'rtt=' + str(self.rtt)
            repr_str += ', rtt_dns=' + str(self.rtt_dns)
            repr_str += ', rtt_tcp_connect=' + str(self.rtt_tcp_connect)
            repr_str += ', rtt_trans=' + str(self.rtt_trans)
            repr_str += ', body_octets=' + str(self.body_octets)
            repr_str += ', sense=' + str(self.sense)
            repr_str += ', sense_description=' + str(self.sense_description)
            repr_str += ')'
            return repr_str


if __name__ == '__main__':
    checker = CiscoIpSlaChecker()
    checker.run()
    exit(checker.status)
