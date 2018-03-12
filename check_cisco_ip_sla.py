#!/usr/bin/python

# -*- coding: utf-8 -*-

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
import math
from decimal import *
from collections import Counter
from easysnmp import Session
from easysnmp.exceptions import *
import logging

__author__ = 'Maarten Hoogveld'
__version__ = '1.2.0'
__email__ = 'maarten@hoogveld.org'
__licence__ = 'GPL-3.0'
__status__ = 'Production'


class CiscoIpSlaChecker(object):
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
        self.status = NagiosStatus()
        self.messages = []
        self.perfdata = []
        self.session = None
        self.options = None

        # A dictionary containing all info obtained through SNMP for every rtt (requested or not)
        self.rtt_dict = dict()

        # A list of all RTT id's requested (strings of numeric id's)
        self.requested_entries = []

    def run(self):
        self.parse_options()

        # Sets the self.requested_entries dict
        if 'check' == self.options.mode:
            self.determine_requested_rtt_entries()

        try:
            self.create_snmp_session()
            self.read_all_rtt_entry_basic_info()

            if 'list' == self.options.mode:
                self.list_rtt()
            elif 'check' == self.options.mode:
                self.check()
        except EasySNMPError as e:
            self.status.add(NagiosStatus.UNKNOWN)
            self.set_message('SNMP error checking {}, {}'.format(self.options.hostname, e))

        self.print_output()
        return

    @staticmethod
    def init_logging(verbosity):
        logging_format = '%(levelname)s: %(message)s'
        level = logging.WARNING
        if verbosity == CiscoIpSlaChecker.V_INFO:
            level = logging.INFO
        elif verbosity == CiscoIpSlaChecker.V_DEBUG:
            level = logging.DEBUG

        logging.basicConfig(format=logging_format, level=level)

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
        parser.add_argument('--critical',
                            default=None, type=int, help='Critical threshold in amount of failed SLAs')
        parser.add_argument('--warning',
                            default=None, type=int, help='Warning threshold in amount of failed SLAs')
        parser.add_argument('--critical-failed-pct',
                            default=None, type=float,
                            help='Critical threshold in percentage of failed SLAs (default "100")')
        parser.add_argument('--warning-failed-pct',
                            default=None, type=float,
                            help='Warning threshold in percentage of failed SLAs (default "50")')
        parser.add_argument('--critical-failed-count',
                            default=None, type=int, help='Critical threshold in amount of failed SLAs')
        parser.add_argument('--warning-failed-count',
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

        try:
            self.options = parser.parse_args()
        except DecimalException:
            print('Error parsing Decimal command-line options, probably one of the MOS thresholds.\n'
                  'Run with --help for usage information')
            print('')
            exit(int(self.status))

        self.init_logging(self.options.verbose)
        logger = logging.getLogger()

        # Set default warning and critical levels if they are not specified at all
        if self.options.critical_failed_count is None and self.options.critical_failed_pct is None:
            self.options.critical_failed_pct = 100
        if self.options.warning_failed_count is None and self.options.warning_failed_pct is None:
            self.options.warning_failed_pct = 50

        # Copy password to auth-password and priv-password if applicable
        if self.options.auth_password is None and self.options.password is not None:
            self.options.auth_password = self.options.password
        if self.options.priv_password is None and self.options.password is not None:
            self.options.priv_password = self.options.password

        if not self.are_options_valid():
            print('Run with --help for usage information')
            print('')
            exit(int(self.status))

        logger.debug('Using parameters:')
        logger.debug(' Hostname:               {}'.format(self.options.hostname))
        logger.debug(' SNMP-version:           {}'.format(self.options.snmp_version))
        logger.debug(' Community:              {}'.format(self.options.community))
        logger.debug(' Security-name:          {}'.format(self.options.security_name))
        logger.debug(' Security-level:         {}'.format(self.options.security_level))
        logger.debug(' Password:               {}'.format(self.options.password))
        logger.debug(' Auth-protocol:          {}'.format(self.options.auth_protocol))
        logger.debug(' Auth-password:          {}'.format(self.options.auth_password))
        logger.debug(' Priv-protocol:          {}'.format(self.options.priv_protocol))
        logger.debug(' Priv-password:          {}'.format(self.options.priv_password))
        logger.debug(' Mode:                   {}'.format(self.options.mode))
        logger.debug(' SLA entries:            {}'.format(self.options.entries))
        logger.debug(' Perf-data:              {}'.format(self.options.perf))
        logger.debug(' Critical:               {}'.format(self.options.critical))
        logger.debug(' Warning:                {}'.format(self.options.warning))
        logger.debug(' Critical-failed-pct:    {}'.format(self.options.critical_failed_pct))
        logger.debug(' Warning-failed-pct:     {}'.format(self.options.warning_failed_pct))
        logger.debug(' Critical-failed-count:  {}'.format(self.options.critical_failed_count))
        logger.debug(' Warning-failed-count:   {}'.format(self.options.warning_failed_count))
        logger.debug(' Critical MOS:           {}'.format(self.options.critical_mos))
        logger.debug(' Warning MOS:            {}'.format(self.options.warning_mos))
        logger.debug(' Critical ICPIF:         {}'.format(self.options.critical_icpif))
        logger.debug(' Warning ICPIF:          {}'.format(self.options.warning_icpif))
        logger.debug(' Verbosity:              {}'.format(self.options.verbose))
        logger.debug('')

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
        if self.options.critical is not None and self.options.warning is not None:
            if self.options.critical <= self.options.warning:
                print('The critical threshold value must be larger than the warning threshold.')
                return False
        if self.options.critical_failed_pct is not None and self.options.warning_failed_pct is not None:
            if self.options.critical_failed_pct <= self.options.warning_failed_pct:
                print('The critical threshold value must be larger than the warning threshold '
                      'for the percentage of failed SLAs.')
                return False
        if self.options.critical_failed_count is not None and self.options.warning_failed_count is not None:
            if self.options.critical_failed_count <= self.options.warning_failed_count:
                print('The critical threshold value must be larger than the warning threshold '
                      'for the number of failed SLAs.')
                return False
        if self.options.critical_mos is not None and self.options.warning_mos is not None:
            if self.options.critical_mos <= self.options.warning_mos:
                print('The critical threshold value must be larger than the warning threshold '
                      'for the MOS value.')
                return False
        if self.options.critical_mos is not None and (self.options.critical_mos < 1 or self.options.critical_mos > 5):
            print('The critical-mos threshold value must lie between 1.00 and 5.00.')
            return False
        if self.options.warning_mos is not None and (self.options.warning_mos < 1 or self.options.warning_mos > 5):
            print('The warning-mos threshold value must lie between 1.00 and 5.00.')
            return False
        if self.options.critical_icpif is not None and self.options.warning_icpif is not None:
            if self.options.critical_icpif <= self.options.warning_icpif:
                print('The critical threshold value must be larger than the warning threshold '
                      'for the ICPIF value.')
                return False
        return True

    def check(self):
        """
        Perform checks on the requested entries
        :return:
        """
        logging.getLogger().debug('Performing checks for requested entries')

        # Initialize result status as OK
        self.status.add(NagiosStatus.OK)

        if not self.validate_requested_rtt_entries_types():
            # Combination of entries not valid
            return

        if len(self.requested_entries) == 0:
            self.add_message('No SLAs checked')
            self.status.add(NagiosStatus.UNKNOWN)
            return

        # Read rtt-type-specific data
        if self.is_rtt_type_requested(RttType.HTTP):
            self.read_rtt_http_entry_info()
        if self.is_rtt_type_requested(RttType.JITTER) \
                or self.is_rtt_type_requested(RttType.ICMP_JITTER) \
                or self.is_rtt_type_requested(RttType.ETHERNET_JITTER):
            self.read_rtt_jitter_entry_info()

        for entry in self.requested_entries:
            self.check_entry(self.rtt_dict[entry])

        if len(self.requested_entries) > 1:
            self.check_fail_percentages()

    def check_entry(self, rtt):
        """
        Check the entry's health and collect performance data if requested
        All collected information is stored in the rtt itsself
        :param rtt:
        :return:
        """
        logging.getLogger().debug('Checking requested entry {}'.format(rtt.id))

        # Set thresholds
        rtt.set_thresholds(self.options.warning, self.options.critical)
        if isinstance(rtt, RttJitter):
            rtt.set_thresholds_mos(self.options.warning_mos, self.options.critical_mos)
            rtt.set_thresholds_icpif(self.options.warning_icpif, self.options.critical_icpif)

        # Check RTT and collect perf data
        rtt.check_health()
        if self.options.perf:
            rtt.collect_perfdata()

    def check_fail_percentages(self):
        failed_count = 0
        not_failed_count = 0
        status_count = {
            NagiosStatus.OK: 0,
            NagiosStatus.WARNING: 0,
            NagiosStatus.CRITICAL: 0,
            NagiosStatus.UNKNOWN: 0,
        }

        for requested_entry in self.requested_entries:
            if requested_entry in self.rtt_dict:
                rtt = self.rtt_dict[requested_entry]
                if rtt.failed:
                    failed_count += 1
                else:
                    not_failed_count += 1
                    status_count[rtt.status.id] += 1

        if len(self.requested_entries) > 1:
            failed_pct = round(float(failed_count) / (failed_count + not_failed_count) * 100, 1)

            # Check percentage thresholds (if set)
            if self.options.critical_failed_pct is not None and failed_pct >= self.options.critical_failed_pct:
                self.status.add(NagiosStatus.CRITICAL)
            if self.options.warning_failed_pct is not None and failed_pct >= self.options.warning_failed_pct:
                self.status.add(NagiosStatus.WARNING)

            # Check absolute thresholds (if set)
            if self.options.critical_failed_count is not None and failed_count >= self.options.critical_failed_count:
                self.status.add(NagiosStatus.CRITICAL)
            if self.options.warning_failed_count is not None and failed_count >= self.options.warning_failed_count:
                self.status.add(NagiosStatus.WARNING)

            if failed_count:
                self.add_message('{0} Failed ({1}%)'.format(failed_count, failed_pct), True)
            if not_failed_count:
                if status_count[NagiosStatus.OK] > 0:
                    self.add_message('{0} OK'.format(status_count[NagiosStatus.OK]), True)
                if status_count[NagiosStatus.WARNING] > 0:
                    self.add_message('{0} Warning'.format(status_count[NagiosStatus.WARNING]), True)
                if status_count[NagiosStatus.CRITICAL] > 0:
                    self.add_message('{0} Critical'.format(status_count[NagiosStatus.CRITICAL]), True)
                if status_count[NagiosStatus.UNKNOWN] > 0:
                    self.add_message('{0} Unknown'.format(status_count[NagiosStatus.UNKNOWN]), True)

        if self.options.perf:
            if failed_count + not_failed_count > 1:
                failed_perf = "'Failed%'={0}%".format(failed_pct)
                if self.options.critical_failed_pct and self.options.warning_failed_pct:
                    failed_perf += ';{0};{1};0;100'.format(
                        self.options.warning_failed_pct,
                        self.options.critical_failed_pct
                    )
                self.add_perfdata(failed_perf)

    def determine_requested_rtt_entries(self):
        if self.options.entries == 'all':
            self.requested_entries = list(self.rtt_dict.keys())
        else:
            self.requested_entries = self.options.entries.replace(' ', '').split(',')
        self.requested_entries.sort(key=int)

        logging.getLogger().debug('Requested entries: ' + ", ".join(self.requested_entries))

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
                self.status.add(NagiosStatus.UNKNOWN)
                return False

            rtt = self.rtt_dict[requested_entry]

            if not CiscoIpSlaChecker.is_rtt_type_supported(rtt.type):
                msg = 'SLA {0} is of type {1} ({2}) which is not supported (yet).'
                self.add_message(msg.format(requested_entry,
                                            rtt.type.description,
                                            rtt.type.id))
                rtt.status.add(NagiosStatus.UNKNOWN)
                self.status.add(NagiosStatus.UNKNOWN)
                return False

            rtt_type_usage_count[rtt.type.id] += 1

        # For now, only checking of multiple SLA's is supported if they are all of the same type
        if len(rtt_type_usage_count) > 1:
            self.add_message('Checking multiple SLA entries is supported, but only if they are of the same type.')
            self.status.add(NagiosStatus.UNKNOWN)
            return False

        return True

    def is_rtt_type_requested(self, rtt_type):
        """
        Returns whether or not the specified rtt-type is supported by this script
        :param rtt_type: The rtt-type in numeric, string or RttType form
        :return: True if the rtt-type is requested, False otherwise
        """
        if not isinstance(rtt_type, RttType):
            rtt_type = RttType(rtt_type)

        is_requested = False

        for requested_entry in self.requested_entries:
            if requested_entry in self.rtt_dict:
                if self.rtt_dict[requested_entry].type == rtt_type:
                    is_requested = True
                    break

        logging.getLogger().debug(
           'Entry type {type} {yes_no} requested.'.format(
               type=rtt_type,
               yes_no='is' if is_requested else 'is not'
           )
        )

        return is_requested

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

    def list_rtt(self):
        """ Reads the list of available SLA entries for the device and prints out a list
        :return:
        """
        logger = logging.getLogger()
        logger.debug('Listing all rtt entries')

        sla_list = list()
        inactive_sla_list = list()

        col_width_id = 0
        col_width_type = 0
        col_width_tag = 0

        # Determine the column widths
        for rtt_id in sorted(self.rtt_dict):
            rtt = self.rtt_dict[rtt_id]
            col_width_id = max(col_width_id, len(str(rtt.id)))
            col_width_type = max(col_width_type, len(rtt.type.description))
            if rtt.in_active_state:
                col_width_tag = max(col_width_tag, len(rtt.tag))
            else:
                col_width_tag = max(col_width_tag, len(rtt.tag + ' (inactive)'))

        # for rtt_item in rtt_table:
        for rtt_id in sorted(self.rtt_dict):
            rtt = self.rtt_dict[rtt_id]
            rtt_line = '  ' + rtt.id.rjust(col_width_id)
            rtt_line += '  ' + rtt.type.description.ljust(col_width_type)
            tag_text = str(rtt.tag)
            if not rtt.in_active_state:
                tag_text += ' (inactive)'
            rtt_line += '  ' + tag_text.strip()

            if rtt.in_active_state:
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

    def print_output(self):
        """
        Prints the final output (in Nagios plugin format if self.status is set)
        :return:
        """
        logging.getLogger().debug('Printing final output')

        combined_msgs = []
        combined_perf = []

        # Add general messages and perf-data
        combined_msgs.append(self.get_messages())
        combined_perf.append(self.get_perfdata())

        # Collect the status, messages and perf-data of all rtt's
        for entry in self.requested_entries:
            rtt = self.rtt_dict[entry]
            self.status.add(rtt.status)
            combined_msgs.append(rtt.get_messages())
            combined_perf.append(rtt.get_perfdata())

        # Remove empty-string items
        combined_msgs = list(filter(None, combined_msgs))
        combined_perf = list(filter(None, combined_perf))

        # Build the output string
        output = str(self.status)
        if len(combined_msgs):
            output += ' - '
            # Join messages like sentences. Correct those messages which already ended with a period or a newline.
            output += '. '.join(combined_msgs).replace('.. ', '. ').replace('\n. ', '\n')

        if self.options.perf and len(combined_perf):
            if len(output):
                output += ' | '
            output += ' '.join(combined_perf)

        print(output)

    def add_status(self, status):
        """ Set the status only if it is more severe than the present status
        The order of severity being OK, WARNING, CRITICAL, UNKNOWN
        :param status: Status to set, one of the NagiosStatus.xxx constants
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

    def get_messages(self):
        # Join messages like sentences. Correct those messages which already ended with a period or a newline.
        return '. '.join(self.messages).replace('.. ', '. ').replace('\n. ', '\n')

    def get_perfdata(self):
        return ' '.join(self.perfdata)

    def get_entry_output_id(self, entry):
        if len(self.requested_entries) > 1:
            entry_output_id = ' ' + entry
        else:
            entry_output_id = ''

        return entry_output_id

    def create_snmp_session(self):
        logging.getLogger().debug('Creating SNMP session')

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

    def read_all_rtt_entry_basic_info(self):
        """ Reads all info on all RTT entries and stores found data in self.rtt_dict """
        logging.getLogger().debug('Reading basic rtt info for all entries')
        self.read_rtt_ctrl_admin_info()
        self.read_rtt_ctrl_oper_info()
        self.read_rtt_latest_oper_info()

    def read_rtt_ctrl_admin_info(self):
        logger = logging.getLogger()

        logger.debug('Starting SNMP-walk for rttMonCtrlAdminTable (.1.3.6.1.4.1.9.9.42.1.2.1.1)')
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
                    if len(self.requested_entries) > 1:
                        self.rtt_dict[rtt_entry].id_in_perf_label = True
                except ValueError:
                    logger.debug('Skipping unsupported rtt-type {}'.format(item.value))

        for item in rtt_ctrl_admin_entries:
            oid_parts = str(item.oid).split('.')
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if rtt_entry not in self.rtt_dict:
                logger.info('Missing entry {} in rtt-list for oid {}.{}'.format(rtt_entry, item.oid, item.oid_index))
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
                logger.info(
                    'In read_rtt_ctrl_oper_info():\n'
                    ' Exception parsing type {} for {} with value {}\n'
                    ' {}'.format(rtt_info_type, rtt_entry, item.value, e)
                )

    def read_rtt_ctrl_oper_info(self):
        # Get SLA entry status
        logger = logging.getLogger()

        logger.debug('Starting SNMP-walk for rttMonCtrlOperTable (.1.3.6.1.4.1.9.9.42.1.2.9.1)')
        rtt_ctrl_oper_entries = self.session.walk('.1.3.6.1.4.1.9.9.42.1.2.9.1')

        for item in rtt_ctrl_oper_entries:
            oid_parts = str(item.oid).split('.')
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if rtt_entry not in self.rtt_dict:
                logger.info('Missing entry {} in rtt-list for oid {}.{}'.format(rtt_entry, item.oid, item.oid_index))
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
                logger.info(
                    'In read_rtt_ctrl_oper_info():\n'
                    ' Exception parsing type {} for {} with value {}\n'
                    ' {}'.format(rtt_info_type, rtt_entry, item.value, e)
                )

    def read_rtt_latest_oper_info(self):
        # Get SLA entry latest result
        logger = logging.getLogger()

        logger.debug('Starting SNMP-walk for rttMonLatestRttOperTable (.1.3.6.1.4.1.9.9.42.1.2.10.1)')
        latest_rtt_oper_entries = self.session.walk('.1.3.6.1.4.1.9.9.42.1.2.10.1')

        for item in latest_rtt_oper_entries:
            oid_parts = str(item.oid).split('.')
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if rtt_entry not in self.rtt_dict:
                logger.info('Missing entry {} in rtt-list for oid {}.{}'.format(rtt_entry, item.oid, item.oid_index))
                continue

            cur_rtt = self.rtt_dict[rtt_entry]

            try:
                if '1' == rtt_info_type:
                    # rttMonLatestRttOperCompletionTime (1)
                    cur_rtt.latest_completion_time = item.value

                elif '2' == rtt_info_type:
                    # rttMonLatestRttOperSense (2)
                    # See http://www.circitor.fr/Mibs/Html/CISCO-RTTMON-TC-MIB.php#RttResponseSense
                    cur_rtt.latest_sense = RttResponseSense(item.value)

            except ValueError as e:
                logger.info(
                    'In read_rtt_latest_oper_info():\n'
                    ' Exception parsing type {} for {} with value {}\n'
                    ' {}'.format(rtt_info_type, rtt_entry, item.value, e)
                )

    def read_rtt_http_entry_info(self):
        logger = logging.getLogger()

        logger.debug('Reading http-specific info for requested entries')

        # Get Http specific data (See '-- LatestHttpOper Table' in MIB)
        logger.debug('Starting SNMP-walk for rttMonLatestHttpOperTable (.1.3.6.1.4.1.9.9.42.1.5.1.1)')
        latest_http_oper_entries = self.session.walk('.1.3.6.1.4.1.9.9.42.1.5.1.1')

        for item in latest_http_oper_entries:
            oid_parts = str(item.oid).split('.')
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if rtt_entry not in self.rtt_dict:
                logger.info('Missing entry {} in rtt-list for oid {}.{}'.format(rtt_entry, item.oid, item.oid_index))
                continue

            cur_rtt = self.rtt_dict[rtt_entry]
            if cur_rtt.type != RttType.HTTP:
                continue

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
                    cur_rtt.latest_http.sense = RttResponseSense(item.value)

                if '7' == rtt_info_type:
                    # rttMonLatestHTTPErrorSenseDescription (7)
                    cur_rtt.latest_http.sense_description = str(item.value)

            except ValueError as e:
                logger.info(
                    'In read_rtt_http_entry_info():\n'
                    ' Exception parsing type {} for {} with value {}\n'
                    ' {}'.format(rtt_info_type, rtt_entry, item.value, e)
                )

    def read_rtt_jitter_entry_info(self):
        logger = logging.getLogger()

        logger.debug('Reading jitter-specific info for all requested entries')

        # Get Jitter specific data (See '-- LatestJitterOper Table' in MIB)
        logger.debug('Starting SNMP-walk for rttMonLatestJitterOperTable (.1.3.6.1.4.1.9.9.42.1.5.2.1)')
        latest_jitter_oper_entries = self.session.walk('.1.3.6.1.4.1.9.9.42.1.5.2.1')

        for item in latest_jitter_oper_entries:
            oid_parts = str(item.oid).split('.')
            rtt_info_type = oid_parts[-1]
            rtt_entry = str(item.oid_index)

            if rtt_entry not in self.rtt_dict:
                logger.info('Missing entry {} in rtt-list for oid {}.{}'.format(rtt_entry, item.oid, item.oid_index))
                continue

            cur_rtt = self.rtt_dict[rtt_entry]
            if not isinstance(cur_rtt, RttJitter):
                continue

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
                    cur_rtt.latest_jitter.sense = RttResponseSense(item.value)

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
                logger.info(
                    'In read_rtt_jitter_entry_info():\n'
                    ' Exception parsing type {} for {} with value {}\n'
                    ' {}'.format(rtt_info_type, rtt_entry, item.value, e)
                )


class NagiosStatus(object):
    UNDEFINED = -1
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3

    status_values = {
        UNDEFINED: 'Undefined',
        OK: 'OK',
        WARNING: 'Warning',
        CRITICAL: 'Critical',
        UNKNOWN: 'Unknown',
    }

    def __init__(self, status=None):
        if status is None:
            status = self.UNDEFINED

        try:
            status_id = int(status)
        except ValueError:
            status_id = NagiosStatus.id_from_description(status)

        if int(status_id) in self.status_values:
            self._status_id = int(status_id)
        else:
            raise ValueError('Invalid NagiosStatus')

    def add(self, status):
        """ Set the status only if it is more severe than the present status
        The order of severity being OK, WARNING, CRITICAL, UNKNOWN
        :param status: Status to set, one of the NagiosStatus.xxx constants
        :return: The current status
        """
        try:
            status_id = int(status)
        except ValueError:
            status_id = NagiosStatus.id_from_description(status)

        if int(status_id) in self.status_values:
            if self.id is None or status_id > self.id:
                self._status_id = status_id
        else:
            raise ValueError('Invalid NagiosStatus')

    def __eq__(self, other):
        if not isinstance(other, NagiosStatus):
            other = NagiosStatus(other)
        return self.id == other.id

    def __ne__(self, other):
        if not isinstance(other, NagiosStatus):
            other = NagiosStatus(other)
        return self.id != other.id

    def __int__(self):
        return self.id

    def __str__(self):
        return self.description

    def __repr__(self):
        return 'NagiosStatus(id=' + str(self.id) + ', description=' + self.description + ')'

    @property
    def description(self):
        return NagiosStatus.description_from_id(self._status_id)

    @property
    def id(self):
        return self._status_id

    @staticmethod
    def id_from_description(status_description):
        """
        Get the numeric equivalent of an nagios-status represented as a string
        :param status_description: The nagios-status in string form
        :return: The numeric form of the nagios-status or None if no match was found
        """
        for status_id in NagiosStatus.status_values:
            if status_description == NagiosStatus.status_values[status_id]:
                return status_id
        return None

    @staticmethod
    def description_from_id(status_id):
        """
        Get the string equivalent of a numeric nagios-status
        :param status_id: The nagios-status in numeric form
        :return: A string describing the nagios-status or 'Undefined' if no match was found
        """
        status_id = int(status_id)
        description = 'Undefined'
        if status_id in NagiosStatus.status_values:
            description = NagiosStatus.status_values[status_id]
        return description


class RttResponseSense(object):
    OTHER = 0
    OK = 1
    DISCONNECTED = 2
    OVER_THRESHOLD = 3
    TIMEOUT = 4
    BUSY = 5
    NOT_CONNECTED = 6
    DROPPED = 7
    SEQUENCE_ERROR = 8
    VERIFY_ERROR = 9
    APPLICATION_SPECIFIC = 10
    DNS_SERVER_TIMEOUT = 11
    TCP_CONNECT_TIMEOUT = 12
    HTTP_TRANSACTION_TIMEOUT = 13
    DNS_QEURY_ERROR = 14
    HTTP_ERROR = 15
    ERROR = 16
    MPLS_LSP_ECHO_TX_ERROR = 17
    MPLS_LSP_UNREACHABLE = 18
    MPLS_LSP_MALFORMED_REQ = 19
    MPLS_LSP_REACH_NUT_NOT_FEC = 20
    ENABLE_OK = 21
    ENABLE_NO_CONNECT = 22
    ENABLE_VERSION_FAIL = 23
    ENABLE_INTERNAL_ERROR = 24
    ENABLE_ABORT = 25
    ENABLE_FAIL = 26
    ENABLE_AUTH_FAIL = 27
    ENABLE_FORMAT_ERROR = 28
    ENABLE_PORT_IN_USE = 29
    STATS_RETRIEVE_OK = 30
    STATS_RETRIEVE_NO_CONNECT = 31
    STATS_RETRIEVE_VERSION_FAIL = 32
    STATS_RETRIEVE_INTERNAL_ERROR = 33
    STATS_RETRIEVE_ABORT = 34
    STATS_RETRIEVE_FAIL = 35
    STATS_RETRIEVE_AUTH_FAIL = 36
    STATS_RETRIEVE_FORMAT_ERROR = 37
    STATS_RETRIEVE_PORT_IN_USE = 38

    sense_values = {
        OTHER: 'other',
        OK: 'ok',
        DISCONNECTED: 'disconnected',
        OVER_THRESHOLD: 'overThreshold',
        TIMEOUT: 'timeout',
        BUSY: 'busy',
        NOT_CONNECTED: 'notConnected',
        DROPPED: 'dropped',
        SEQUENCE_ERROR: 'sequenceError',
        VERIFY_ERROR: 'verifyError',
        APPLICATION_SPECIFIC: 'applicationSpecific',
        DNS_SERVER_TIMEOUT: 'dnsServerTimeout',
        TCP_CONNECT_TIMEOUT: 'tcpConnectTimeout',
        HTTP_TRANSACTION_TIMEOUT: 'httpTransactionTimeout',
        DNS_QEURY_ERROR: 'dnsQueryError',
        HTTP_ERROR: 'httpError',
        ERROR: 'error',
        MPLS_LSP_ECHO_TX_ERROR: 'mplsLspEchoTxError',
        MPLS_LSP_UNREACHABLE: 'mplsLspUnreachable',
        MPLS_LSP_MALFORMED_REQ: 'mplsLspMalformedReq',
        MPLS_LSP_REACH_NUT_NOT_FEC: 'mplsLspReachButNotFEC',
        ENABLE_OK: 'enableOk',
        ENABLE_NO_CONNECT: 'enableNoConnect',
        ENABLE_VERSION_FAIL: 'enableVersionFail',
        ENABLE_INTERNAL_ERROR: 'enableInternalError',
        ENABLE_ABORT: 'enableAbort',
        ENABLE_FAIL: 'enableFail',
        ENABLE_AUTH_FAIL: 'enableAuthFail',
        ENABLE_FORMAT_ERROR: 'enableFormatError',
        ENABLE_PORT_IN_USE: 'enablePortInUse',
        STATS_RETRIEVE_OK: 'statsRetrieveOk',
        STATS_RETRIEVE_NO_CONNECT: 'statsRetrieveNoConnect',
        STATS_RETRIEVE_VERSION_FAIL: 'statsRetrieveVersionFail',
        STATS_RETRIEVE_INTERNAL_ERROR: 'statsRetrieveInternalError',
        STATS_RETRIEVE_ABORT: 'statsRetrieveAbort',
        STATS_RETRIEVE_FAIL: 'statsRetrieveFail',
        STATS_RETRIEVE_AUTH_FAIL: 'statsRetrieveAuthFail',
        STATS_RETRIEVE_FORMAT_ERROR: 'statsRetrieveFormatError',
        STATS_RETRIEVE_PORT_IN_USE: 'statsRetrievePortInUse',
    }

    def __init__(self, sense):
        try:
            sense_id = int(sense)
        except ValueError:
            sense_id = RttResponseSense.id_from_description(sense)

        if int(sense_id) in self.sense_values:
            self._sense_id = int(sense_id)
        else:
            raise ValueError('Invalid RttResponseSense')

    def __eq__(self, other):
        if not isinstance(other, RttResponseSense):
            other = RttResponseSense(other)
        return self.id == other.id

    def __ne__(self, other):
        if not isinstance(other, RttResponseSense):
            other = RttResponseSense(other)
        return self.id != other.id

    def __str__(self):
        return self.description

    def __repr__(self):
        return 'RttResponseSense(id=' + str(self.id) + ', description=' + self.description + ')'

    @property
    def description(self):
        return RttResponseSense.description_from_id(self._sense_id)

    @property
    def id(self):
        return self._sense_id

    @staticmethod
    def id_from_description(sense_description):
        """
        Get the numeric equivalent of an rtt-response-sense represented as a string
        :param sense_description: The rtt-response-sense in string form
        :return: The numeric form of the rtt-response-sense or None if no match was found
        """
        for sense_id in RttResponseSense.sense_values:
            if sense_description == RttResponseSense.sense_values[sense_id]:
                return sense_id
        return None

    @staticmethod
    def description_from_id(sense_id):
        """
        Get the string equivalent of a numeric rtt-response-sense
        :param sense_id: The rtt-response-sense in numeric form as returned by an SNMP request
        :return: A string describing the rtt-response-sense or 'Undefined' if no match was found
        """
        sense_id = int(sense_id)
        description = 'Undefined'
        if sense_id in RttResponseSense.sense_values:
            description = RttResponseSense.sense_values[sense_id]
        return description


class RttType(object):
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
        return 'RttType(id=' + str(self.id) + ', description=' + self.description + ')'

    @property
    def description(self):
        return RttType.description_from_id(self._type_id)

    @property
    def id(self):
        return self._type_id

    @staticmethod
    def id_from_description(rtt_type_description):
        """
        Get the numeric equivalent of an rtt-type represented as a string
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


class Rtt(object):
    def __init__(self, rtt_id):
        self._id = rtt_id
        self._owner = None
        self._tag = None
        self._type = None
        self._threshold = None
        self._long_tag = None
        self._diag_text = None
        self._conn_lost_occurred = None
        self._timeout_occurred = None
        self._over_thres_occurred = None
        self._in_active_state = None
        self._latest_completion_time = None
        self._latest_sense = None
        self._status = NagiosStatus()
        self._failed = False
        self.messages = []
        self.perfdata = []
        self.warning = None
        self.critical = None
        self.id_in_perf_label = False

    @staticmethod
    def rtt_factory(rtt_id, rtt_type):
        if not isinstance(rtt_type, RttType):
            rtt_type = RttType(rtt_type)

        if rtt_type == RttType.ECHO \
                or rtt_type == RttType.PATH_ECHO \
                or rtt_type == RttType.UDP_ECHO:
            return RttEcho(rtt_id, rtt_type)
        elif rtt_type == RttType.JITTER \
                or rtt_type == RttType.ICMP_JITTER \
                or rtt_type == RttType.ETHERNET_JITTER:
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
    def in_active_state(self):
        return self._in_active_state

    @in_active_state.setter
    def in_active_state(self, value):
        self._in_active_state = bool(value)

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
        if not isinstance(value, RttResponseSense):
            value = RttResponseSense(value)
        self._latest_sense = value

    @property
    def status(self):
        return self._status

    @property
    def failed(self):
        return self._failed

    def set_thresholds(self, warning, critical):
        self.warning = warning
        self.critical = critical

    def set_message(self, message):
        self.messages = [message]

    def add_message(self, message, prepend=False):
        if prepend:
            self.messages.insert(0, message)
        else:
            self.messages.append(message)

    def get_messages(self):
        # Join messages like sentences. Correct those messages which already ended with a period or a newline.
        return '. '.join(self.messages).replace('.. ', '. ').replace('\n. ', '\n')

    @property
    def perf_label_suffix(self):
        if self.id_in_perf_label:
            return '_{}'.format(self.id)
        else:
            return ''

    def get_perfdata(self):
        return ' '.join(self.perfdata)

    def add_perfdata(self, perfitem, prepend=False):
        if prepend:
            self.perfdata.insert(0, perfitem)
        else:
            self.perfdata.append(perfitem)

    def check_basic_health(self):
        logger = logging.getLogger()
        logger.debug('Checking basic health for echo entry {}'.format(self.id))

        # Initialize result status as OK
        self.status.add(NagiosStatus.OK)

        if self.in_active_state:
            if self.conn_lost_occurred:
                self._failed = True
                self.add_message('Connection lost for SLA {0}'.format(self.description))
            elif self.timeout_occurred:
                self._failed = True
                self.add_message('Timeout for SLA {0}'.format(self.description))
            elif self.over_thres_occurred:
                self._failed = True
                self.add_message('Threshold exceeded for SLA {0}'.format(self.description))
            else:
                self._failed = False
        else:
            self._failed = True
            self.status.add(NagiosStatus.UNKNOWN)
            self.add_message('SLA {0} not active'.format(self.description))

    def __str__(self):
        self_str = 'Rtt id: {id}\n  owner: {owner}\n  tag: {tag}\n  type: {type}\n  threshold: {threshold}\n' \
                   '  long-tag: {long_tag}\n  diag-text: {diag_text}\n  conn-lost-occurred: {conn_lost_occurred}\n' \
                   '  over-thres-occurred: {over_thres_occurred}\n  in-active-state: {in_active_state}\n' \
                   '  latest-completion-time: {latest_completion_time}\n' \
                   '  latest-sense: {latest_sense}'
        return self_str.format(id=self.id,
                               owner=self.owner,
                               tag=self.tag,
                               type=self.type,
                               threshold=self.threshold,
                               long_tag=self.long_tag,
                               diag_text=self.diag_text,
                               conn_lost_occurred=self.conn_lost_occurred,
                               over_thres_occurred=self.over_thres_occurred,
                               in_active_state=self.in_active_state,
                               latest_completion_time=self.latest_completion_time,
                               latest_sense=self.latest_sense)


class RttEcho(Rtt):
    def __init__(self, rtt_id, rtt_type):
        Rtt.__init__(self, rtt_id)
        self.type = rtt_type

    def check_health(self):
        """
        Checks if the latest echo entry check went OK by it's sense value and latest rtt
        Can adjust the status and messages returned by the check
        :return:
        """
        logger = logging.getLogger()
        logger.debug('Checking health for echo entry {}'.format(self.id))

        Rtt.check_basic_health(self)

        if self.latest_sense != RttResponseSense.OK:
            self._failed = True
            self.status.add(NagiosStatus.CRITICAL)
            self.add_message('Latest echo operation gave {sense} for SLA {sla}'.format(
                sense=self.latest_sense, sla=self.description))

        # Check rtt thresholds (if set)
        if self.critical is not None or self.warning is not None:
            if self.latest_completion_time is None:
                self._failed = True
                self.status.add(NagiosStatus.UNKNOWN)
                self.add_message('RTT not known for SLA {sla}, but threshold is set'.format(sla=self.description))
            elif self.critical is not None and self.latest_completion_time >= self.critical:
                self.status.add(NagiosStatus.CRITICAL)
                self.add_message(
                    'RTT for SLA {sla} is {rtt}ms, which is over critical threshold of {crit}ms'.format(
                        sla=self.description,
                        rtt=self.latest_completion_time,
                        crit=self.critical
                    )
                )
            elif self.warning is not None and self.latest_completion_time >= self.warning:
                self.status.add(NagiosStatus.WARNING)
                self.add_message(
                    'RTT for SLA {sla} is {rtt}ms, which is over warning threshold of {warn}ms'.format(
                        sla=self.description,
                        rtt=self.latest_completion_time,
                        warn=self.warning
                    )
                )

    def collect_perfdata(self):
        self.add_perfdata(
            "'rtt{label_suffix}'={val}ms".format(
                label_suffix=self.perf_label_suffix,
                val=self.latest_completion_time
            )
        )


class RttJitter(Rtt):
    def __init__(self, rtt_id, rtt_type):
        Rtt.__init__(self, rtt_id)
        self.type = rtt_type
        self.latest_jitter = self.LatestJitter()
        self.warning_mos = None
        self.critical_mos = None
        self.warning_icpif = None
        self.critical_icpif = None

    def set_thresholds_mos(self, warning_mos, critical_mos):
        self.warning_mos = warning_mos
        self.critical_mos = critical_mos

    def set_thresholds_icpif(self, warning_icpif, critical_icpif):
        self.warning_icpif = warning_icpif
        self.critical_icpif = critical_icpif

    def check_health(self):
        """
        Checks if the latest jitter entry check went OK by it's sense value,
        if time is synced between the source and destination
        and checks the MOS and ICPIF thresholds if they are set.
        Can adjust the status and messages returned by the check
        :return:
        """
        logger = logging.getLogger()

        logger.debug('Checking health for jitter entry')
        logger.debug(str(self))

        Rtt.check_basic_health(self)

        if self.latest_jitter.sense != RttResponseSense.OK:
            self._failed = True
            self.status.add(NagiosStatus.WARNING)
            self.status.add(NagiosStatus.WARNING)
            self.add_message('Latest jitter operation gave {sense} for SLA {sla} (descr: {descr})'.format(
                sense=self.latest_jitter.sense, sla=self.description, descr=self.latest_jitter.sense_description))

        if not self.latest_jitter.ntp_sync:
            self._failed = True
            self.status.add(NagiosStatus.WARNING)
            self.add_message('NTP not synced between source and destination for SLA {0}'.format(self.description))

        # Check MOS thresholds (if set)
        if self.critical_mos is not None or self.warning_mos is not None:
            if self.latest_jitter.mos is None:
                self.status.add(NagiosStatus.UNKNOWN)
                self.add_message('MOS not known for SLA {0}, but threshold is set'.format(self.description))
            elif self.critical_mos is not None and self.latest_jitter.mos <= self.critical_mos:
                self.status.add(NagiosStatus.CRITICAL)
                self.add_message('MOS is under critical threshold for SLA {0}'.format(self.description))
            elif self.warning_mos is not None and self.latest_jitter.mos <= self.warning_mos:
                self.status.add(NagiosStatus.WARNING)
                self.add_message('MOS is under warning threshold for SLA {0}'.format(self.description))

        # Check ICPIF thresholds (if set)
        if self.critical_icpif is not None or self.warning_icpif is not None:
            if self.latest_jitter.icpif is None:
                self.status.add(NagiosStatus.UNKNOWN)
                self.add_message('ICPIF not known for SLA {0}, but threshold is set'.format(self.description))
            elif self.critical_icpif is not None and self.latest_jitter.icpif >= self.critical_icpif:
                self.status.add(NagiosStatus.CRITICAL)
                self.add_message('ICPIF is over critical threshold for SLA {0}'.format(self.description))
            elif self.warning_icpif is not None and self.latest_jitter.icpif >= self.warning_icpif:
                self.status.add(NagiosStatus.WARNING)
                self.add_message('ICPIF is over warning threshold for SLA {0}'.format(self.description))

    def collect_perfdata(self):
        """
        Collect and save perf-data for the rtt so it gets returned by this check
        Will adjust the perfdata returned by the check
        :return:
        """
        logger = logging.getLogger()
        logger.debug('Collecting perfdata for jitter entry')

        if self.latest_jitter.num_of_rtt > 1:
            self.add_perfdata("'RTT avg{label_suffix}'={avg}ms;{min};{max}".format(
                label_suffix=self.perf_label_suffix,
                avg=round(self.latest_jitter.rtt_sum / (self.latest_jitter.num_of_rtt - 1), 1),
                min=self.latest_jitter.rtt_min,
                max=self.latest_jitter.rtt_max
            ))
            self.add_perfdata("'RTT variance{label_suffix}'={var}".format(
                label_suffix=self.perf_label_suffix,
                var=round(self.latest_jitter.rtt_sum2 / (self.latest_jitter.num_of_rtt - 1), 1),
            ))
            self.add_perfdata("'RTT std dev{label_suffix}'={var}".format(
                label_suffix=self.perf_label_suffix,
                var=round(math.sqrt(self.latest_jitter.rtt_sum2 / (self.latest_jitter.num_of_rtt - 1)), 1),
            ))

        self.add_perfdata("'Avg jitter{label_suffix}'={v}".format(
            label_suffix=self.perf_label_suffix,
            v=self.latest_jitter.avg_jitter
        ))
        self.add_perfdata("'Avg jitter SD{label_suffix}'={v}".format(
            label_suffix=self.perf_label_suffix,
            v=self.latest_jitter.avg_jitter_sd
        ))
        self.add_perfdata("'Avg jitter DS{label_suffix}'={v}".format(
            label_suffix=self.perf_label_suffix,
            v=self.latest_jitter.avg_jitter_ds
        ))
        self.add_perfdata("'Avg latency SD{label_suffix}'={v}".format(
            label_suffix=self.perf_label_suffix,
            v=self.latest_jitter.avg_latency_sd
        ))
        self.add_perfdata("'Avg latency DS{label_suffix}'={v}".format(
            label_suffix=self.perf_label_suffix,
            v=self.latest_jitter.avg_latency_ds
        ))

        mos_perfdata = "'MOS{label_suffix}'={v}".format(
            label_suffix=self.perf_label_suffix,
            v=self.latest_jitter.mos
        )
        if self.critical_mos is not None and self.warning_mos is not None:
            mos_perfdata += ';{warn};{crit}'.format(warn=self.warning_mos, crit=self.critical_mos)
        self.add_perfdata(mos_perfdata)

        icpif_perfdata = "'ICPIF{label_suffix}'={v}".format(
            label_suffix=self.perf_label_suffix,
            v=self.latest_jitter.icpif
        )
        if self.critical_icpif is not None and self.warning_icpif is not None:
            icpif_perfdata += ';{warn};{crit}'.format(warn=self.warning_icpif, crit=self.critical_icpif)
        self.add_perfdata(icpif_perfdata)

        self.add_perfdata("'Packet loss SD{label_suffix}'={v}".format(
            label_suffix=self.perf_label_suffix,
            v=self.latest_jitter.packet_loss_sd
        ))
        self.add_perfdata("'Packet loss DS{label_suffix}'={v}".format(
            label_suffix=self.perf_label_suffix,
            v=self.latest_jitter.packet_loss_ds
        ))
        self.add_perfdata("'Packet out of seq{label_suffix}'={v}".format(
            label_suffix=self.perf_label_suffix,
            v=self.latest_jitter.packet_out_of_seq
        ))
        self.add_perfdata("'Packet MIA{label_suffix}'={v}".format(
            label_suffix=self.perf_label_suffix,
            v=self.latest_jitter.packet_mia
        ))
        self.add_perfdata("'Packet late arrival{label_suffix}'={v}".format(
            label_suffix=self.perf_label_suffix,
            v=self.latest_jitter.packet_late_arrival
        ))
        if self.latest_jitter.num_over_threshold is not None:
            self.add_perfdata("'Num over threshold{label_suffix}'={v}".format(
                label_suffix=self.perf_label_suffix,
                v=self.latest_jitter.num_over_threshold
            ))

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
            if not isinstance(value, RttResponseSense):
                value = RttResponseSense(value)
            self._sense = value

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
                mos /= 100
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
    def __init__(self, rtt_id, rtt_type):
        Rtt.__init__(self, rtt_id)
        self.type = rtt_type
        self.latest_http = self.LatestHttp()

    def __str__(self):
        return Rtt.__str__(self) + '\n' + str(self.latest_http)

    def check_health(self):
        """
        Checks if the latest http entry check went OK by it's sense value
        Can adjust the status and messages returned by the check
        :return:
        """
        logger = logging.getLogger()
        logger.debug('Checking health for http entry {}'.format(self.id))
        logger.debug(str(self))

        Rtt.check_basic_health(self)

        if self.latest_http.sense != RttResponseSense.OK:
            self._failed = True
            self.status.add(NagiosStatus.CRITICAL)
            self.add_message('Latest http operation gave {sense} for SLA {sla}'.format(
                sense=self.latest_http.sense, sla=self.description))

        # Check rtt thresholds (if set)
        if self.critical is not None or self.warning is not None:
            if self.latest_http.rtt is None:
                self._failed = True
                self.status.add(NagiosStatus.UNKNOWN)
                self.add_message('Http RTT not known for SLA {sla}, but threshold is set'.format(sla=self.description))
            elif self.critical is not None and self.latest_http.rtt >= self.critical:
                self.status.add(NagiosStatus.CRITICAL)
                self.add_message('Http RTT is over critical threshold for SLA {sla}'.format(sla=self.description))
            elif self.warning is not None and self.latest_http.rtt >= self.warning:
                self.status.add(NagiosStatus.WARNING)
                self.add_message('Http RTT is over warning threshold for SLA {sla}'.format(sla=self.description))

    def collect_perfdata(self):
        """
        Collect and save perf-data for the rtt so it gets returned by this check
        Will adjust the perfdata returned by the check
        :return:
        """
        logger = logging.getLogger()
        logger.debug('Collecting perfdata for http entry {}'.format(self.id))

        self.add_perfdata("'DNS rtt{label_suffix}'={v}ms".format(
            label_suffix=self.perf_label_suffix,
            v=self.latest_http.rtt_dns
        ))
        self.add_perfdata("'TCP connect rtt{label_suffix}'={v}ms".format(
            label_suffix=self.perf_label_suffix,
            v=self.latest_http.rtt_tcp_connect
        ))
        self.add_perfdata("'Transaction rtt{label_suffix}'={v}ms".format(
            label_suffix=self.perf_label_suffix,
            v=self.latest_http.rtt_trans
        ))

        thresholds = ''
        if self.critical is not None and self.warning is not None:
            thresholds = ';{warn};{crit}'.format(warn=self.warning, crit=self.critical)

        self.add_perfdata("'Total rtt{label_suffix}'={val}ms{thresholds}".format(
            label_suffix=self.perf_label_suffix,
            val=self.latest_http.rtt,
            thresholds=thresholds
        ))

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
            if not isinstance(value, RttResponseSense):
                value = RttResponseSense(value)
            self._sense = value

        @property
        def sense_description(self):
            return self._sense_description

        @sense_description.setter
        def sense_description(self, value):
            self._sense_description = str(value)

        def __str__(self):
            self_str = ' LatestHttp:\n  rtt: {rtt}\n  rtt-dns: {rtt_dns}\n  rtt-tcp-connect: {rtt_tcp_connect}\n' \
                       '  rtt-trans: {rtt_trans}\n  body-octets: {body_octets}\n' \
                       '  sense: {sense}\n  sense-description: {sense_description}'
            return self_str.format(rtt=self.rtt,
                                   rtt_dns=self.rtt_dns,
                                   rtt_tcp_connect=self.rtt_tcp_connect,
                                   rtt_trans=self.rtt_trans,
                                   body_octets=self.body_octets,
                                   sense=self.sense,
                                   sense_description=self.sense_description)

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
    exit(int(checker.status))
