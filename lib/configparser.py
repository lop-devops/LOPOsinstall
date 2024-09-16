#!/usr/bin/env python
#  -*- coding: utf-8 -*-
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# See LICENSE for more details.
#
# Copyright: 2023 IBM
# Author: Praveen K Pandey <praveen@linux.vnet.ibm.com>

import argparse
import sys
import configparser
import os
import logging


class CmdLineArgParser():

    def __init__(self):
        self.args = []
        self.Config = configparser.ConfigParser()
        self.Config.read('./installvm.conf')
        return

    def parse_args(self, argv=None):
        parser = argparse.ArgumentParser(
            description=__doc__,
            formatter_class=argparse.RawDescriptionHelpFormatter)

        hostGroup = parser.add_argument_group(
            'Host Specific Information for Installation', '')
        hostGroup.add_argument(
            '--host-ip', help='Host IP address', required=True)
        hostGroup.add_argument('--host-name', help='Host FQDN', required=True)
        hostGroup.add_argument(
            '--host-gw', help='Host Gateway IP', required=True)
        hostGroup.add_argument(
            '--host-netmask', help='Host network subnetmask', default="255.255.255.0")
        hostGroup.add_argument(
            '--host-mac', help='Host MAC address', required=True)
        hostGroup.add_argument(
            '--host-disk', help='Host disk(s) by-id to install ex: /dev/disk/by-id/<disk>', required=True)
        hostGroup.add_argument(
            '--boot-disk', help='boot disk ID from VIOS to set order ex: U9080.M9S.78264B8-V1-C101-T1-L8100000000000000', required=False)
        hostGroup.add_argument(
            '--multipathsetup', help='Host disk having multipath setup', default='')
        hostGroup.add_argument(
            '--kernel-params', help='append addon kernel parameters', default='')
        hostGroup.add_argument(
            '--host-password', help='system password', default='passw0rd')
        lparDetails = parser.add_argument_group('Managed System Details', '')
        lparDetails.add_argument(
            '--lpar-hmc', help='HMC Name or IP', required=True)
        lparDetails.add_argument(
            '--lpar-managed-system', help='LPAR Managed system name', required=True)
        lparDetails.add_argument(
            '--lpar-partition-name', help='LPAR Partition Name', required=True)
        lparDetails.add_argument(
            '--hmc-userid', help='HMC userid', default='hscroot')
        lparDetails.add_argument(
            '--hmc-password', help='HMC password', default='abc1234')
        lparDetails.add_argument(
            '--hmc-profile', help='HMC Profile Name', default='default')
        lparDetails.add_argument(
            '--ksargs', help='Additional Kick Start option', default='')
        lparDetails.add_argument('--showcleanup', default=1)
        parser.add_argument(
            '--distro', help='distro to be installed ex: rhel_7.4le_alpa, sles_11sp3_beta', required=True)
        parser.add_argument(
            '--install-protocol' , help='Mode of Install Protocol ex: http, ftp, nfs',default='http')
        parser.add_argument('--fs-type' ,help='RootFS type ex: xfs, ext4, btrfs',default='xfs')
        parser.add_argument(
            '--set-boot-order', help='yes/True to set the boot disk order', required=False)
        parser.add_argument(
            '--ssl-server', help='SSL certificate for the server domain to be created in LPAR', required=False)

        self.args = parser.parse_args()
        self.domain = (self.args.host_name).split('.', 1)[1]
        self.distroPath = '/'.join(self.args.distro.split('_'))
        self.netDir = ''.join(self.args.host_mac.split(':'))

    def confparser(self, section, option):
        try:
            return self.Config.get(section, option)
        except Exception as e:
            logging.info("Check your config file %s" % e)
            logging.info("Aborting Installation : Check log for errors")
            exit(1)

    def checkSys(self, addr, name):
        '''Check for server availability'''
        rc = os.system("ping -c 1 %s > /dev/null" % addr)
        if rc:
            logging.info("%s not reachable : %s" % (name, addr))
            logging.info("Aborting Installation : Check log for errors")
            exit(1)
        logging.info("%s is reachable : OK" % name)

    def validate(self):
        self.checkSys(self.args.lpar_hmc, "HMC")
        self.checkSys(self.confparser(self.domain, 'NextServer'), 'NextServer')
        self.checkSys(self.confparser('dhcp', 'DHCPServer'), 'DHCPServer')
        self.checkSys(self.confparser('repo', 'RepoIP'), 'RepoServer')
