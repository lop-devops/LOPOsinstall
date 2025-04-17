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


import os
import sys
import time
import logging
try:
    import pexpect
except ImportError:
    print ("please install pexpect module")


class CommonLib():

    def __init__(self, hmc_ip, user_name, password, ManagedSystem, lparname, lparprofile, bootid):
        self.hmc_ip = hmc_ip
        self.user_name = user_name
        self.password = password
        self.ManagedSystem = ManagedSystem
        self.lparname = lparname
        self.lparprofile = lparprofile
        self.bootid = bootid
        self.con = pexpect.spawn(
            "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no " + self.user_name + "@" + self.hmc_ip)
        self.con.logfile = sys.stdout
        self.delaybeforesend = 0.9
        rc = self.con.expect(["[Pp]assword:", pexpect.TIMEOUT], timeout=60)
        if rc == 0:
            self.con.sendline(self.password)
        else:
            sys.exit(1)
        self.smsmenu = [('Main Menu', 'Select Boot Options'), ('Multiboot', 'Configure Boot Device Order'), ('Configure Boot Device Order', 'Select 1st Boot Device'), ('Select Device Type', 'Hard Drive'), (
            'Select Media Type', 'List All Devices'), ('Select Device', 'bootdisk'), ('Select Task', 'Set Boot Sequence'), ('Current Boot Sequence', 'Current Boot Sequence')]

    def getDiskIndex(self, pages):
        flag = False
        while not flag:
            for index, line in enumerate(pages):
                if 'Next page' in line:
                    self.con.send('N')
                    time.sleep(5)
                    i = self.con.expect(
                        ["Navigation keys", pexpect.TIMEOUT], timeout=600)
                    if i == 0:
                        lines = self.con.before.split("\n")
                        for index, line in enumerate(lines):
                            if bootdisk in line:
                                key = lines[index - 1].split(".")[0]
                                return key
                else:
                    flag = True
        if flag:
            self.con.sendline(
                "rmvterm -m " + self.ManagedSystem + " -p " + self.lparname)
            logging.info("DISK NOT FOUND:OS not installed ?")
            sys.exit(1)

    def smsMenu(self, page, string):
        key = ''
        disk_found = False
        i = self.con.expect([page, pexpect.TIMEOUT], timeout=80)
        if i == 0:
            i = self.con.expect(["key:", pexpect.TIMEOUT], timeout=80)
            if i == 0:
                lines = self.con.before.split("\n")
                for index, line in enumerate(lines):
                    if string in line:
                        if page == 'Select Device':
                            key = lines[index - 1][1]
                            disk_found = True
                            continue
                        else:
                            key = lines[index][1]
                if page == 'Select Device':
                    if not disk_found:
                        key = self.getDiskIndex(lines)
                if page == 'Current Boot Sequence':
                    self.con.send(str('X'))
                    i = self.con.expect(["key:", pexpect.TIMEOUT], timeout=80)
                    if i == 0:
                        key = '1'
                self.con.send(key)
                self.con.send('\r')
                time.sleep(5)

    def setBootOrder(self):
        logging.info("Shutting down LPAR")
        self.con.sendline(
            "chsysstate -r lpar -o shutdown --immed -m " + self.ManagedSystem + " -n " + self.lparname)
        time.sleep(10)
        logging.info("Booting LPAR to SMS menu")
        self.con.sendline("chsysstate -r lpar -b sms -o on -m " +
                          self.ManagedSystem + " -n " + self.lparname + " -f " + self.lparprofile)
        self.con.send('\r')
        time.sleep(10)
        self.con.sendline(
            "rmvterm -m " + self.ManagedSystem + " -p " + self.lparname)
        self.con.send('\n')
        time.sleep(5)
        logging.info("\nActivating Console")
        self.con.sendline(
            "mkvterm -m " + self.ManagedSystem + " -p " + self.lparname)
        self.con.send('\n')
        time.sleep(40)
        self.con.send('\r')
        i = self.con.expect(["Invalid entry", pexpect.TIMEOUT], timeout=60)
        if i == 0:
            self.con.send('\r')
            self.con.logfile = sys.stdout
            self.con.delaybeforesend = 0.9
        for page, string in self.smsmenu:
            if page == 'Select Device':
                string = self.bootid
            self.smsMenu(page, string)
        time.sleep(60)
        logging.info("Rebooting .... ")
        self.con.sendline(
            "rmvterm -m " + self.ManagedSystem + " -p " + self.lparname)

    def checkLogin(self):
        self.con.sendline(
            "rmvterm -m " + self.ManagedSystem + " -p " + self.lparname)
        self.con.send('\n')
        time.sleep(5)
        self.con.sendline(
            "mkvterm -m " + self.ManagedSystem + " -p " + self.lparname)
        self.con.send('\n')
        i = self.con.expect(["Open Completed.", pexpect.TIMEOUT], timeout=60)
        if i == 0:
            self.con.send('\r')
        i = self.con.expect(["login:", "#", pexpect.TIMEOUT], timeout=600)
        if i == 0:
            self.con.send('root')
            self.con.send('\r')
            i = self.con.expect(["Password:", pexpect.TIMEOUT], timeout=60)
            if i == 0:
                self.con.send('passw0rd')
                self.con.send('\r')
                i = self.con.expect(
                    ["Last login", pexpect.TIMEOUT], timeout=60)
                if i == 0:
                    return 1
        elif i == 1:
            return 1
        else:
            return 0
