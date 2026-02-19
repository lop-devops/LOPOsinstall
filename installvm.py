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

import sys
import os
import paramiko
import re
import netaddr
import time
import logging
import logging.config
from datetime import datetime
from multiprocessing import Process

from lib import configparser


class Distro():

    def __init__(self):
        self.nxtSrvCon = paramiko.SSHClient()
        self.nxtSrvCon.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.nxtSrvCon.connect(vmParser.confparser(vmParser.domain, 'NextServer'),
                               username=vmParser.confparser(
                                   vmParser.domain, 'User'),
                               password=vmParser.confparser(vmParser.domain, 'Password'))
        self.baseURL = vmParser.confparser(vmParser.domain, 'TFTPBoot')
        self.destDir = self.baseURL + '/' + vmParser.netDir
        self.repoDir = vmParser.confparser(
            'repo', 'RepoDir') + vmParser.distroPath
        self.filename = None
        self.show = 0
        if vmParser.args.showcleanup:
            self.show = 1

    def runCommandcleanup(self, conn, cmd):
        if self.show:
            logging.info("Running Command : %s" % cmd)
        stdin, stdout, stderr = conn.exec_command(cmd)
        for line in stdout:
            if self.show:
                logging.debug(line.strip())
        rc = stdout.channel.recv_exit_status()
        if rc:
            if self.show:
                logging.info(
                    "Command Failed : Aborting the Installation : %s" % rc)
            self.cleanup()
            exit(1)
        if self.show:
            logging.info("Command Run Successfull : %s" % rc)

    def runCommand(self, conn, cmd):
        if self.show:
            logging.info("Running Command : %s" % cmd)
        stdin, stdout, stderr = conn.exec_command(cmd)
        for line in stdout:
            logging.debug(line.strip())
        rc = stdout.channel.recv_exit_status()
        if rc:
            if self.show:
                logging.info(
                    "Command Failed : Aborting the Installation : %s" % rc)
            self.cleanup()
            exit(1)
        if self.show:
            logging.info("Command Run Successfull : %s" % rc)

    def configDHCP(self):
        logging.info("Configuring DHCP for netboot")
        self.dhcpSrvCon = paramiko.SSHClient()
        self.dhcpSrvCon.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.dhcpSrvCon.connect(vmParser.confparser('dhcp', 'DHCPServer'),
                                username=vmParser.confparser('dhcp', 'User'),
                                password=vmParser.confparser('dhcp', 'Password'))
        dhcpsftp = self.dhcpSrvCon.open_sftp()
        with dhcpsftp.open('/etc/dhcp/dhcpd.conf', 'r') as dhcpfd:
            data = dhcpfd.read().decode("utf-8").strip()
        tmpf = dhcpsftp.open('/tmp/dhcpd.conf', 'w')
        reg = re.compile("""(^subnet[ \t0-9a-zA-Z.{]*\n)(^[ \t]+.+\n)*(^}$)""",
                         re.MULTILINE)
        for match in reg.finditer(data):
            start = match.start()
            end = match.end()
            dhcprecord = data[start:end]
            if vmParser.args.host_name not in dhcprecord:
                tmpf.write(dhcprecord)
                tmpf.write("\n")
        '''
        The following lines are to be append in dhcpd.conf for each system
        subnet 9.40.192.0 netmask 255.255.255.0 {
            allow bootp;
            option routers 9.40.192.1;
            option domain-name-servers 9.3.1.200;
            option domain-name "aus.stglabs.ibm.com";
            group {
                next-server 9.40.192.217;
                filename "boot/ppc64le/grub2-ieee1275/core.elf";
                host tuleta4u-lp3.aus.stglabs.ibm.com {
                    hardware ethernet 22:82:8e:78:a1:02;
                    fixed-address 9.40.192.212;
                    option host-name "tuleta4u-lp3";
                    option tftp-server-name "9.40.192.217";
                }
            }
        }
        '''
        addr = str(vmParser.args.host_ip) + "/" + \
            str(vmParser.args.host_netmask)
        ip = netaddr.IPNetwork(addr)
        nw = str(ip.network)
        tmpf.write('subnet ' + nw + ' netmask ' +
                   vmParser.args.host_netmask + ' {\n')
        tmpf.write('    allow bootp;\n')
        tmpf.write('    option routers ' + vmParser.args.host_gw + ';\n')
        tmpf.write('    option domain-name-servers ' +
                   vmParser.confparser(vmParser.domain, 'DNS') + ';\n')
        tmpf.write('    option domain-name \"' + vmParser.domain + '\";\n')
        tmpf.write('    group {\n')
        tmpf.write('        next-server ' +
                   vmParser.confparser(vmParser.domain, 'NextServer') + ';\n')
        tmpf.write('        filename \"' + self.filename + '\";\n')
        tmpf.write('        host ' + vmParser.args.host_name + ' {\n')
        tmpf.write('            hardware ethernet ' +
                   vmParser.args.host_mac + ';\n')
        tmpf.write('            fixed-address ' +
                   vmParser.args.host_ip + ';\n')
        tmpf.write('            option host-name \"' +
                   (vmParser.args.host_name).split('.', 1)[0] + '\";\n')
        tmpf.write('            option tftp-server-name \"' +
                   vmParser.confparser(vmParser.domain, 'NextServer') + '\";\n')
        tmpf.write('        }\n')
        tmpf.write('    }\n')
        tmpf.write('}\n')
        tmpf.sftp.close()
        dhcpfd.sftp.close()
        cmd = 'mv /tmp/dhcpd.conf /etc/dhcp/dhcpd.conf'
        self.runCommand(self.dhcpSrvCon, cmd)
        cmd = 'rm -rf /tmp/dhcpd.conf'
        self.runCommand(self.dhcpSrvCon, cmd)
        cmd = 'setenforce Permissive'
        self.runCommand(self.dhcpSrvCon, cmd)
        cmd = 'systemctl restart dhcpd'
        self.runCommand(self.dhcpSrvCon, cmd)
        cmd = 'systemctl status dhcpd'
        self.runCommand(self.dhcpSrvCon, cmd)
        self.dhcpSrvCon.close()

    def dhcp_cleanup(self):
        if self.show:
            logging.info(
                "Cleanup  DHCP entry which is created while Instllation Process")
        self.dhcpSrvCon = paramiko.SSHClient()
        self.dhcpSrvCon.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.dhcpSrvCon.connect(vmParser.confparser('dhcp', 'DHCPServer'),
                                username=vmParser.confparser('dhcp', 'User'),
                                password=vmParser.confparser('dhcp', 'Password'))
        dhcpsftp = self.dhcpSrvCon.open_sftp()
        with dhcpsftp.open('/etc/dhcp/dhcpd.conf', 'r') as dhcpfd:
            data = dhcpfd.read().decode("utf-8").strip()
        tmpf = dhcpsftp.open('/tmp/dhcpd.conf', 'w')
        reg = re.compile("""(^subnet[ \t0-9a-zA-Z.{]*\n)(^[ \t]+.+\n)*(^}$)""",
                         re.MULTILINE)
        for match in reg.finditer(data):
            start = match.start()
            end = match.end()
            dhcprecord = data[start:end]
            if vmParser.args.host_name not in dhcprecord:
                tmpf.write(dhcprecord)
            tmpf.write("\n")
        cmd = 'mv /tmp/dhcpd.conf /etc/dhcp/dhcpd.conf'
        self.runCommandcleanup(self.dhcpSrvCon, cmd)
        cmd = 'rm -rf /tmp/dhcpd.conf'
        self.runCommandcleanup(self.dhcpSrvCon, cmd)
        cmd = 'systemctl restart dhcpd'
        self.runCommandcleanup(self.dhcpSrvCon, cmd)
        cmd = 'systemctl status dhcpd'
        self.runCommandcleanup(self.dhcpSrvCon, cmd)
        self.dhcpSrvCon.close()

    def startInstallation(self):
        logging.info("Starting lpar_netboot command")
        self.hmcSrvCon = paramiko.SSHClient()
        self.hmcSrvCon.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.hmcSrvCon.connect(vmParser.args.lpar_hmc,
                               username=vmParser.args.hmc_userid,
                               password=vmParser.args.hmc_password)
        mac_address = vmParser.args.host_mac.replace(':', '')
        cmd = 'lpar_netboot -x -v -f -i -D -t ent -s auto -d auto -m %s -S ' % mac_address + \
            vmParser.confparser('dhcp', 'DHCPServer') + \
            ' -G ' + vmParser.args.host_gw + ' -C ' + vmParser.args.host_ip + \
            ' -K ' + vmParser.args.host_netmask + ' ' + vmParser.args.lpar_partition_name \
            + ' ' + vmParser.args.hmc_profile + ' ' + vmParser.args.lpar_managed_system
        print(cmd)
        self.runCommand(self.hmcSrvCon, cmd)
        time.sleep(5)

    def consoleMessages(self):
        self.insLog = paramiko.SSHClient()
        self.insLog.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.insLog.connect(vmParser.args.lpar_hmc,
                            username=vmParser.args.hmc_userid,
                            password=vmParser.args.hmc_password)
        cmd = 'rmvterm -m ' + vmParser.args.lpar_managed_system + \
            ' -p ' + vmParser.args.lpar_partition_name
        stdin, stdout, stderr = self.insLog.exec_command(cmd)
        cmd = 'mkvterm -m ' + vmParser.args.lpar_managed_system + \
            ' -p ' + vmParser.args.lpar_partition_name
        stdin, stdout, stderr = self.insLog.exec_command(cmd)
        try:
            for line in stdout:
                logging.debug(line.strip())
        except UnicodeDecodeError:
            pass

    def monitorInstallation(self):
        logging.info(
            "Installation will take approximatly 10-12 mins to complete.")
        logging.info("For realtime monitoring \"tail -f %s\"" % logfile)
        proc = Process(target=self.consoleMessages)
        proc.start()
        self.chkssh = paramiko.SSHClient()
        self.chkssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        iteration = 0
        while iteration <= 100:
            try:
                self.chkssh.connect(vmParser.args.host_ip,
                                    username='root', password=vmParser.args.host_password)
                self.chkssh.close()
                time.sleep(20)
                self.chkssh.connect(vmParser.args.host_ip,
                                    username='root', password=vmParser.args.host_password)
                logging.info("Installation was Succesfull")
                self.chkssh.close()
                proc.terminate()
                return None
            except paramiko.ssh_exception.BadHostKeyException as e:
                self.chkssh.close()
                self.chkssh = paramiko.SSHClient()
                self.chkssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            except Exception:
                time.sleep(30)
            iteration += 1
        logging.info("Installation Failed : Check logs for more details")

    def cleanup(self):
        self.dhcp_cleanup()
        if vmParser.args.showcleanup:
            logging.debug("Cleanup the Folder")
        cmd = 'rm -rf ' + self.baseURL + '/' + vmParser.netDir
        logging.debug('Running Command : %s' % cmd)
        stdin, stdout, stderr = self.nxtSrvCon.exec_command(cmd)
        rc = stdout.channel.recv_exit_status()
        if rc:
            if vmParser.args.showcleanup:
                logging.debug("Cleanup Failed : %s" % rc)
        else:
            if vmParser.args.showcleanup:
                logging.debug("Cleanup Successful : %s" % rc)

    def file_addinsystem(self):
        self.system = paramiko.SSHClient()
        self.system.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.system.connect(vmParser.args.host_ip, username='root',
                            password=vmParser.args.host_password)
        cmd = 'touch /etc/%s' % vmParser.args.distro
        self.runCommandcleanup(self.system, cmd)

    def cacert_addinsystem(self):
        self.system = paramiko.SSHClient()
        self.system.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.system.connect(vmParser.args.host_ip, username='root',
                            password=vmParser.args.host_password)
        cmd = 'openssl s_client -showcerts -servername %s -connect %s:443 > /etc/pki/trust/anchors/cacert.pem' % (
            vmParser.args.ssl_server, vmParser.args.ssl_server)
        self.runCommand(self.system, cmd)
        cmd = 'update-ca-certificates'
        self.runCommand(self.system, cmd)


class Rhel(Distro):

    def copyNetbootImage(self):
        logging.info("Copyt netboot image to tftp server")
        cutdir = len(list(filter(None, self.repoDir.split('/'))))
        cmd = 'sudo rm -rf ' + self.destDir
        self.runCommand(self.nxtSrvCon, cmd)
        cmd = 'sudo mkdir ' + self.destDir
        self.runCommand(self.nxtSrvCon, cmd)
        cmd = 'sudo wget -r --reject="index.html*"  --no-parent -nH --cut-dir=' + str(cutdir) \
            + ' http://' + vmParser.confparser('repo', 'RepoIP') + ':' \
            + vmParser.confparser('repo', 'RepoPort') \
            + self.repoDir + '/boot/' + ' -P ' + self.destDir
        self.runCommand(self.nxtSrvCon, cmd)
        cmd = 'sudo wget -r --reject="index.html*"  --no-parent -nH --cut-dir=' + str(cutdir) \
            + ' http://' + vmParser.confparser('repo', 'RepoIP') + ':' \
            + vmParser.confparser('repo', 'RepoPort') \
            + self.repoDir + '/ppc/' + ' -P ' + self.destDir
        self.runCommand(self.nxtSrvCon, cmd)
        cmd = 'sudo grub2-mknetdir --net-directory=' + self.baseURL + \
            ' --subdir=' + vmParser.netDir + '/boot/grub/'
        self.runCommand(self.nxtSrvCon, cmd)
        cmd = 'wget -r --reject="index.html*"  --no-parent -nH --cut-dir=' + str(cutdir) \
            + ' http://' + vmParser.confparser('repo', 'RepoIP') + ':' \
            + vmParser.confparser('repo', 'RepoPort') \
            + self.repoDir + '/boot/grub/powerpc-ieee1275/core.elf -P ' + \
            self.destDir+"/boot/grub/powerpc-ieee1275/"
        self.runCommand(self.nxtSrvCon, cmd)
        self.filename = vmParser.netDir + '/boot/grub/powerpc-ieee1275/core.elf'

    def createKickstart(self):
        logging.info("Prepareing kick start file")
        self.KsHost = paramiko.SSHClient()
        self.KsHost.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.KsHost.connect(vmParser.confparser('kshost', 'Host'),
                            username=vmParser.confparser(
            'kshost', 'User'),
            password=vmParser.confparser('kshost', 'Password'))

        sftp = self.KsHost.open_sftp()
        self.ksinst = vmParser.confparser(
            'kshost', 'KsDir') + '/' + distro+'/'+distro+'-' + vmParser.args.host_mac + '.ks'
        if vmParser.args.host_disk == '' and vmParser.args.multipathsetup == '':
            vmParser.args.host_disk = '/dev/sda'
        else:
            host_disk = ''
            disks = vmParser.args.host_disk.split(',')
            for disk in disks:
                host_disk += '/dev/disk/by-id/' + disk+','
            vmParser.args.host_disk = host_disk.rstrip(',')

        if vmParser.args.install_protocol == 'http':
            if version.startswith('8') or version.startswith('9') or version.startswith('10'):
                lstr = "%end"
                urlstring = "--url=http://"+vmParser.confparser('repo', 'RepoIP') + ':' + vmParser.confparser('repo', 'RepoPort') + \
                    self.repoDir + "/BaseOS"
            else:
                lstr = "telnet\njava\n%end"
                urlstring = "--url=http://"+vmParser.confparser('repo', 'RepoIP') + ':' + vmParser.confparser('repo', 'RepoPort') + \
                    self.repoDir

        if vmParser.args.install_protocol == 'ftp':
            # username:password@server/
            if version.startswith('8') or version.startswith('9') or version.startswith('10'):
                lstr = "%end"
                urlstring = "--url=ftp://" + \
                    vmParser.confparser('repo', 'RepoIP') + \
                    ':' + self.repoDir + "/BaseOS"
            else:
                lstr = "telnet\njava\n%end"
                urlstring = "--url=ftp://" + \
                    vmParser.confparser('repo', 'RepoIP') + ':' + self.repoDir

        if vmParser.args.install_protocol == 'nfs':
            if version.startswith('8') or version.startswith('9') or version.startswith('10'):
                lstr = "%end"
                urlstring = "--url=nfs://" + \
                    vmParser.confparser('repo', 'RepoIP') + \
                    ':/var/www/html' + self.repoDir + "/BaseOS"
            else:
                lstr = "telnet\njava\n%end"
                urlstring = "--url=nfs://" + \
                    vmParser.confparser('repo', 'RepoIP') + \
                    ':/var/www/html' + self.repoDir

        if vmParser.args.fs_type == 'btrfs':
            if vmParser.args.partition_type == 'plain':
                addksstring = "autopart --fstype=btrfs"
            else:
                addksstring = "autopart --type=lvm --fstype=btrfs"
        elif vmParser.args.fs_type == 'ext4':
            if vmParser.args.partition_type == 'plain':
                addksstring = "autopart --fstype=ext4"
            else:
                addksstring = "autopart --type=lvm --fstype=ext4"
        else:
            if vmParser.args.partition_type == 'plain':
                addksstring = "autopart --fstype=xfs"
            else:
                addksstring = "autopart --type=lvm --fstype=xfs"

        exit_nosupport = 0
        if vmParser.args.partition_type not in ['lvm', 'plain']:
            logging.info("Aborting Installation : as partition type %s is not supported or not valid" %
                         vmParser.args.partition_type)
            exit_nosupport = 1

        if vmParser.args.fs_type not in ['xfs', 'ext4', 'btrfs']:
            logging.info(
                "Aborting Installation : as filesystem type %s is not supported or not valid" % vmParser.args.fs_type)
            exit_nosupport = 1

        if vmParser.args.install_protocol not in ['http', 'nfs', 'ftp']:
            logging.info("Aborting Installation : as install protocol type %s is not supported or not valid" %
                         vmParser.args.install_protocol)
            exit_nosupport = 1

        if exit_nosupport:
            exit(1)

        ksparm = sftp.open('/var/www/html'+self.ksinst, 'w')
        sshd_file = ''
        kernel_params = ''
        if not vmParser.args.kernel_params:
            kernel_params = " --append="+'\"'+vmParser.args.kernel_params+'\"'
        mpath_file = ";multipath -t >/etc/multipath.conf;service multipathd start"
        if vmParser.args.multipathsetup != '':
            sshd_file = "\n%post \n"+mpath_file+"\n%end"
        if version.startswith('9') or version.startswith('10'):
            sshd_file = "\n%post \nsed -i 's/#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config;service sshd restart"+mpath_file+"\n%end"
        if version.startswith('10'):
            timezone = ""
        else:
            timezone = "--isUtc"

        inst_param = "%pre\n%end\nurl "+urlstring, "\ntext\nkeyboard"\
                     " --vckeymap=us --xlayouts='us'\nlang en_US.UTF-8\n"\
                     "rootpw --plaintext " + vmParser.args.host_password, \
                     "\nskipx\ntimezone Asia/Kolkata " + timezone, \
                     "\nzerombr" \
                     "\nclearpart --all --initlabel "\
                     "--drives=" + vmParser.args.host_disk, \
                     "\nbootloader   --location=mbr --boot-drive=" + vmParser.args.host_disk+kernel_params, \
                     "\nignoredisk --only-use=" + vmParser.args.host_disk, \
                     "\n" + addksstring, \
                     "\nservices --enabled=NetworkManager,sshd" \
                     "\nreboot\n%packages\n@core\nkexec-tools\ndevice-mapper-multipath\n"+lstr+sshd_file

        ksparm.writelines(inst_param)
        ksparm.sftp.close()

    def configGrub(self):
        self.createKickstart()
        logging.info("Prepareing GRUB")
        sftp = self.nxtSrvCon.open_sftp()
        self.runCommand(self.nxtSrvCon, "sudo chmod 777 -R %s" % self.destDir)
        gfd = sftp.open(self.destDir + '/boot/grub/grub.cfg', 'w')
        gfd.write('set timeout=1\n')
        gfd.write('menuentry \'Install OS\' {\n')
        gfd.write('    insmod http\n')
        gfd.write('    insmod tftp\n')
        gfd.write('    set root=tftp,' +
                  vmParser.confparser(vmParser.domain, 'NextServer') + '\n')
        gfd.write('    echo \'Loading OS Install kernel ...\'\n')
        installer_string = ''
        if version.startswith('10'):
            installer_string = ' inst.text inst.xtimeout=300'
        cli_nw = 'ifname=net0:' + vmParser.args.host_mac + ' ip=' + vmParser.args.host_ip + '::' + \
            vmParser.args.host_gw + ':' + vmParser.args.host_netmask + ':' + \
            vmParser.args.host_name + ':' + 'net0:none' + ' nameserver=' + \
            vmParser.confparser(vmParser.domain, 'DNS')
        strLnx = '    linux ' + vmParser.netDir + '/ppc/ppc64/vmlinuz ' + cli_nw + \
            ' inst.repo=http://' + vmParser.confparser('repo', 'RepoIP') + ':' + vmParser.confparser('repo', 'RepoPort') + \
            self.repoDir + \
            ' inst.ks=http://' + \
            vmParser.confparser('kshost', 'Host') + \
            self.ksinst + installer_string+'\n'
        gfd.write(strLnx)
        strInit = '    initrd ' + vmParser.netDir + '/ppc/ppc64/initrd.img\n'
        gfd.write(strInit)
        gfd.write('}\n')
        gfd.sftp.close()
        gfm = 'grub.cfg-01-' + (vmParser.args.host_mac).replace(':', '-')
        cmd = 'sudo cp ' + self.destDir + '/boot/grub/grub.cfg ' + \
            self.destDir + '/boot/grub/powerpc-ieee1275/' + gfm
        self.runCommand(self.nxtSrvCon, cmd)


class Sles(Distro):

    def copyNetbootImage(self):
        logging.info("Copyt netboot image to tftp server")
        cutdir = len(list(filter(None, self.repoDir.split('/'))))
        cmd = 'rm -rf ' + self.destDir
        self.runCommand(self.nxtSrvCon, cmd)
        cmd = 'mkdir ' + self.destDir
        self.runCommand(self.nxtSrvCon, cmd)
        if '16SP' in version.upper():
            cmd = 'wget -r --reject="index.html*"  --no-parent -nH --cut-dir=' + str(cutdir) + ' http://' + vmParser.confparser('repo', 'RepoIP') + ':' +  vmParser.confparser('repo', 'RepoPort') + self.repoDir + '/LiveOS/squashfs.img -P '  + self.destDir + '/LiveOS/'
            self.runCommand(self.nxtSrvCon, cmd)
            cmd = 'wget -r --reject="index.html*"  --no-parent -nH --cut-dir=' + str(cutdir) \
                + ' http://' + vmParser.confparser('repo', 'RepoIP') + ':' \
                + vmParser.confparser('repo', 'RepoPort') \
                + self.repoDir + '/boot/' + ' -P ' + self.destDir
            self.runCommand(self.nxtSrvCon, cmd)
            print("second cmd: {cmd}")
            cmd = 'grub2-mknetdir --net-directory=' + self.baseURL + ' --subdir=' + vmParser.netDir + '/boot/ppc64le/grub2-ieee1275/'
            print(cmd)
            self.runCommand(self.nxtSrvCon, cmd)  
            src_cfg = self.destDir + '/boot/grub2/grub.cfg'
            dest_cfg = self.destDir + '/boot/ppc64le/grub2-ieee1275/grub.cfg'
            cmd = f'cp {src_cfg} {dest_cfg}'
            self.runCommand(self.nxtSrvCon, cmd)  
            self.runCommand(self.nxtSrvCon, 'chmod 777 -R ' + self.destDir)
            self.filename = vmParser.netDir + '/boot/ppc64le/grub2-ieee1275/powerpc-ieee1275/core.elf' 
        elif '15SP' in version.upper():
            cmd = 'wget -r --reject="index.html*"  --no-parent -nH --cut-dir=' + str(cutdir) \
                + ' http://' + vmParser.confparser('repo', 'RepoIP') + ':' \
                + vmParser.confparser('repo', 'RepoPort') \
                + self.repoDir + '/boot/' + ' -P ' + self.destDir
            self.runCommand(self.nxtSrvCon, cmd)
            cmd = 'grub2-mknetdir --net-directory=' + self.baseURL + \
                ' --subdir=' + vmParser.netDir + '/boot/ppc64le/grub2-ieee1275/'
            self.runCommand(self.nxtSrvCon, cmd)
            cmd = 'wget -r --reject="index.html*"  --no-parent -nH --cut-dir=' + str(cutdir) \
                + ' http://' + vmParser.confparser('repo', 'RepoIP') + ':' \
                + vmParser.confparser('repo', 'RepoPort') \
                + self.repoDir + '/boot/ppc64le/grub2-ieee1275/core.elf -P ' + \
                self.destDir+"/boot/ppc64le/grub2-ieee1275/powerpc-ieee1275/"
            self.runCommand(self.nxtSrvCon, cmd)
            self.runCommand(self.nxtSrvCon, 'chmod 777 -R ' + self.destDir)
            self.filename = vmParser.netDir + \
                '/boot/ppc64le/grub2-ieee1275/powerpc-ieee1275/core.elf'
        else:
            cmd = 'wget -r --reject="index.html*"  --no-parent -nH --cut-dir=' + str(cutdir) \
                + ' http://' + vmParser.confparser('repo', 'RepoIP') + ':' \
                + vmParser.confparser('repo', 'RepoPort') \
                + self.repoDir + '/suseboot/' + ' -P ' + self.destDir
            self.runCommand(self.nxtSrvCon, cmd)
            cmd = 'mv ' + self.destDir + '/suseboot/yaboot.ibm ' + \
                self.destDir + '/suseboot/yaboot.suse'
            self.runCommand(self.nxtSrvCon, cmd)
            self.filename = vmParser.netDir + '/suseboot/yaboot.suse'

    def createAutoyastJsonnet(self):
        logging.info("Generating dynamic autoyast.jsonnet for SLES16")
        self.KsHost = paramiko.SSHClient()
        self.KsHost.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.KsHost.connect(vmParser.confparser('kshost', 'Host'),
                            username=vmParser.confparser('kshost', 'User'),
                            password=vmParser.confparser('kshost', 'Password'))
        sftp = self.KsHost.open_sftp()
        self.ksinst = vmParser.confparser('kshost', 'KsDir') + '/sles/' + vmParser.args.host_mac + '.jsonnet'
        remote_path = '/var/www/html' + self.ksinst

        ip_cidr = f"{vmParser.args.host_ip}/{netaddr.IPNetwork(vmParser.args.host_ip + '/' + vmParser.args.host_netmask).prefixlen}"
        if vmParser.args.host_disk:
            if "-" not in vmParser.args.host_disk:
                print(f"ERROR: '{vmParser.args.host_disk}' looks like a device name. Provide a valid disk ID from /dev/disk/by-id/", file=sys.stderr)
                sys.exit(1)
            disk_id = f"/dev/disk/by-id/{vmParser.args.host_disk}"
        if vmParser.args.host_disk == '' and vmParser.args.multipathsetup == '':
            disk_id = '/dev/sda'
        nameserver = vmParser.confparser(vmParser.domain, 'DNS')
        pre_script_block = ''
        post_script_block = ''
        scripts_block = ''
        pre_script_block = """{
            name: "activate-multipath",
            content: |||
                #!/usr/bin/bash
                systemctl start multipathd.socket multipathd.service
            |||
        }"""
        post_script_block = """{
            name: "permit-root-login",
            content: |||
                #!/bin/bash
                ssh_file="/usr/etc/ssh/sshd_config"
                backup_file="/usr/etc/ssh/sshd_config.bak.$(date +%F_%T)"
                cp "$ssh_file" "$backup_file"
                if grep -q "^PermitRootLogin" "$ssh_file"; then
                    sed -i "s/^PermitRootLogin.*/PermitRootLogin yes/" "$ssh_file"
                else
                    echo "PermitRootLogin yes" >> "$ssh_file"
                fi
                systemctl enable sshd.service
            |||
        }"""
        if "mpath" in vmParser.args.host_disk:
            scripts_block = f"""  scripts: {{
                pre: [
                    {pre_script_block}
                ],
                post: [
                    {post_script_block}
                ]
            }}"""
        else:
            scripts_block = f"""  scripts: {{
                post: [
                    {post_script_block}
                ]
            }}"""


        jsonnet_content = f'''{{
  "bootloader": {{ "stopOnBootMenu": false }},
  "user": {{ "fullName": "abc", "userName": "abc", "password": "abc123", "hashedPassword": false, "autologin": false }},
  "root": {{ "hashedPassword": false, "password": "{vmParser.args.host_password}" }},
  "software": {{ "patterns": [], "package":"openssl" }},
  "product": {{ "id": "SLES" }},
  "storage": {{
    "drives": [{{ "search": "{disk_id}", "partitions": [{{ "search": "*", "delete": true }}, {{ "filesystem": {{ "path": "/" }}, "size": {{ "min": "10 GiB" }} }}, {{ "filesystem": {{ "path": "swap" }}, "size": {{ "min": "1 GiB", "max": "4 GiB" }} }}] }}]
  }},
  "network": {{
    "connections": [{{ "id": "Wired Connection", "method4": "manual", "gateway4": "{vmParser.args.host_gw}", "method6": "disabled", "addresses": ["{ip_cidr}"], "nameservers": ["{nameserver}"], "ignoreAutoDns": false, "status": "up", "autoconnect": true }}]
  }},
  "localization": {{ "language": "en_US.UTF-8", "keyboard": "us", "timezone": "Europe/Berlin" }},
{scripts_block}
}}'''
        with sftp.open(remote_path, 'w') as jfd:
            jfd.write(jsonnet_content)

        sftp.close()


    def createKickstart(self):
        logging.info("Prepareing kick start file")
        self.KsHost = paramiko.SSHClient()
        self.KsHost.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.KsHost.connect(vmParser.confparser('kshost', 'Host'),
                            username=vmParser.confparser(
            'kshost', 'User'),
            password=vmParser.confparser('kshost', 'Password'))

        sftp = self.KsHost.open_sftp()
        self.ksinst = vmParser.confparser(
            'kshost', 'KsDir') + '/' + distro+'/'+distro+'-' + vmParser.args.host_mac + '.ks'

        partition_string = ''
        multipath_string = ''
        kernel_params = 'mitigations=auto quiet crashkernel=1024M '
        if not vmParser.args.kernel_params:
            kernel_params = "%s %s" % (
                kernel_params, vmParser.args.kernel_params)

        if vmParser.args.multipathsetup != '':
            multipath_string = "<storage>\n<start_multipath config:type=\"boolean\">true</start_multipath>\n</storage>"
        if vmParser.args.host_disk != '':
            vmParser.args.host_disk = '/dev/disk/by-id/' + vmParser.args.host_disk
            partition_string = "<device>"+vmParser.args.host_disk+"</device>\n<use>all</use>"
        else:
            partition_string = "<use>all</use>\n<partitions config:type=\"list\">\n<partition>\n<mount>/</mount>\n<size>max</size>\n</partition>\n</partitions>\n"

        host_name = ''
        if vmParser.args.host_name:
            host_name = vmParser.args.host_name
        else:
            host_name = "localhost"
        urlstring = ''
        sles15_url = ''
        sles_package = ''
        urlstring = "http://"+vmParser.confparser('repo', 'RepoIP') + ':' + vmParser.confparser('repo', 'RepoPort') + \
            self.repoDir + "/sdk"
        if '15' in version:
            subversion = ''
            python_str = ''
            if version[2:5]:
                subversion = version[2:5].upper()+"-"
                if 'SP' in subversion:
                    urlstring = "http://"+vmParser.confparser(
                        'repo', 'RepoIP') + ':' + vmParser.confparser('repo', 'RepoPort')+self.repoDir
                if 'SP1' in subversion:
                    urlstring = "http://"+vmParser.confparser(
                        'repo', 'RepoIP') + ':' + vmParser.confparser('repo', 'RepoPort')+self.repoDir+'/sdk'
                    python_str = "<listentry>\n" \
                        "<media_url><![CDATA["+urlstring+"]]></media_url>\n" \
                        "<product>sle-module-python2</product>\n<product_dir>/Module-Python2</product_dir>\n" \
                        "</listentry>\n"
                value = ["SP4", "SP3", "SP1", "SP5"]
                if any(x in subversion for x in value):
                    python_str = ''
                subversion = ''

            sles15_url = "<add-on>\n<add_on_products config:type=\"list\">\n<listentry>\n" \
                "<media_url><![CDATA["+urlstring+"]]></media_url>\n" \
                "<product>sle-module-server-applications</product>\n<product_dir>/"+subversion+"Module-Server-Applications</product_dir>\n" \
                "</listentry>\n<listentry>\n" \
                "<media_url><![CDATA["+urlstring+"]]></media_url>\n" \
                "<product>sle-module-legacy</product>\n<product_dir>/"+subversion+"Module-Legacy</product_dir>\n" \
                "</listentry>\n<listentry>\n" \
                "<media_url><![CDATA["+urlstring+"]]></media_url>\n" \
                "<product>sle-module-development-tools</product>\n<product_dir>/"+subversion+"Module-Development-Tools</product_dir>\n" \
                "</listentry>\n<listentry>\n" \
                "<media_url><![CDATA["+urlstring+"]]></media_url>\n" \
                "<product>sle-module-desktop-applications</product>\n<product_dir>/"+subversion+"Module-Desktop-Applications</product_dir>\n" \
                "</listentry>\n<listentry>\n" \
                "<media_url><![CDATA["+urlstring+"]]></media_url>\n" \
                "<product>sle-module-basesystem</product>\n<product_dir>/"+subversion+"Module-Basesystem</product_dir>\n" \
                "</listentry>\n"+python_str + \
                "</add_on_products>\n</add-on>\n"

            sles_package = "<package>sles-release</package><package>sle-module-server-applications-release</package>\n" \
                "<package>sle-module-legacy-release</package>\n" \
                "<package>sle-module-development-tools-release</package><package>sle-module-desktop-applications-release</package>\n" \
                "<package>sle-module-basesystem-release</package><package>java-11-openjdk</package></packages><patterns config:type=\"list\"><pattern>apparmor</pattern>\n" \
                "<pattern>base</pattern>\n" \
                "<pattern>basesystem</pattern><pattern>enhanced_base</pattern><pattern>fonts</pattern><pattern>gnome_basic</pattern>\n" \
                "<pattern>gnome_basis</pattern><pattern>minimal_base</pattern><pattern>sw_management</pattern><pattern>x11</pattern>\n" \
                "<pattern>x11_enhanced</pattern><pattern>x11_yast</pattern><pattern>yast2_basis</pattern></patterns>\n"
        else:
            sles15_url = "<add-on>\n<add_on_products config:type=\"list\">\n<listentry>\n" \
                "<media_url><![CDATA["+urlstring+"]]></media_url>\n" \
                "<product>sle-module-server-applications</product>\n<product_dir>/</product_dir>\n" \
                "</listentry>\n</add_on_products>\n</add-on>\n"
            sles_package = "<package>java-1_8_0-openjdk</package></packages>\n"
        print(self.ksinst)
        ksparm = sftp.open('/var/www/html'+self.ksinst, 'w')
        inst_param = "<?xml version=\"1.0\"?>\n<!DOCTYPE profile>\n" \
                     "<profile xmlns=\"http://www.suse.com/1.0/yast2ns\" xmlns:config=\"http://www.suse.com/1.0/configns\">\n"+sles15_url+""\
                     "<bootloader>\n<global>\n<append>"+kernel_params+"</append>\n" \
                     "<xen_kernel_append>crashkernel=1024M\&lt;4G</xen_kernel_append>\n</global>\n</bootloader>\n" \
                     "<kdump>\n<add_crash_kernel t=\"boolean\">true</add_crash_kernel>\n<crash_kernel>1024M</crash_kernel>\n" \
                     "<crash_xen_kernel>1024M\&lt;4G</crash_xen_kernel>\n</kdump> \n" \
                     "<users config:type=\"list\">\n<user>\n<encrypted config:type=\"boolean\">false</encrypted>\n" \
                     "<user_password>"+vmParser.args.host_password+"</user_password>\n<username>root</username>\n</user>\n</users>\n" \
                     "<general>\n<mode>\n<confirm config:type=\"boolean\">false</confirm>\n</mode>\n"+multipath_string+"</general>\n" \
                     "<partitioning config:type=\"list\">\n<drive>\n"+partition_string+"</drive>\n</partitioning>\n" \
                     "<services-manager>\n<default_target>multi-user</default_target>\n<services>\n<disable config:type=\"list\">\n" \
                     "<service>sshd</service>\n</disable>\n</services>\n</services-manager>\n<firewall>\n" \
                     "<enable_firewall config:type=\"boolean\">false</enable_firewall>\n<start_firewall config:type=\"boolean\">false</start_firewall>\n" \
                     "</firewall>\n<networking>\n<dns>\n<hostname>"+host_name+"</hostname>\n</dns>\n<managed config:type=\"boolean\">false</managed>\n<routing>\n" \
                     "<ip_forward config:type=\"boolean\">false</ip_forward>\n</routing>\n" \
                     "<keep_install_network config:type=\"boolean\">true</keep_install_network>\n</networking>\n<software>\n" \
                     "<packages config:type=\"list\">\n<package>gcc</package>\n<package>multipath-tools</package>\n<package>kdump</package>\n" \
                     "<package>gcc-c++</package>\n"+sles_package+"</software>\n<scripts>\n<post-scripts config:type=\"list\">\n<script>\n" \
                     "<filename>setupssh.sh</filename>\n<interpreter>shell</interpreter>\n<debug config:type=\"boolean\">true</debug>\n" \
                     "<source><![CDATA[\nsystemctl enable sshd.service\nsystemctl start sshd.service\n]]></source>\n" \
            "</script>\n</post-scripts>\n</scripts>\n</profile>\n"
        ksparm.writelines(inst_param)
        ksparm.sftp.close()

    def configGrub(self):
        if '16' in version:
            if '16SP1' in version:
                installurl="inst.install_url"
            else:
                installurl="agama.install_url"
            self.createAutoyastJsonnet()
            logging.info("Preparing GRUB for SLES16")
            sftp = self.nxtSrvCon.open_sftp()
            gfd = sftp.open(self.destDir + '/boot/ppc64le/grub2-ieee1275/grub.cfg','w')
            gfd.write('set timeout=1  ')
            gfd.write('\n')
            gfd.write('menuentry \'Install SLES16\' {')
            gfd.write('\n')
            gfd.write('    insmod http')
            gfd.write('\n')
            gfd.write('    insmod tftp')
            gfd.write('\n')
            gfd.write('    set root=tftp,' + vmParser.confparser(vmParser.domain, 'NextServer') + '')
            gfd.write('\n')
            gfd.write('    echo \'Loading SLES16 kernel ...\'')
            httppath="(http,"+vmParser.confparser('repo', 'RepoIP')+":"+ vmParser.confparser('repo', 'RepoPort')+")"
            httplinux="/"+self.repoDir+'/boot/ppc64le/linux '
            httpintrd="/"+self.repoDir+'/boot/ppc64le/initrd'
            gfd.write('\n')
            cli_nw = 'rd.neednet=1 ' + 'ip=' + vmParser.args.host_ip + '::' + vmParser.args.host_gw + ':' + vmParser.args.host_netmask + \
                    ':' + vmParser.args.host_name + '::none' + ' nameserver=' + vmParser.confparser(vmParser.domain, 'DNS')
            strLnx = '    linux ' + vmParser.netDir + '/boot/ppc64le/linux '+ cli_nw + \
                    ' '+installurl+'=http://' + vmParser.confparser('repo', 'RepoIP') + ':' + vmParser.confparser('repo', 'RepoPort') + \
                    self.repoDir +'/install  root=live:http://' + vmParser.confparser('repo', 'RepoIP') + ':' + vmParser.confparser('repo', 'RepoPort')  + \
                    self.repoDir + '/LiveOS/squashfs.img  live.password=abc123' + \
                    ' inst.auto=http://' +vmParser.confparser('kshost', 'Host') + self.ksinst + '\n'
            gfd.write(strLnx)
            strInit = '    initrd ' + vmParser.netDir + '/boot/ppc64le/initrd\n'
            gfd.write(strInit)
            gfd.write('}')
            gfd.close()
            sftp.close()
        elif '11SP' not in version.upper():
            self.createKickstart()
            sftp = self.nxtSrvCon.open_sftp()
            logging.info("Prepareing GRUB for sles15")
            gfd = sftp.open(
                self.destDir + '/boot/ppc64le/grub2-ieee1275/grub.cfg', 'w')
            gfd.write('set timeout=1\n')
            gfd.write('menuentry \'Install OS\' {\n')
            gfd.write('    insmod http\n')
            gfd.write('    insmod tftp\n')
            gfd.write('    set root=tftp,' +
                      vmParser.confparser(vmParser.domain, 'NextServer') + '\n')
            gfd.write('    echo \'Loading OS Install kernel ...\'\n')
            cli_nw = ' Display_IP=' + vmParser.args.host_ip + ' Netmask=' + vmParser.args.host_netmask + \
                ' HostIP=' + vmParser.args.host_ip + ' Gateway=' + vmParser.args.host_gw + \
                ' nameserver=' + vmParser.confparser(vmParser.domain, 'DNS')
            strLnx = '    linux ' + vmParser.netDir + '/boot/ppc64le/linux ' + cli_nw + \
                ' install=http://' + vmParser.confparser('repo', 'RepoIP') + ':' + vmParser.confparser('repo', 'RepoPort') + \
                self.repoDir
            # if '15' in version:
            #    strLnx = strLnx+ ' autoyast=http://' + vmParser.confparser('repo', 'RepoIP') + ':' + vmParser.confparser('repo', 'RepoPort') + \
            #            '/powervmks/sles%s.ks\n' % "15"
            # else:
            strLnx = strLnx + ' autoyast=http://' + \
                vmParser.confparser('kshost', 'Host') + self.ksinst + '\n'
            gfd.write(strLnx)
            strInit = '    initrd ' + vmParser.netDir + '/boot/ppc64le/initrd\n'
            gfd.write(strInit)
            gfd.write('}\n')
            gfd.sftp.close()
        else:
            gfd = sftp.open(self.baseURL + '/yaboot.conf', 'w')
            gfd.write('message=suseboot/yaboot.txt\n\n')
            gfd.write('default=install\n')
            gfd.write('timeout=10\n')
            gfd.write('image[64bit]=' + vmParser.netDir +
                      '/suseboot/linux64\n')
            gfd.write(' label=install\n')
            gfd.write(' initrd=' + vmParser.netDir + '/suseboot/initrd64\n')
            cli_nw = ' gateway=' + vmParser.args.host_gw + ' hostip=' + vmParser.args.host_ip + \
                ' netmask=' + vmParser.args.host_netmask + ' dns=' + \
                vmParser.confparser(vmParser.domain, 'DNS')
            cli_mod = 'sysrq=1 install=slp insmod=sym53c8xx insmod=ipr insmod=tftp insmod=http slp=1 splash=0 TERM=linux textmode=1'
            cli_repo = ' install=http://' + vmParser.confparser('repo', 'RepoIP') + ':' + vmParser.confparser('repo', 'RepoPort') + \
                self.repoDir
            cli_yast = ' autoyast=http://' + vmParser.confparser('repo', 'RepoIP') + ':' + vmParser.confparser('repo', 'RepoPort') + \
                '/powervmks/sles99.ks'
            gfd.write(' append="' + cli_mod + cli_repo +
                      cli_nw + cli_yast + '"\n')
            gfd.sftp.close()
            gfm = '/yaboot.conf-' + (vmParser.args.host_mac).replace(':', '-')
            cmd = 'mv ' + self.baseURL + '/yaboot.conf ' + self.baseURL + gfm
            self.runCommand(self.nxtSrvCon, cmd)


def logger():
    if not os.path.isdir("./log"):
        os.makedirs("./log")
    logfile = datetime.now().strftime('./log/installvm-%Y%m%d-%H%M%S.log')
    logging.basicConfig(filename=logfile,
                        format="%(asctime)s [%(levelname)-5.5s]  %(message)s", level=logging.DEBUG)
    conlog = logging.StreamHandler()
    conlog.setLevel(logging.INFO)
    formatter = logging.Formatter('%(message)s')
    conlog.setFormatter(formatter)
    logging.getLogger('').addHandler(conlog)
    logging.getLogger('paramiko').setLevel(logging.ERROR)
    logging.config.dictConfig({
        'version': 1,
        'disable_existing_loggers': True,
    })

    return logfile


def copylog():
    LogHost = paramiko.SSHClient()
    LogHost.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    LogHost.connect(vmParser.confparser('LogHost', 'Host'),
                    username=vmParser.confparser(
        'LogHost', 'User'),
        password=vmParser.confparser('LogHost', 'Password'))

    sftp = LogHost.open_sftp()
    filepath = '/var/www/html' + \
        vmParser.confparser('LogHost', 'LogDir')+'/'+logfile.rsplit('/')[2]
    localpath = logfile
    sftp.put(localpath, filepath)
    sftp.close()
    cmd = 'http://'+vmParser.confparser('LogHost', 'Host')+vmParser.confparser(
        'LogHost', 'LogDir')+'/'+logfile.rsplit('/')[2]
    if vmParser.args.showcleanup:
        logging.info("find installation  log here  %s" % cmd)


if __name__ == "__main__":
    logfile = logger()
    vmParser = configparser.CmdLineArgParser()
    vmParser.parse_args(sys.argv)
    vmParser.args.showcleanup = int(vmParser.args.showcleanup)
    distro, version, build = (vmParser.args.distro).split('_')
    if distro.upper() == 'RHEL' or distro.upper() == 'RHEL-ALT':
        vmInst = Rhel()
    elif distro.upper() == 'SLES':
        vmInst = Sles()
    else:
        logging.info("%s Installation Not Supported" % distro)
        exit(1)
    logging.info("Starting Installation of %s " %
                 (vmParser.args.distro).upper())
    vmParser.validate()
    vmInst.copyNetbootImage()
    vmInst.configGrub()
    vmInst.configDHCP()
    vmInst.startInstallation()
    vmInst.monitorInstallation()
    vmInst.cleanup()
    vmInst.file_addinsystem()
    if vmParser.args.ssl_server and distro.upper() == 'SLES':
       if '16' not in version: 
           vmInst.cacert_addinsystem()
    copylog()
