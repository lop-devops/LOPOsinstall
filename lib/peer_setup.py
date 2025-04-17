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
import logging
import argparse
import fileinput
import subprocess
import shutil

logging.getLogger().setLevel(logging.INFO)
base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
http_conf = '/etc/httpd/conf/httpd.conf'
http_path = '/var/www/html'
install_conf = '%s/installvm.conf' % base
pattern = ['NextServer', 'DHCPServer', 'Host', 'Password']
pips = ['--upgrade pip', '--upgrade setuptools',
        'cryptography==2.4.2', 'paramiko', 'aexpect']
deps = [
    'ksh', 'wget', 'xinetd', 'dhcp', 'dhcp-common', 'dhcp-libs', 'dnsmasq', 'tftp', 'tftp-server', 'vsftpd', 'python2-pip', 'expect', 'pexpect', 'python-setuptools',
    'gcc', 'python-devel', 'python-cffi', 'libffi-devel', 'openssl-devel', 'pyOpenSSL', 'openssl', 'openssl-libs', 'python-netaddr', 'httpd', 'httpd-devel', 'initscripts', 'net-tools', 'sshpass']
deps_to_remove = ['python-gssapi']


class peerSetup():

    def __init__(self, mac, ip, mask, password, repo, port, path):
        self.mac = mac
        self.ip = ip
        self.mask = mask
        self.passwd = password
        self.repo = repo
        self.port = port
        self.repo_path = path
        shutil.copy(install_conf, "/tmp/install_conf")

    def run_cmd(self, cmd):
        logging.info("Run Command : %s" % cmd)
        p = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = p.communicate()[0]
        rc = p.wait()
        if rc:
            logging.info("%s Command failed exiting" % cmd)
            sys.exit(1)
        return (output, rc)

    def tearDown(self):
        interface = None
        out, rc = self.run_cmd('ip a')
        ifaces = out.split('\n')
        for index, lines in enumerate(ifaces):
            if self.ip in lines:
                interface = lines.split(" ")[-1]
        if interface:
            cmd = "ip link set dev %s down && ip addr flush dev %s" % (
                interface, interface)
            self.run_cmd(cmd)
        shutil.copy("/tmp/install_conf", install_conf)

    def setDeps(self):
        rpm = 'epel-release-latest-7.noarch.rpm'
        url = 'http://%s:81/%s/io' % (self.repo, self.repo_path)
        eplrepo = 'wget %s/%s -O /tmp/%s' % (url, rpm, rpm)
        self.run_cmd(eplrepo)
        path1 = '/tmp/%s' % rpm
        if os.path.exists(path1):
            cmd = 'rpm -ivh --reinstall %s' % path1
            self.run_cmd(cmd)
        rhrepo = 'wget %s/rh75.repo -O /etc/yum.repos.d/rh75.repo' % url
        self.run_cmd(rhrepo)
        out, rc = self.run_cmd('yum repolist all')
        if 'enabled:' not in out:
            logging.info("Package Repository not set")
            sys.exit(1)
        for pkg in deps:
            cmd = "yum install -y %s" % pkg
            self.run_cmd(cmd)
        for rm_pkg in deps_to_remove:
            cmd = "yum remove -y %s" % rm_pkg
            self.run_cmd(cmd)
        for pip in pips:
            cmd = 'pip install %s' % pip
            self.run_cmd(cmd)

    def setNetwork(self):
        out, rc = self.run_cmd('ip a')
        ifaces = out.split('\n')
        for index, lines in enumerate(ifaces):
            if self.mac in lines:
                iface = ifaces[index - 1].split(":")[1].strip()
        cmd = "ip addr add %s/%s dev %s" % (self.ip, self.mask, iface)
        self.run_cmd(cmd)
        out, rc = self.run_cmd('ip a')
        if self.ip not in out:
            logging.info("IP not set")
            sys.exit(1)
        cmd = "ip link set dev %s up" % iface
        self.run_cmd(cmd)

    def setHttp(self, distro):
        for line in fileinput.input(http_conf, inplace=True):
            if line.strip().startswith('Listen'):
                line = "Listen %s:%s\n" % (self.ip, self.port)
            sys.stdout.write(line)
        for file_name in ['installlog', 'powervmks/rhel', 'powervmks/sles']:
            path = "%s/%s" % (http_path, file_name)
            if not os.path.exists(path):
                cmd = "mkdir -p %s" % path
                self.run_cmd(cmd)

    def setRepo(self, distro):
        distro, version, build = distro.split('_')
        path = "%s/%s/%s/%s" % (http_path, self.repo_path, distro, version)
        build_path = '%s/%s' % (path, build)
        if not os.path.exists(build_path):
            cmd = "mkdir -p %s" % build_path
            self.run_cmd(cmd)
            logging.info("Distro packages downloading...")
            cmd = 'rsync -az --exclude "*.iso" --rsh="sshpass -p passw0rd ssh -o StrictHostKeyChecking=no -l root" %s:%s %s' % (
                self.repo, build_path, path)
            self.run_cmd(cmd)
        else:
            cmd = "ls %s" % build_path
            self.run_cmd(cmd)
            logging.info("%s Repo is already set" % build_path)

    def setTftp(self):
        path = '/var/lib/tftpboot'
        if not os.path.exists(path):
            cmd = "mkdir -p %s" % path
            self.run_cmd(cmd)
        with open('/etc/xinetd.d/tftp', 'w') as tftp:
            tftp.write('{\n')
            tftp.write('	socket_type = dgram\n')
            tftp.write('	protocol = udp\n')
            tftp.write('	wait = yes\n')
            tftp.write('	user = root\n')
            tftp.write('	server = /usr/sbin/in.tftpd\n')
            tftp.write('	server_args = -c -svv /tftpboot\n')
            tftp.write('	disable = no\n')
            tftp.write('	flags = IPv4\n')
            tftp.write('}\n')

    def setConfig(self):
        for line in fileinput.input(install_conf, inplace=True):
            for string in pattern:
                if line.strip().startswith(string):
                    if 'RepoPort' in string:
                        tmp = self.port
                    elif 'Password' in string:
                        tmp = self.passwd
                    else:
                        tmp = self.ip
                    line = "%s: %s\n" % (string, tmp)
            sys.stdout.write(line)

    def setServices(self):
        self.run_cmd('service firewalld stop')
        for service in ['httpd', 'xinetd', 'tftp', 'dhcpd']:
            cmd = 'service %s restart' % service
            self.run_cmd(cmd)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        '--mac-addr', help='Provide the mac address id of the nic card', required=True)
    parser.add_argument(
        '--ip-addr', help='Provide the IP address to be set for given mac', required=True)
    parser.add_argument(
        '--http-port', help='Provide the http port if not default', default='80')
    parser.add_argument(
        '--peer-passwd', help='Provide peer root password if not default', default='passw0rd')
    parser.add_argument(
        '--net-mask', help='Provide netmask if not default', default='255.255.255.0')
    parser.add_argument(
        '--distro', help='Provide the distro string like rhel_8.0.0le_rc-1.0/sles_15sp1_beta4', required=True)
    parser.add_argument(
        '--repo-ip', help='Provide the HTTP pacakge repo IP, default is jenkins', default='9.40.192.92')
    parser.add_argument(
        '--repo-path', help='Provide the package repo path, default is /crtl/repo', default='/crtl/repo')
    parser.add_argument(
        '--clean', dest='clean', action='store_true', help='Option to clean up the network interface', default=False)
    args = parser.parse_args()
    nic_mac = args.mac_addr
    nic_ip = args.ip_addr
    nic_mask = args.net_mask
    passwd = args.peer_passwd
    repo_ip = args.repo_ip
    http_port = args.http_port
    repo_path = args.repo_path
    distro = args.distro
    peer = peerSetup(nic_mac, nic_ip, nic_mask, passwd,
                     repo_ip, http_port, repo_path)
    if args.clean:
        peer.tearDown()
        sys.exit(0)
    logging.info("Clear old MAC network setup")
    peer.tearDown()
    logging.info("Network Setup for MAC : %s" % nic_mac)
    peer.setNetwork()
    logging.info("Install require packages")
    peer.setDeps()
    logging.info("Set http configuration")
    peer.setHttp(distro)
    logging.info("Set distro packages for installation")
    if not nic_ip.strip().startswith('9.'):
        pattern.extend(['RepoIP', 'RepoPort'])
        peer.setRepo(distro)
    logging.info("Set tftp configurations")
    peer.setTftp()
    logging.info("Set install.conf configuration")
    peer.setConfig()
    logging.info("Start server services")
    peer.setServices()


if __name__ == "__main__":
    main()
