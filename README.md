# Automated Linux installation on PowerVM Logical partition(LPAR)

#### python installvm.py -h 
```
usage: installvm.py [-h] --host-ip HOST_IP --host-name HOST_NAME --host-gw
                    HOST_GW [--host-netmask HOST_NETMASK] --host-mac HOST_MAC
                    --host-disk HOST_DISK --lpar-hmc LPAR_HMC
                    --lpar-managed-system LPAR_MANAGED_SYSTEM
                    --lpar-partition-name LPAR_PARTITION_NAME
                    [--hmc-userid HMC_USERID] [--hmc-password HMC_PASSWORD]
                    [--hmc-profile HMC_PROFILE] --distro DISTRO

optional arguments:
  -h, --help            show this help message and exit
  --distro DISTRO       distro to be installed ex: rhel_7.4le_alpa,
                        sles_11sp3_beta

Host Specific Information for Installation:

  --host-ip HOST_IP     Host IP address
  --host-name HOST_NAME
                        Host FQDN
  --host-gw HOST_GW     Host Gateway IP
  --host-netmask HOST_NETMASK
                        Host network subnetmask
  --host-mac HOST_MAC   Host MAC address
  --host-disk HOST_DISK
                        Host disk by-id to install ex: scsi-SAIX_VDASD_00f869b300004c000000014612c44ea1.1
			get it from system using ll /dev/disk/by-id/

Managed System Details:

  --lpar-hmc LPAR_HMC   HMC Name or IP
  --lpar-managed-system LPAR_MANAGED_SYSTEM
                        LPAR Managed system name
  --lpar-partition-name LPAR_PARTITION_NAME
                        LPAR Partition Name
  --hmc-userid HMC_USERID
                        HMC userid
  --hmc-password HMC_PASSWORD
                        HMC password
  --hmc-profile HMC_PROFILE
                        HMC Profile Name


Example :
python installvm.py --host-ip <host ip> --host-name <host name > --host-gw <system gateway> 
--host-netmask <netmask> --host-mac <mac> --lpar-hmc <hmc where lpar hosted> 
--lpar-managed-system <managed system name> --lpar-partition-name <partition name> 
--distro <build name (hosted in /repo/crlt path)> --host-disk=<disk name> --hmc-profile <lpar profile>
```
