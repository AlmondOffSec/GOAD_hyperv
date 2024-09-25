# GOAD Hyper-V

Vagrant style script to build [GOAD](https://github.com/Orange-Cyberdefense/GOAD) on Hyper-V. 

This script is intended to run on a properly licensed Windows Server Datacenter Hyper-V host: GOAD VMs are converted from Eval to Retail and activated, so rebuilding GOAD every 180 days is no longer needed.

## Prerequisites

* A properly licensed Windows Server Datacenter host (mandatory to activate GOAD VMs)
* An "external" vSwitch (DHCP is optionnal)
* [Syspreped](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/sysprep--system-preparation--overview) VM templates for [Windows Server 2019 Eval](https://app.vagrantup.com/StefanScherer/boxes/windows_2019/versions/2020.02.12) and [Windows Server 2016 Eval](https://app.vagrantup.com/StefanScherer/boxes/windows_2016/versions/2017.12.14). Those two VMs need to be [exported](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/deploy/export-and-import-virtual-machines#export-a-virtual-machine).

## Credits

[Mayfly](https://x.com/M4yFly) / Orange-Cyberdefense for the [GOAD project](https://github.com/Orange-Cyberdefense/GOAD)