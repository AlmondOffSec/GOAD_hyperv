$boxes =  @{"name" = "GOAD-DC01"; "internal_ip" = "192.168.56.10"; "version" = "2019"; "external_ip"="172.20.170.1"},
          @{"name" = "GOAD-DC02"; "internal_ip" = "192.168.56.11"; "version" = "2019"; "external_ip"="172.20.170.2"},
          @{"name" = "GOAD-DC03"; "internal_ip" = "192.168.56.12"; "version" = "2016"; "external_ip"="172.20.170.3"},
          @{"name" = "GOAD-SRV02"; "internal_ip" = "192.168.56.22"; "version" = "2019"; "external_ip"="172.20.170.4"},
          @{"name" = "GOAD-SRV03"; "internal_ip" = "192.168.56.23"; "version" = "2016"; "external_ip"="172.20.170.5"}


# This interface provides Internet to your GOAD lab
# You can safely change it
$nat_interface = "Ethernet"
$nat_gateway = "172.20.170.254"
$nat_netmask = "255.255.255.0"
$nat_dns = "1.1.1.1"

# This is the GOAD domain's LAN
$dom_interface = "Ethernet 2"
$dom_netmask = "255.255.255.0"

# Default vagrant credential
$default_username = "vagrant"
$default_password = "vagrant"
$password = ConvertTo-SecureString $default_password -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($default_username, $password)

# You need to create this vswitch within the Hyper-V interface!
$name_external_vswitch = "GOAD_EXTERNAL"
# This vswitch will be automaticaly created by this script
$name_private_vswitch = "GOAD_INTERNAL"

# Full path to your Vagrant exported VMs, VM must be "syspreped"
$vagrant_path_2019 = "D:\Hyper-V\export\W2019-VAGRANT\Virtual Machines\AD4D00A7-287F-4FD7-90A4-E037A7242144.vmcx"
$vagrant_path_2016 = "D:\Hyper-V\export\W2016-VAGRANT\Virtual Machines\00F86AEA-4090-4096-B259-D0F1AABFB22F.vmcx"

# Additionnal PS1 scripts (ConfigureRemotingForAnsible.ps1 and Install-WMF3Hotfix.ps1)
$goad_hyperv_script_path = "D:\Hyper-V\GOAD_HYPERV\Scripts\"

# Folder to store GOAD VMs
$vm_install_path = "D:\Hyper-V\GOAD_HYPERV\Virtual Machines\"

# https://learn.microsoft.com/en-us/windows-server/get-started/automatic-vm-activation
$avma_key_2019 = "H3RNG-8C32Q-Q8FRX-6TDXV-WMBMW"
$avma_key_2016 = "C3RCX-M6NRP-6CXC9-TW2F2-4RHYD"

# https://learn.microsoft.com/en-us/windows-server/get-started/kms-client-activation-keys
$gvlk_key_2019 = "WMDGN-G9PQG-XVVXX-R3X43-63DFG"
$gvlk_key_2016 = "WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY"

function Set-NetworkInterface
{
     param ([PSCredential] $cred,
            [String] $vm_name,
            [String] $int_name,
            [String] $int_ip,
            [String] $int_netmask,
            [String] $gateway,
            [Bool] $set_dns,
            [String] $int_dns)

    $parameters = @{
                        VMName       = $vm_name
                        Credential   = $cred
                        ScriptBlock  = { param($int_name_sb, $int_ip_sb, $int_netmask_sb, $int_gateway_sb) 
                                         netsh.exe int ip set address $int_name_sb static  $int_ip_sb $int_netmask_sb gateway=$int_gateway_sb 
                                       }
                        ArgumentList = $int_name, $int_ip, $int_netmask, $gateway
                    }

    Invoke-Command @parameters
    if ($set_dns)
    {
        $parameters = @{
                    VMName       = $vm_name
                    Credential   = $cred
                    ScriptBlock  = { param($int_name_sb, $int_dns_sb) 
                                        netsh.exe int ip set dnsservers $int_name_sb static $int_dns_sb primary
                                    }
                    ArgumentList = $int_name, $int_dns
                }

        # Returns an error but it works
        # https://answers.microsoft.com/en-us/windows/forum/all/error-at-configuring-dns-server-via-netsh-command/60540340-e09f-454c-9fe9-dd96f66dfde1
        Invoke-Command @parameters
    }
}

function Create-GOADVM
{
 param ([Hashtable] $box)
    
    Write-Host -ForegroundColor Yellow  "[+] Creating folders"
    $null = New-Item -ItemType Directory -Path "$($vm_install_path)$($box.name)"
    $null = New-Item -ItemType Directory -Path "$($vm_install_path)$($box.name)\Virtual Hard Disks\"
    $null = New-Item -ItemType Directory -Path "$($vm_install_path)$($box.name)\Virtual Machines\"

    Write-Host -ForegroundColor Yellow  "[+] Importing VM"
    if ($box.version -eq "2019")
    {
        Import-Vm  -Path $vagrant_path_2019 -GenerateNewId -Copy -VirtualMachinePath "$($vm_install_path)$($box.name)\Virtual Machines\" -VhdDestinationPath "$($vm_install_path)$($box.name)\Virtual Hard Disks\"
        Rename-VM "W$($box.version)-VAGRANT" -NewName $box.name
    }
    else
    {
        Import-Vm  -Path $vagrant_path_2016 -GenerateNewId -Copy -VirtualMachinePath "$($vm_install_path)$($box.name)\Virtual Machines\" -VhdDestinationPath "$($vm_install_path)$($box.name)\Virtual Hard Disks\"
        Rename-VM "W$($box.version)-VAGRANT" -NewName $box.name
    }

    # Translation...
    $name_virtual_adapter = Get-VMNetworkAdapter -VMName $box.name | Select-Object -ExpandProperty Name
    Write-Host -ForegroundColor Yellow  "[+] Adding $($name_external_vswitch) to" $box.name

    Connect-VMNetworkAdapter -VMName $box.name -Name $name_virtual_adapter -SwitchName $name_external_vswitch
    Set-VMProcessor -VMName $box.name -count 4
}

function Activate-GOADVM
{
    param ([Hashtable] $box,
           [PSCredential] $cred)
    
    if ($box.version -eq "2019")
    {
        $key = $avma_key_2019
        $gvlk_key = $gvlk_key_2019
        $retail_version = "ServerDatacenter"
    }
    else
    {
        $key = $avma_key_2016
        $gvlk_key = $gvlk_key_2016
        $retail_version = "ServerStandard"
    }

    Write-Host -ForegroundColor Yellow  "[+] Converting $($box.name) from Eval to $($retail_version)"   
    $parameters = @{
                    VMName       = $box.name
                    Credential   = $cred
                    ScriptBlock  = { param($gvlk_key_sb, $retail_version_sb) 
                                        DISM /online /Set-Edition:$retail_version_sb /ProductKey:$gvlk_key_sb /AcceptEula /Quiet 
                                   }
                    ArgumentList = $gvlk_key, $retail_version
                   }

    Invoke-Command @parameters

    Write-Host -ForegroundColor Yellow  "[+] Sleeping 240 sec"
    Start-Sleep -Seconds 240
    Write-Host -ForegroundColor Yellow  "[+] Activating Windows"  
    $parameters = @{
                    VMName       = $box.name
                    Credential   = $cred
                    ScriptBlock  = { param($key_sb) 
                                        cscript C:\Windows\System32\slmgr.vbs /ipk $key_sb
                                        cscript C:\Windows\System32\slmgr.vbs /ato
                                    }
                    ArgumentList = $key
                   }

    Invoke-Command @parameters
}

# This vswitch must be mannualy created
try {
    Write-Host -ForegroundColor Yellow  "[+] Is $($name_external_vswitch) switch exists?"
    Get-VMSwitch -Name $name_external_vswitch -ErrorAction Stop | select -exp Name
    Write-Host -ForegroundColor Green  "[+] Yes!"
}
catch [Microsoft.HyperV.PowerShell.VirtualizationException] {
    Write-Host -ForegroundColor Red  "[-] No, exiting..."
    exit
}

foreach ($box in $boxes)
{
    Write-Host -ForegroundColor Green  "[+] Creating box" $box.name
    Create-GOADVM $box

    Start-VM -VMName $box.name
    Write-Host -ForegroundColor Yellow  "[+] Sleeping 120 seconds..."
    Start-Sleep -Seconds 120

    # No DCHP, no problem, however you can comment it if your external vswitch has DHCP
    Write-Host -ForegroundColor Yellow  "[+] Setting IP addresses for" $box.name
    Set-NetworkInterface $Cred $box.name $nat_interface $box.external_ip $nat_netmask $nat_gateway $True $nat_dns

    # Inherited from GOAD
    # https://github.com/Orange-Cyberdefense/GOAD/blob/main/vagrant/ConfigureRemotingForAnsible.ps1
    # https://github.com/Orange-Cyberdefense/GOAD/blob/main/vagrant/Install-WMF3Hotfix.ps1
    Write-Host -ForegroundColor Yellow  "[+] Launching scripts"
    Invoke-Command -VMName $box.name -Credential $Cred -FilePath "$($goad_hyperv_script_path)\ConfigureRemotingForAnsible.ps1"
    Invoke-Command -VMName $box.name -Credential $Cred -FilePath "$($goad_hyperv_script_path )\Install-WMF3Hotfix.ps1"

    Write-Host -ForegroundColor Yellow  "[+] Sleeping 30 seconds..."
    Start-Sleep -Seconds 30
    Write-Host -ForegroundColor Yellow  "[+] Stopping"  $box.name
    Stop-VM -VMName $box.name

    # Is the private vswitch exists ?
    try {
        Write-Host -ForegroundColor Yellow  "[+] Is $($name_private_vswitch) switch exists?"
        Get-VMSwitch -Name $name_private_vswitch -ErrorAction Stop | select -exp Name
        Write-Host -ForegroundColor Green  "[+] Yes!"
    }
    catch [Microsoft.HyperV.PowerShell.VirtualizationException] {
        Write-Host -ForegroundColor Red  "[+] No, creating the switch"
        New-VMSwitch -Name $name_private_vswitch -SwitchType private
    }

    # We add the network adapter to the VM
    Write-Host -ForegroundColor Yellow  "[+] Adding $($name_private_vswitch) to" $box.name
    Add-VMNetworkAdapter -VMName $box.name -Name $name_private_vswitch -SwitchName $name_private_vswitch

    Write-Host -ForegroundColor Yellow  "[+] Starting"  $box.name
    Start-VM -VMName $box.name
    Write-Host -ForegroundColor Yellow  "[+] Sleeping 30 seconds..."
    Start-Sleep -Seconds 30

    # We setup the GOAD domain's LAN
    Write-Host -ForegroundColor Yellow  "[+] Setting $($name_private_vswitch) network IP for" $box.name
    Set-NetworkInterface $Cred $box.name $dom_interface $box.internal_ip $dom_netmask "" $False ""

    Write-Host -ForegroundColor Yellow  "[+] Activating VM"
    Activate-GOADVM $box $Cred

    Write-Host -ForegroundColor Yellow  "[+] Creating Checkpoint"
    Checkpoint-VM -Name $box.name -SnapshotName "Checkpoint 0 : VM activated, before ansible"
}
