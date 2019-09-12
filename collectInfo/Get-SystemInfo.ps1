<#PSScriptInfo
.LASTCHANGED 2019/09/12

.VERSION 1.0

.GUID 4a3210c2-7ec8-4034-bf75-4c52ed197964

.AUTHOR hiro@seclab.cx

.COMPANYNAME 

.COPYRIGHT 

.TAGS 

#>

<# 

.DESCRIPTION 
	Gather System and OS Information 
	License: BSD 3-Clause
#> 
Param(
	[switch]$info = $false
)


$WinVerInformation = @'
	Windows 10 version 1903 (May 2019 Update) -  Build 18362
	Windows 10 version 1809 (October 2018 Update) - Build 17763
	Windows 10 version 1803 (April 2018 Update) - Build 17134
	Windows 10 version 1709 (Fall Creators Update) - Build 16299
	Windows 10 version 1703 (Creators Update) - Build 15063
	Windows 10 version 1607 (Anniversary Update) - Build 14393 
	Windows 10 version 1511 (November Update) - Build 10586 
	Windows 10 version 1507 (Initial Release) - Build 10240 

	https://pureinfotech.com/windows-10-version-release-history/
'@


Function Get-SystemInfo {
    [CmdletBinding()]
            
    # Parameters used in this function
	Param
    (
        [Parameter(Position=0, Mandatory = $false, ValueFromPipeline = $true)] 
        $Server = $env:computername
    ) 
    
    
    $ErrorActionPreference = 'SilentlyContinue'
               
    # Adding properties to object
    $Object = New-Object PSCustomObject
    $Object | Add-Member -Type NoteProperty -Name "Computer name" -Value $Server
    
    # Get OS details using WMI query
    $os = Get-WmiObject win32_operatingsystem -ComputerName $Server | select LastBootUpTime,LocalDateTime,organization,Caption,OSArchitecture,Version,BuildNumber
                  
    # Get bootup time and local date time  
    $LastBootUpTime = [Management.ManagementDateTimeConverter]::ToDateTime(($os).LastBootUpTime)
    $LocalDateTime = [Management.ManagementDateTimeConverter]::ToDateTime(($os).LocalDateTime)
                        
    # Calculate uptime - this is automatically a timespan
    $up = $LocalDateTime - $LastBootUpTime
    $uptime = "$($up.Days) days, $($up.Hours)h, $($up.Minutes)mins"
                    
    # Get computer system details
    $ComputerSystemInfo = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Server
                     
    
    # Add collected properties to object
    $Object | Add-Member -Type NoteProperty -Name "Domain" -Value $ComputerSystemInfo.domain
    $Object | Add-Member -Type NoteProperty -Name "Organization" -Value $os.organization
	$Object | Add-Member -Type NoteProperty -Name "Manufacturer" -Value $ComputerSystemInfo.Manufacturer
    $Object | Add-Member -Type NoteProperty -Name "Machine Type" -Value $ComputerSystemInfo.Model
    $Object | Add-Member -Type NoteProperty -Name "Operating system" -Value $os.Caption
    $Object | Add-Member -Type NoteProperty -Name "Version" -Value $os.version
    $Object | Add-Member -Type NoteProperty -Name "Build Number" -Value $os.BuildNumber
	$Object | Add-Member -Type NoteProperty -Name "Release ID" -Value (Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('ReleaseID')
    $Object | Add-Member -Type NoteProperty -Name "OSArchitecture" -Value $os.OSArchitecture
    $Object | Add-Member -Type NoteProperty -Name "InstallDate" -Value (gcim Win32_OperatingSystem).InstallDate.toString("s")
    $Object | Add-Member -Type NoteProperty -Name "LastBootUpTime" -Value (gcim Win32_OperatingSystem).LastBootUpTime.toString("s")
	$Object | Add-Member -Type NoteProperty -Name "Up Time" -Value $uptime					
                        
    # Checking network adapters and their IP address
    $NetAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Namespace "root\CIMV2" | where{$_.IPEnabled -eq "True"}
    
    ForEach($Item in $NetAdapters) {
		$NetAdapName = $Item.Description
		$Object | Add-Member -Type NoteProperty -Name "$NetAdapName" -Value $Item.IPAddress[0]
    }
   
 
    # Display results
    $Object
}

### MAIN #########################################################################################

Get-SystemInfo


if ($info) {
	"`n Windows 10 Version Build and Relase Information`n"
	$WinVerInformation
}

