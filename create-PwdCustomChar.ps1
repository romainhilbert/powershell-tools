<#
.SYNOPSIS
  Create custom charset 

.DESCRIPTION
  Create custom charset for hashcat from file or variable


.NOTES
  Version:        1.0
  Author:         Romain
  Creation Date:  2021-01-05

.EXAMPLE
  powershell -ep bypass -f create-PwdCustomChar.ps1
  powershell -ep bypass -f create-PwdCustomChar.ps1  -f john.pot

  # Load script from Github to memory	
  $url = 'https://raw.githubusercontent.com/romainhilbert/powershell-tools/master/create-PwdCustomChar.ps1'
  $wc = New-Object Net.WebClient
  $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
  IEX $wc.DownloadString($url)

#>

param (
	[string]$inFile
)


"-"*79
"[+] Date           : $(Get-Date -format s)`n"

$johnPot = @" 
2021
ADMIN!
admin$
password
PASSWORD
cCe@s
"@


If (! [string]::IsNullOrEmpty($inFile)) { 
	"[+] Filename       : $inFile`n" 
	# Read words from file
	$bytes = [System.IO.File]::ReadAllBytes($inFile)
} Else {
	# Read words from local script variable
	$bytes = [System.Text.Encoding]::UTF8.GetBytes($johnPot)
}


$uniqueBytes = $bytes  | sort-object -CaseSensitive -Unique
$customChar = ([System.Text.Encoding]::ASCII.GetString($uniqueBytes)).trim()

"[+] Custom charset : $customChar"
"[+] Length         : $($customChar.Length)"
