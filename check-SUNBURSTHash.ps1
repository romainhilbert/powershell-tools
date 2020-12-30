<#
.DESCRIPTION
  Searching files by MD5 or SHA1 hash
  Create MD5,SHA1,... hash list from files selected by SearchPath and SearchFilter 
  and compare to hashes from a given IOC (Indicators of Compromise) list

.PARAMETER 	$SearchPath  

.PARAMETER 	$SearchFilter 

.PARAMETER 	$HashValue

.NOTES
  Version:        1.0
  Author:         Romain
  Creation Date:  2020-12-30

.EXAMPLE
  powershell -ep bypass -f check-SUNBURSTHash.ps1  
  powershell -ep bypass -f check-SUNBURSTHash.ps1  -SearchPath  "C:\Windows"
  powershell -ep bypass -f check-SUNBURSTHash.ps1  -SearchPath  "C:\Program Files"
  powershell -ep bypass -f check-SUNBURSTHash.ps1  -SearchPath  "C:\Program Files (x86)"
  powershell -ep bypass -f check-SUNBURSTHash.ps1  -SearchPath  "C:\temp"  -SearchFilter "*.exe"
  powershell -ep bypass -f check-SUNBURSTHash.ps1  -SearchPath  "C:\temp"  -SearchFilter "*.exe"  -Hash "9bb6826905965c13be1c84cc0ff83f42"
  powershell "IEX (New-Object Net.WebClient).DownloadString('https://s3.amazonaws.com/powershell.seclab.cx/check-SUNBURSTHash.ps1')"

.NOTES
  https://us-cert.cisa.gov/ncas/alerts/aa20-352a
  https://cyber.dhs.gov/ed/21-01/
  https://unit42.paloaltonetworks.com/fireeye-solarstorm-sunburst/
  https://www.solarwinds.com/securityadvisory/faq

  Path(s)
    $env:SystemRoot\SysWOW64,
    $env:ProgramFiles\SolarWinds

    Get-FileHash "C:\Program Files (x86)\SolarWinds\Orion\SolarWinds.Orion.Core.BusinessLayer.dll"

.TODO
  Write function to run script by download craddle

  Only 1 file !!!!!!

  

#>

param (
	[string]$SearchPath   = "C:\Program Files (x86)",
	[string]$SearchFilter = "*.dll",
	[string]$Algorithm    = "MD5",
	[string]$HashValue    = $null
)

$IOC_MD5_List = @(
	'02af7cec58b9a5da1c542b5a32151ba1',
	'08e35543d6110ed11fdf558bb093d401',
	'b91ce2fa41029f6955bff20079468448',
	'd5aad0d248c237360cf39c054b654d69',
	'2c4a910a1299cdae2a4e55988a2f102e',
	'846e27a652a5e1bfbd0ddd38a16dc865',
	'72c887ead9a9d4ee114815748da3da35'
	'baa3d3488db90289eb2889c1a2acbcde',
	'e18a6a21eb44e77ca8d739a72209c370',
	'3e329a4c9030b26ba152fb602a1d5893',
	'4f2eb62fa529c0283b28d05ddd311fae',
	'56ceb6d0011d87b6e4d7023d7ef85676',
	'B633BCC4C34FEB41CE5657F28146F268'
)

Function SearchBy-Hash {
	param (
		[string]$OutLogfile   = "HashLog{.TIMESTAMP}.csv",
		[string]$SearchPath   = "C:\Program Files (x86)",
		[string]$SearchFilter = "*.dll"
)

	"### NONE"

}

### MAIN ##########################################################################

'-'*79

"[+] Date                : $(Get-Date -format s)"
"[+] Description         : Searching files by cryptographic hash value"
Start-Sleep -s 1

[string]$OutLogfile   = "HashSearchLog-{.TIMESTAMP}.csv"

$timestamp = Get-Date -format s
$timestamp = $timestamp.Replace(':','').Replace('-','')


## All MD5 and path and filenames from SearchPath and SearchFilter enumeration are written to $OutLogfile
$OutLogfile   = $OutLogfile.Replace('{.TIMESTAMP}', $timestamp)

## Check if Last character is backslash '\'  or use $SearchPath[-1]
##If (!($SearchPath.EndsWith('\'))) {
##	$SearchPath += "\" 
##}


# Check if HASH was provided via commandline; otherwise use hashes provided by local IOC variable list
If (! [string]::IsNullOrEmpty( $HashValue )) {
	$IOC_MD5_List  = @( $HashValue )
	""
	"[+] Search Hash         : $HashValue"
}


""
"[+] Status              : Enumerating Files by '-Path' and '-Filter'  ..."
"[+] Path                : $SearchPath"
"[+] Filter              : $SearchFilter"
Start-Sleep -s 1

# Enumerating Files by '-Filter' and '-Path' parameter and export to CSV file
#Get-ChildItem -Path $SearchPath -Filter $SearchFilter -Recurse -Force -ErrorAction SilentlyContinue | Get-FileHash -ErrorAction SilentlyContinue -Algorithm $Algorithm | Export-Csv -Append -Delimiter ";" -NoTypeInformation -Path  $OutLogfile  


$itemList = Get-ChildItem -Path $SearchPath -Filter $SearchFilter -Recurse -Force -ErrorAction SilentlyContinue 


""
"[+] Number of files     : $($itemList.Length)"


$results = @()

$itemList | % {
	$hash = Get-FileHash $_.FullName -ErrorAction SilentlyContinue -Algorithm $Algorithm  
	$hash | Add-Member -NotePropertyName "MatchIOC" -NotePropertyValue "0"

	$IOC_MD5_List | % {
		If ($hash.Hash -eq $_) {
			$hash.MatchIOC = "1"
		} 
	}

	$results += $hash
}


""
$results |  where MatchIOC -eq 1 | ft -autosize


""                                                                     
"[+] Hash Search Logfile : $OutLogfile"
$results | Export-Csv -Append -Delimiter ";" -NoTypeInformation -Path  $OutLogfile


""
"[+] DONE !"

