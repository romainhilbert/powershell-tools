<#
.DESCRIPTION
  Searching files cryptographic hash value
  Create MD5, SHA1, SHA256 hash list from files selected by SearchPath and SearchFilter 
  and compare to hashes from a given IOC (Indicators of Compromise) list

.PARAMETER 	$SearchPath  

.PARAMETER 	$SearchFilter 

.PARAMETER 	$HashValue

.PARAMETER 	$HashFile

.NOTES
  Version:        1.0
  Author:         Romain
  Creation Date:  2021-01-02

.EXAMPLE
  SearchBy-Hash  -SearchPath  "C:\temp"  -SearchFilter "*.exe"  -HashFile IOC_List.txt
  SearchBy-Hash  -SearchPath  "C:\temp"  -SearchFilter "*.exe"  -HashValue 9bb6826905965c13be1c84cc0ff83f42  -Algorithm MD5  -HashFile IOC_List.txt
  SearchBy-Hash  -SearchPath  "C:\temp"  -SearchFilter "*.exe"  -HashValue F3AABA4720B37439020298E180ED8DF02BC9FC88  -Algorithm SHA1  
  SearchBy-Hash  -SearchPath  "C:\temp"  -SearchFilter "*.exe"  -HashValue CFA4F56807405FD36E406688FEB970A0D0D4854456BA2DA72E4A33A27B01D9AE  -Algorithm SHA256  
  
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/romainhilbert/powershell-tools/master/check-SearchBy-Hash.ps1')

.NOTES
  https://us-cert.cisa.gov/ncas/alerts/aa20-352a
  https://cyber.dhs.gov/ed/21-01/
  https://unit42.paloaltonetworks.com/fireeye-solarstorm-sunburst/
  https://www.solarwinds.com/securityadvisory/faq
  Path(s)
    $env:SystemRoot\SysWOW64,
    $env:ProgramFiles\SolarWinds
    C:\Program Files (x86)
	
    Get-FileHash "C:\Program Files (x86)\SolarWinds\Orion\SolarWinds.Orion.Core.BusinessLayer.dll"

#>

$Hash_RefLength = @{
   MD5 = 32;
   SHA1 = 40;
   SHA256 = 64;
}


Function Get-StringHash {
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [ValidateScript({ ![System.String]::IsNullOrEmpty($PSItem) })][System.String]$inputString,
        [ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')][System.String]$hashAlgo
    )
    process {
        $inputBytes    = [System.Text.Encoding]::UTF8.GetBytes($inputString)
        $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($hashAlgo)

        return ( [System.BitConverter]::ToString( $hashAlgorithm.ComputeHash($inputBytes) ) -replace '-' )
    }
}

Function SearchBy-Hash {
	Param (
		[string]$SearchPath   = "C:\",
		[string]$SearchFilter = "*.exe",
		[string]$Algorithm    = "MD5",
		[string]$HashValue    = $null,
		[string]$HashFile     = $null,
		[string]$OutLogfile   = "HashSearchLog-{.TIMESTAMP}.csv",
		[switch]$verbose
	)

	'-'*79

	"[+] Date                 : $(Get-Date -format s)"
	"[+] Description          : Searching files by cryptographic hash value"
	Start-Sleep -s 1

	$timestamp = Get-Date -format s
	$timestamp = $timestamp.Replace(':','').Replace('-','')


	## All MD5 and path and filenames from SearchPath and SearchFilter enumeration are written to $OutLogfile
	$OutLogfile   = $OutLogfile.Replace('{.TIMESTAMP}', $timestamp)


	$HashList  = @()

	# Check if a HASH  value was provided via commandline
	If (! [string]::IsNullOrEmpty( $HashValue )) {
		$HashList  += $HashValue
	}


	# Check if HASH value(s) were provided from file
	If (! [string]::IsNullOrEmpty( $HashFile )) {
		Get-Content $HashFile | Where-Object { $_.Trim() -ne '' } |  % {
			$HashList  += $_
		}
	}


	# Verify at least 1 Hash value(s) was provided by command line or from file
	If ($HashList.Count -eq 0) {
		Write-Warning "Missing Hash Value"
		return
	} Else {
		""
		"[+] Number Hash Value(s) : $($HashList.Count)"
		""
		$HashList
	}



	#Verify that provided HashValue(s) accord to choosen Hash Algorithm
	$HashAlgoTestCheck = $HashList[0]

	If ( $($HashAlgoTestCheck.Length) -ne $Hash_RefLength[$Algorithm] ) {
		Write-Warning "HashValue(s) does NOT accord to choosen Hash Algorithm: $Algorithm"
		return
	}

	""
	"[+] Status               : Enumerating Files by '-Path' and '-Filter'  ..."
	"[+] Path                 : $SearchPath"
	"[+] Filter               : $SearchFilter"
	Start-Sleep -s 1

	$itemList = Get-ChildItem -Path $SearchPath -Filter $SearchFilter -Recurse -Force -ErrorAction SilentlyContinue 

	"[+] Files enumerated     : $($itemList.Length)"

	$results = @()

	$itemList | % {
		$hash = Get-FileHash $_.FullName -ErrorAction SilentlyContinue -Algorithm $Algorithm  
		$hash | Add-Member -NotePropertyName "MatchIOC" -NotePropertyValue "0"

		$HashList | % {
			If ($hash.Hash -eq $_) {
				$hash.MatchIOC = "1"
			} 
		}

		$results += $hash
	}

	""
	If ($verbose) {
		$results | select -Property MatchIOC, Hash, Path  | ft -autosize
	} Else {
		$results |  where MatchIOC -eq 1 | ft -autosize
	}


	""                                                                     
	"[+] Hash Search Logfile  : $OutLogfile"
	$results | Export-Csv -Append -Delimiter ";" -NoTypeInformation -Path  $OutLogfile


	""
	"[+] DONE !"
}

