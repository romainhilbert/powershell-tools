<#
.SYNOPSIS
  Base64 & GZIP Encode/Decode function

.DESCRIPTION
  Compress GZIP and encode Base64 input from local file or URL to output file
  Decode Base64 and decompress GZIP input from local file or URL to output file

.NOTES
  Version:        1.0
  Author:         Romain
  Creation Date:  2021-01-04

.EXAMPLE
  # Encode from FILE
  Encode-FromFile -in "hello101.exe" -out "hello101.exe.txt"

  # Encode from URL 
  Encode-FromUrl -in "https://raw.githubusercontent.com/romainhilbert/powershell-tools/master/base64BLOBs/hello101.exe" -out "hello101(2).exe.txt"

  # Decode from FILE 
  Decode-FromFile -in "hello101.exe.txt"  -out "hello101(3).exe"

  # Decode from URL  
  Decode-FromUrl -in "https://raw.githubusercontent.com/romainhilbert/powershell-tools/master/base64BLOBs/hello101.exe.txt"  -out "hello101(4).exe"

  # Load script from Github to memory	
  $url = 'https://raw.githubusercontent.com/romainhilbert/powershell-tools/master/Get-Base64GZIP.ps1'
  $wc = New-Object Net.WebClient
  $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
  IEX $wc.DownloadString($url)
#>


#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = "1.0"


#-----------------------------------------------------------[Functions]------------------------------------------------------------

#################################################################################
## GZIP Compress & BASE64 encode from input File

Function Encode-FromFile {
	[CmdletBinding()]
	param (
		$inFile     = $null,
		$outFile    = $null
	)

	"`n[+] Date                   : $(Get-Date -format s)"
	"[+] Encode FROM File`n"

	If ([string]::IsNullOrEmpty($inFile)) {
		Write-Host "SYNTAX: Encode-FromFile -inFile <FILENAME> -outFile <FILENAME>" -ForegroundColor Yellow
		Return
	}

	$bytes       = [System.IO.File]::ReadAllBytes($inFile)

	# Calc MD5 hash
	$hasher = [System.Security.Cryptography.HashAlgorithm]::Create('md5')
	$hash = $hasher.ComputeHash($bytes)
	$md5 = ([System.BitConverter]::ToString($hash)).Replace('-', '')

	$fileSize =  ("{0:N0}" -f $($bytes.Length)) -replace ",", "."

	"[+] In File Name           : $inFile"
	"[+] In File Size           : $fileSize bytes"
	"[+] In File MD5            : $md5"
	""

	#Compress GZIP
	$compressedByteArray = Get-CompressedByteArray -byteArray $bytes

	#Encode Base64
	$EncodedBase64 = [Convert]::ToBase64String($compressedByteArray)
	[System.IO.File]::WriteAllText($outFile, $EncodedBase64) 

	$hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($EncodedBase64))
	$md5 = ([System.BitConverter]::ToString($hash)).Replace('-', '')

	$fileSize =  ("{0:N0}" -f $($EncodedBase64.Length)) -replace ",", "."

	"[+] Out B64/GZIP File Name : $outFile"
	"[+] Out B64/GZIP File Size : $fileSize bytes"
	"[+] Out B64/GZIP File MD5  : $md5"
}


#################################################################################
## GZIP Compress & BASE64 encode from input URL

Function Encode-FromUrl {
	[CmdletBinding()]
	param (
		$inUrl     = $null,
		$outFile    = $null
	)

	"`n[+] Date                   : $(Get-Date -format s)"
	"[+] Encode FROM URL`n"

	If ([string]::IsNullOrEmpty($inUrl)) {
		Write-Host "SYNTAX: Encode-FromURL -inURL <URL> -outFile <FILENAME>" -ForegroundColor Yellow
		Return
	}

	$wc = New-Object Net.WebClient
	$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

	"[+] Download URL           : $inUrl"

	Try {
		$bytes = $wc.DownloadData($inURL)

	} Catch [Net.WebException] { 
		Write-Host "[+] Download FAILED from URL : $inUrl" -ForegroundColor Yellow
		Return
	}

	# Calc MD5 hash
	$hasher = [System.Security.Cryptography.HashAlgorithm]::Create('md5')
	$hash = $hasher.ComputeHash($bytes)
	$md5 = ([System.BitConverter]::ToString($hash)).Replace('-', '')

	$fileSize =  ("{0:N0}" -f $($bytes.Length)) -replace ",", "."

	"[+] In Data Size           : $fileSize bytes"
	"[+] In Data MD5            : $md5"
	""

	#Compress GZIP
	$compressedByteArray = Get-CompressedByteArray -byteArray $bytes

	#Encode Base64
	$EncodedBase64 = [Convert]::ToBase64String($compressedByteArray)
	[System.IO.File]::WriteAllText($outFile, $EncodedBase64) 

	$hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($EncodedBase64))
	$md5 = ([System.BitConverter]::ToString($hash)).Replace('-', '')

	$fileSize =  ("{0:N0}" -f $($EncodedBase64.Length)) -replace ",", "."

	"[+] Out B64/GZIP File Name : $outFile"
	"[+] Out B64/GZIP File Size : $fileSize bytes"
	"[+] Out B64/GZIP File MD5  : $md5"
}

#################################################################################
## GZIP Decompress & BASE64 decode from URL

Function Decode-FromUrl {
	[CmdletBinding()]
	param (
		$inUrl      = $null,
		$outFile    = $null
	)

	"`n[+] Date                   : $(Get-Date -format s)"
	"[+] Decode FROM URL`n"

	If ([string]::IsNullOrEmpty($inUrl)) {
		Write-Host "SYNTAX: Decode-FromURL -inURL <URL> -outFile <FILENAME>" -ForegroundColor Yellow
		Return
	}

	$wc = New-Object Net.WebClient
	$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

	"[+] Download URL           : $inUrl"

	Try {
		$bytes = $wc.DownloadString($inURL)

	} Catch [Net.WebException] { 
		Write-Host "[+] Download FAILED from URL : $inUrl" -ForegroundColor Yellow
		Return
	}

	# Calc MD5 hash
	$hasher = [System.Security.Cryptography.HashAlgorithm]::Create('md5')
	$hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($bytes))
	$md5 = ([System.BitConverter]::ToString($hash)).Replace('-', '')


	$fileSize =  ("{0:N0}" -f $($bytes.Length)) -replace ",", "."

	"[+] In Data Size           : $fileSize bytes"
	"[+] In Data MD5            : $md5"
	""

	# Decode Base64
	$compressedByteArray = [System.Convert]::FromBase64String($bytes)

	# Decompress
	$decompressedByteArray = Get-DecompressedByteArray -byteArray $compressedByteArray

	$hash = $hasher.ComputeHash($decompressedByteArray)
	$md5 = ([System.BitConverter]::ToString($hash)).Replace('-', '')


	If ([string]::IsNullOrEmpty($outFile)) {
		$outFile = Split-Path ($inURL) -Leaf
		$outFile += ".txt"
	}

	[System.IO.File]::WriteAllBytes($outFile, $decompressedByteArray)

	$fileSize =  ("{0:N0}" -f $($decompressedByteArray.Length)) -replace ",", "."

	"[+] Out File Name          : $outFile"
	"[+] Out File Size          : $fileSize bytes"
	"[+] Out File MD5           : $md5"
}

#################################################################################
## GZIP Decompress &  BASE64 decode from File

Function Decode-FromFile {
	[CmdletBinding()]
	param (
		$inFile     = $null,
		$outFile    = $null
	)

	"`n[+] Date                   : $(Get-Date -format s)"
	"[+] Decode FROM File`n"

	If ([string]::IsNullOrEmpty($inFile)) {
		Write-Host "SYNTAX: Decode-FromFile -inFIle <FILENAME> -outFile <FILENAME>" -ForegroundColor Yellow
		Return
	}

	$bytes       = [System.IO.File]::ReadAllText($inFile)

	# Calc MD5 hash
	$hasher = [System.Security.Cryptography.HashAlgorithm]::Create('md5')
	$hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($bytes))
	$md5 = ([System.BitConverter]::ToString($hash)).Replace('-', '')

	$fileSize =  ("{0:N0}" -f $($bytes.Length)) -replace ",", "."

	"[+] In B64/GZIP File Name  : $inFile"
	"[+] In B64/GZIP File Size  : $fileSize bytes"
	"[+] In B64/GZIP File MD5   : $md5"
	""

	# Decode Base64
	$compressedByteArray = [System.Convert]::FromBase64String($bytes)

	# Decompress
	$decompressedByteArray = Get-DecompressedByteArray -byteArray $compressedByteArray

	$hash = $hasher.ComputeHash($decompressedByteArray)
	$md5 = ([System.BitConverter]::ToString($hash)).Replace('-', '')


	If ([string]::IsNullOrEmpty($outFile)) {
		$outFile = $inFile + ".txt"
	}

	[System.IO.File]::WriteAllBytes($outFile, $decompressedByteArray)

	$fileSize =  ("{0:N0}" -f $($decompressedByteArray.Length)) -replace ",", "."

	"[+] Out File Name          : $outFile"
	"[+] Out File Size          : $fileSize bytes"
	"[+] Out File MD5           : $md5"
}

###############################################################################3
# Compress to GZIP Array

Function Get-CompressedByteArray {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
		[byte[]] $byteArray
	)

	[System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
	$gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
	$gzipStream.Write( $byteArray, 0, $byteArray.Length )
	$gzipStream.Close()
	$output.Close()
	[byte[]] $byteOutArray = $output.ToArray()
	Write-Output $byteOutArray
}

#################################################################################
# Decompress From GZIP Array

Function Get-DecompressedByteArray {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
		[byte[]] $byteArray 
	)

	$input = New-Object System.IO.MemoryStream( , $byteArray )
	$output = New-Object System.IO.MemoryStream
	$gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
	$gzipStream.CopyTo( $output )
	$gzipStream.Close()
	$input.Close()
	[byte[]] $byteOutArray = $output.ToArray()
	Write-Output $byteOutArray
}

###########################################################################################################3333




