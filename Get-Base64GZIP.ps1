<#
.DESCRIPTION
Base64 / GZIP encoding and decoding

.NOTES
  Version:        1.0
  Author:         HIRO
  Creation Date:  2020-12-25

.EXAMPLE	

### ENCODE
powershell -ep bypass -f Get-Base64GZIP.ps1 -inFile "TEST_2020-11-12.txt" -outFile "TEST_2020-11-12.gz.b64" -encode

### DECODE
powershell -ep bypass -f Get-Base64GZIP.ps1 -outFile "TEST_2020-11-12.txt" -inFile "TEST_2020-11-12.gz.b64" -decode
#>


param (
	$inFile     = $null,
	$inURL      = $null,
	$outFile    = $null,
	[Switch]$encode,
	[Switch]$decode
)


###############################################################################3

function Get-CompressedByteArray {

	[CmdletBinding()]
    Param (
	[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [byte[]] $byteArray = $(Throw("-byteArray is required"))
    )
	Process {
        Write-Verbose "Get-CompressedByteArray"
       	[System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
      	$gzipStream.Write( $byteArray, 0, $byteArray.Length )
        $gzipStream.Close()
        $output.Close()
        $tmp = $output.ToArray()
        Write-Output $tmp
    }
}


function Get-DecompressedByteArray {

	[CmdletBinding()]
    Param (
		[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [byte[]] $byteArray = $(Throw("-byteArray is required"))
    )
	Process {
	    Write-Verbose "Get-DecompressedByteArray"
        $input = New-Object System.IO.MemoryStream( , $byteArray )
	    $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
	    $gzipStream.CopyTo( $output )
        $gzipStream.Close()
		$input.Close()
		[byte[]] $byteOutArray = $output.ToArray()
        Write-Output $byteOutArray
    }
}



###MAIN ###################################################


"[+] Date                   : $(Get-Date -format s)"
""


if ($encode) {	
	## GZIP Compress &  BASE64 encode

	$bytes       = [System.IO.File]::ReadAllBytes($inFile)

	# Cacl MD5 hash
	$hasher = [System.Security.Cryptography.HashAlgorithm]::Create('md5')
	$hash = $hasher.ComputeHash($bytes)
	$md5 = ([System.BitConverter]::ToString($hash)).Replace('-', '')


	"[+] In File Name           : $inFile"
	"[+] In File Size           : $($bytes.Length) bytes"
	"[+] In File MD5            : $md5"
	""

	#Compress GZIP
	$compressedByteArray = Get-CompressedByteArray -byteArray $bytes

	#Encode Base64
	$EncodedBase64 = [Convert]::ToBase64String($compressedByteArray)
	[System.IO.File]::WriteAllText($outFile, $EncodedBase64) 

	$hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($EncodedBase64))
	$md5 = ([System.BitConverter]::ToString($hash)).Replace('-', '')

	"[+] Out B64/GZIP File Name : $outFile"
	"[+] Out B64/GZIP File Size : $($EncodedBase64.Length) bytes"
	"[+] Out B64/GZIP File MD5  : $md5"

}


if ($decode) {	
	## Base64 Decode & Decompress

	$bytes       = [System.IO.File]::ReadAllText($inFile)

	# Cacl MD5 hash
	$hasher = [System.Security.Cryptography.HashAlgorithm]::Create('md5')
	$hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($bytes))
	$md5 = ([System.BitConverter]::ToString($hash)).Replace('-', '')


	"[+] In B64/GZIP File Name  : $inFile"
	"[+] In B64/GZIP File Size  : $($bytes.Length) bytes"
	"[+] In B64/GZIP File MD5   : $md5"
	""

	# Decode Base64
	$compressedByteArray = [System.Convert]::FromBase64String($bytes)

	# Decompress
	$decompressedByteArray = Get-DecompressedByteArray -byteArray $compressedByteArray

	$hash = $hasher.ComputeHash($decompressedByteArray)
	$md5 = ([System.BitConverter]::ToString($hash)).Replace('-', '')

	[System.IO.File]::WriteAllBytes($outFile, $decompressedByteArray)

	"[+] Out File Name          : $outFile"
	"[+] Out File Size          : $($decompressedByteArray.Length) bytes"
	"[+] Out File MD5           : $md5"
}


