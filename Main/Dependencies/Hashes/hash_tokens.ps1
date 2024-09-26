# Define the path to the Hashes_Tokens directory
$HashesTokensDir = "path\to\your\Hashes_Tokens"

# Function to generate the hash of a given token
function Get-TokenHash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    $HashAlgorithm = New-Object System.Security.Cryptography.SHA256Managed
    $ByteArray = [System.Text.Encoding]::UTF8.GetBytes($Token)
    $HashedBytes = $HashAlgorithm.ComputeHash($ByteArray)
    $HashedToken = [System.BitConverter]::ToString($HashedBytes).Replace("-", "").ToLower()

    return $HashedToken
}

# Hash and store the SentinelOne token
$S1Token = "your_s1_token_here"
$HashedS1Token = Get-TokenHash -Token $S1Token
$HashedS1Token | Out-File -FilePath (Join-Path $HashesTokensDir "s1token.txt")

# Hash and store the Adobe Acrobat serial number
$AcrobatSerialNumber = "your_acrobat_serial_number_here"
$HashedAcrobatSerialNumber = Get-TokenHash -Token $AcrobatSerialNumber
$HashedAcrobatSerialNumber | Out-File -FilePath (Join-Path $HashesTokensDir "acrobat_serial.txt")

# Securely delete the plaintext tokens
$S1Token = $null
$AcrobatSerialNumber = $null
Remove-Variable -Name "S1Token", "AcrobatSerialNumber" -ErrorAction SilentlyContinue
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()