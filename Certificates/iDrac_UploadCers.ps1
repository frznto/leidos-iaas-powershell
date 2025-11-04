<#
.SYNOPSIS
  Upload Certificates for iDracs from a csv list
.DESCRIPTION
  Upload Certificates for idracs from a csv list which is saved in the same directory that the csv list is located in.
.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>
.INPUTS
  <Inputs if any, otherwise state None>
.OUTPUTS
  <Outputs if any, otherwise state None - example: Log file stored in C:\Windows\Temp\<name>.log>
.NOTES
  Version:        1.1
  Author:         Matthew Blakeslee-Hisel
  Creation Date:  3/2025
  Purpose/Change: 
    8/11 1.1 Added to the target loop a file name to check of the file being in the form of fqdn.pem, or ip.pem or IP_xxx_xxx_xxx_xxx.pem.
             Added to the initial message the format expected for the .pem files. 
  
  CSV Header Structure: fqdn,ip


.EXAMPLE
  
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

<#
# Check PowerShell version
if ($PSVersionTable.PSEdition -ne 'Core' -and $PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "This script requires PowerShell Core 7 or later to run."
    return
}
#>

#Required modules: List modules that are required for the script
# Ensure the module is available before running the script
If (-not (Get-Module -ListAvailable -Name IdracRedfishSupport)) {
    Write-Host "Required module 'IdracRedfishSupport' is not installed. Install it before running the script." -ForegroundColor Red
    Exit 1
}

# Check PowerShell version and load System.Windows.Forms accordingly
if ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.PSVersion.Major -ge 7) {
    Add-Type -AssemblyName System.Windows.Forms
} else {
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
}


#----------------------------------------------------------[Declarations]----------------------------------------------------------
<#
#Script Version
$sScriptVersion = "1.0"

#Log File Info
$sLogPath = "C:\Windows\Temp"
$sLogName = "<script_name>.log"
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName
#>

#Certificate Variables
$OrgName = "Leidos"
$OrgUnitName = "CIO Services"
$City = "Reston"
$State = "Virginia"
$Country = "US"
$CsrEmail = "vmware_team@leidos.com"

#-----------------------------------------------------------[Functions]------------------------------------------------------------

<#
Function <FunctionName>{
  Param()
  
  Begin{
    Log-Write -LogPath $sLogFile -LineValue "<description of what is going on>..."
  }
  
  Process{
    Try{
      <code goes here>
    }
    
    Catch{
      Log-Error -LogPath $sLogFile -ErrorDesc $_.Exception -ExitGracefully $True
      Break
    }
  }
  
  End{
    If($?){
      Log-Write -LogPath $sLogFile -LineValue "Completed Successfully."
      Log-Write -LogPath $sLogFile -LineValue " "
    }
  }
}
#>


#-----------------------------------------------------------[Execution]------------------------------------------------------------

#Log-Start -LogPath $sLogPath -LogName $sLogName -ScriptVersion $sScriptVersion
#Script Execution goes here

Write-Host 
Write-Host "Verify the generated certificates are in the same directory as the target csv list."
Write-Host "Certificates should be in the .pem format WITHOUT IA or CA information"
Write-Host "Verify all .pems are named in the following format TargetFQDN.pem, or TargetIP.pem or IP_xxx_xxx_xxx_xxx.pem."
Write-Host "For Example: iDracHost001.leidos.com.pem or 192.168.1.1.pem or IP_192_168_1_1.pem"
Write-Host

# Securely cache credentials
$SessionCache = [PSCustomObject]@{
  Credential = Get-Credential -Message "Enter the iDRAC credentials. If using domain credentials must be in the form of username@domain"
}

# Extract username and password separately
$IdracUsername = $SessionCache.Credential.UserName
$SecurePassword = $SessionCache.Credential.Password

# Set folder location for the CSV 
$Directory = "$ENV:USERPROFILE\Downloads"

# Explorer Window to prompt for CSV file selection
Write-Host "Select CSV list" -ForegroundColor Green -BackgroundColor Black
Start-Sleep -Seconds 2

$File = New-Object System.Windows.Forms.OpenFileDialog -Property @{
  InitialDirectory = "$Directory"
  Filter = "CSV Files (*.csv)|*.csv|All files (*.*)|*.*"
}
$null = $File.ShowDialog()
$FilePath = $File.FileName
$FolderPath = [System.IO.Path]::GetDirectoryName($FilePath)

# Validate file selection
if (-not $FilePath -or -not (Test-Path $FilePath)) {
  Write-Host "No valid file selected. Exiting script." -ForegroundColor Red
  Exit 1
}

$iDracTargets = Import-CSV -Path $FilePath -Delimiter ',' -Encoding UTF8 | Select-Object fqdn,ip

# Initialize summary results array
$SummaryResults = @()

# Start loop to process each entry in the CSV
ForEach ($Target in $iDracTargets) {

    Remove-Variable -Force -ErrorAction Ignore -Name "CommonName", "IPAddress", "PemFilePath", "$PemFilePathFqdn", "$PemFilePathIP", "$PemFilePathIPUnderscore"

    $CommonName = $Target.fqdn
    $IPAddress  = $Target.ip

    # Define possible PEM file paths
    $PemFilePathFqdn        = Join-Path $FolderPath "$CommonName.pem"
    $PemFilePathIP          = Join-Path $FolderPath "$IPAddress.pem"
    $PemFilePathIPUnderscore = Join-Path $FolderPath ("IP_" + ($IPAddress -replace '\.', '_') + ".pem")

    # File existence check in priority order: FQDN → IP → IP_
    if (Test-Path -Path $PemFilePathFqdn -PathType Leaf) {
        $PemFilePath = $PemFilePathFqdn
    }
    elseif (Test-Path -Path $PemFilePathIP -PathType Leaf) {
        Write-Host "WARNING: Certificate for $CommonName found using plain IP filename. Using '$PemFilePathIP'." -ForegroundColor Yellow
        $PemFilePath = $PemFilePathIP
    }
    elseif (Test-Path -Path $PemFilePathIPUnderscore -PathType Leaf) {
        Write-Host "WARNING: Certificate for $CommonName found in underscore IP format ($PemFilePathIPUnderscore)." -ForegroundColor Yellow
        $PemFilePath = $PemFilePathIPUnderscore
    }
    else {
        Write-Host "ERROR: No PEM file found for $CommonName (checked FQDN, IP, and IP_ format)." -ForegroundColor Red
        $SummaryResults += [PSCustomObject]@{ FQDN = $CommonName; Status = "FAILED - PEM file missing" }
        continue
    }

    # Host reachability check
    if (-not (Test-Connection -ComputerName $CommonName -Count 2 -Quiet)) {
        Write-Host "ERROR: $CommonName could not be reached. No certificate was uploaded." -ForegroundColor Red
        $SummaryResults += [PSCustomObject]@{ FQDN = $CommonName; Status = "FAILED - Host unreachable" }
        continue
    }

    # DNS resolution check
    try {
        $ResolvedIP = [System.Net.Dns]::GetHostAddresses($CommonName) | Select-Object -ExpandProperty IPAddressToString
        if ($ResolvedIP -notcontains $IPAddress) {
            Write-Host "ERROR: DNS mismatch for $CommonName (Expected: $IPAddress, Resolved: $ResolvedIP). No certificate was uploaded." -ForegroundColor Red
            $SummaryResults += [PSCustomObject]@{ FQDN = $CommonName; Status = "FAILED - DNS mismatch" }
            continue
        }
    }
    catch {
        Write-Host "ERROR: Unable to resolve $CommonName. No certificate was uploaded." -ForegroundColor Red
        $SummaryResults += [PSCustomObject]@{ FQDN = $CommonName; Status = "FAILED - DNS resolution error" }
        continue
    }

    # Upload PEM File
    try {
        $UploadedCert = Invoke-ExportImportSslCertificateREDFISH `
            -idrac_ip $IPAddress `
            -idrac_username $IdracUsername `
            -idrac_password ([System.Net.NetworkCredential]::new("", $SecurePassword).Password) `
            -import_ssl_cert Server `
            -cert_filename $PemFilePath

        # Example check — replace with real error handling logic if Invoke returns structured output
        if ($UploadedCert -and $UploadedCert.ToString() -match "error") {
            throw "Upload error detected"
        }

        # Restart iDRAC
        Invoke-ResetIdracREDFISH `
            -idrac_ip $IPAddress `
            -idrac_username $IdracUsername `
            -idrac_password ([System.Net.NetworkCredential]::new("", $SecurePassword).Password)

        $SummaryResults += [PSCustomObject]@{ FQDN = $CommonName; Status = "SUCCESS" }
    }
    catch {
        Write-Host "ERROR: Failed to upload certificate for $CommonName - $($_.Exception.Message)" -ForegroundColor Red
        $SummaryResults += [PSCustomObject]@{ FQDN = $CommonName; Status = "FAILED - Upload error" }
    }
}


# Output Summary with color-coded results
Write-Host "`n===== Certificate Upload Summary =====" -ForegroundColor Cyan
foreach ($entry in $SummaryResults) {
  if ($entry.Status -like "Success*") {
      Write-Host ("{0,-30} {1}" -f $entry.FQDN, $entry.Status) -ForegroundColor Black -BackgroundColor Green
  } else {
      Write-Host ("{0,-30} {1}" -f $entry.FQDN, $entry.Status) -ForegroundColor White -BackgroundColor Red
  }
}
Write-Host "========================================" -ForegroundColor Cyan

#Log-Finish -LogPath $sLogFile


