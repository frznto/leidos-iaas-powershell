<#
.SYNOPSIS
  Generate CSRs for iLos from a csv list
.DESCRIPTION
  Generate CSRs for iLos from a csv list which is saved in the same directory that the csv list is located in.
.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>
.INPUTS
  <Inputs if any, otherwise state None>
.OUTPUTS
  <Outputs if any, otherwise state None - example: Log file stored in C:\Windows\Temp\<name>.log>
.NOTES
  Version:        1.0
  Author:         Matthew Blakeslee-Hisel
  Creation Date:  8/2025
  Purpose/Change: 

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
If (-not (Get-Module -ListAvailable -Name HPEiLOCmdlets)) {
    Write-Host "Required module 'HPEiLOCmdlets' is not installed. Install it before running the script." -ForegroundColor Red
    Exit 1
}

# Check PowerShell version and load System.Windows.Forms accordingly
if ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.PSVersion.Major -ge 7) {
    Add-Type -AssemblyName System.Windows.Forms
} else {
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
}


#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = "1.0"

#Log File Info
$sLogPath = "C:\Windows\Temp"
$sLogName = "<script_name>.log"
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName


#Certificate Variables
#$commonName = "sfo-m01-srm01.sfo.rainpole.io"    --Set via csv in loop
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


# Securely cache credentials
$SessionCache = [PSCustomObject]@{
  Credential = Get-Credential -Message "Enter the iLo local credentials. Domain credentials or XAUTH does not work"
}

# Extract username and password separately
$iLoUsername = $SessionCache.Credential.UserName
$SecurePassword = $SessionCache.Credential.Password

# Set folder location for the CSV 
$Directory = "$ENV:USERPROFILE\Downloads"

# Prompt user to select a CSV file
Write-Host
Write-Host "Select CSV list" -ForegroundColor Green -BackgroundColor Black
Start-Sleep -Seconds 2

$File = New-Object System.Windows.Forms.OpenFileDialog -Property @{
  InitialDirectory = "$Directory"
  Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
}
$null = $File.ShowDialog()
$FilePath = $File.FileName
$FolderPath = [System.IO.Path]::GetDirectoryName($FilePath)

# Validate file selection
if (-not $FilePath -or -not (Test-Path $FilePath)) {
  Write-Host "No valid file selected. Exiting script." -ForegroundColor Red
  Exit 1
}

$CSVTargets = Import-CSV -Path $FilePath -Delimiter ',' -Encoding UTF8 | Select-Object fqdn, ip

# Initialize an array to store summary results
$SummaryResults = @()

# Start loop to generate CSRs for each entry in the CSV
ForEach ($Target in $CSVTargets) { 

  # Remove previous loop data
  Remove-Variable -Force -ErrorAction Ignore -Name "CommonName", "IPAddress", "CsrFilePath"

  $CommonName = $Target.fqdn
  $IPAddress = $Target.ip
  $CsrFilePath = Join-Path $FolderPath "$CommonName.csr"

  # Check if the host is reachable
  if (-not (Test-Connection -ComputerName $CommonName -Count 2 -Quiet)) {
      $SummaryResults += [PSCustomObject]@{ FQDN = $CommonName; Status = "Failed - Host unreachable" }
      continue
  }

  # Verify DNS resolution
  try {
      $ResolvedIP = [System.Net.Dns]::GetHostAddresses($CommonName) | Select-Object -ExpandProperty IPAddressToString
      if ($ResolvedIP -notcontains $IPAddress) {
          $SummaryResults += [PSCustomObject]@{ FQDN = $CommonName; Status = "Failed - DNS mismatch (Expected: $IPAddress, Resolved: $ResolvedIP)" }
          continue
      }
  } catch {
      $SummaryResults += [PSCustomObject]@{ FQDN = $CommonName; Status = "Failed - Unable to resolve hostname" }
      continue
  }

  # Create iLo Session
  try {
        $HPiLoSession = Connect-HPEiLO -IP "$IPAddress" -Username $iLoUsername -Password ([System.Net.NetworkCredential]::new("", $SecurePassword).Password) -DisableCertificateAuthentication -ErrorAction Stop
  } catch {
            if($_ -contains "(401) Unauthorized" -or $_.Exception.Message -contains "(401) Unauthorized")
            exit
        }
        
        # Only check the firmware version level for iLO 4.
        $firmware = Get-HPEiLOFirmwareVersion -Connection $connection
        if ($firmware.ManagerType -ne "iLO 5") {
            if ([Version]$firmware.FirmwareVersion -lt [Version]"2.70"){
                throw "The HPE iLO Firmware needs to be updated to continue."
                exit
            }
        }
  

  # Invoke CSR Generation
  try {
    $HPiLoSession = Connect-HPEiLO -IP "$IPAddress" -Username $iLoUsername -Password ([System.Net.NetworkCredential]::new("", $SecurePassword).Password) -DisableCertificateAuthentication -ErrorAction warn

    $csrfile = Invoke-GenerateCsrREDFISH -idrac_ip $IPAddress -idrac_username $IdracUsername -idrac_password ([System.Net.NetworkCredential]::new("", $SecurePassword).Password) -city $City -state $State -country $Country -commonname $CommonName -subject_alt_name "$CommonName,$IPAddress" -org $OrgName -orgunit $OrgUnitName -email $CsrEmail -export $CsrFilePath

      # Check for errors
      if ($csrfile.ErrorRecord -match "error") {
          $SummaryResults += [PSCustomObject]@{ FQDN = $CommonName; Status = "Failed - CSR generation error" }
          continue
      }

      # Verify CSR file contents
      if ($csrfile -match "END CERTIFICATE REQUEST") {
          $csrfile | Out-File -FilePath $CsrFilePath
          $SummaryResults += [PSCustomObject]@{ FQDN = $CommonName; Status = "Success - CSR generated at $CsrFilePath" }
      } else {
          $SummaryResults += [PSCustomObject]@{ FQDN = $CommonName; Status = "Failed - CSR file incomplete" }
      }

  } catch {
      $SummaryResults += [PSCustomObject]@{ FQDN = $CommonName; Status = "Failed - Exception during CSR generation: $_" }
  }
}

Write-Host "`n===== CSR Generation Summary =====" -ForegroundColor Cyan

foreach ($entry in $SummaryResults) {
    if ($entry.Status -like "Success*") {
        Write-Host ("{0,-30} {1}" -f $entry.FQDN, $entry.Status) -ForegroundColor Black -BackgroundColor Green
    } else {
        Write-Host ("{0,-30} {1}" -f $entry.FQDN, $entry.Status) -ForegroundColor White -BackgroundColor Red
    }
}

Write-Host "===================================" -ForegroundColor Cyan


#Log-Finish -LogPath $sLogFile


