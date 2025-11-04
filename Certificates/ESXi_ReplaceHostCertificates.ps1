<#
.SYNOPSIS
  Replace ESXI Host Certificates from Bulk generated certs. 
.DESCRIPTION
  Replace ESXI Host Certificates from Bulk generated certs. Bulk generated certs folder structure should be in the name or IP address.pem and the private key as .key
.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>
.INPUTS
  <Inputs if any, otherwise state None>
.OUTPUTS
  <Outputs if any, otherwise state None - example: Log file stored in C:\Windows\Temp\<name>.log>
.NOTES
  Version:        1.0
  Author:         Matthew Blakeslee-Hisel
  Creation Date:  9/26/2025
  Purpose/Change: 
  

csv template format dnsname,ip,vcenter?


.EXAMPLE
  <Example goes here. Repeat this attribute for more than one example>
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

<#
# Check PowerShell version
if ($PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "This script requires PowerShell Core 7 or later to run."
    return
}

#Required modules: List modules that are required for the script
#Requires –Modules VMWare.PowerCLI
#>

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

Write-Host 
Write-Host "Verify the generated certificates are in the same directory as the target csv list."
Write-Host "Certificates should be in the .pem format WITHOUT IA or CA information"
Write-Host "Private Key should be in the .key format."
Write-Host "Verify all .pems are named in the following format TargetFQDN.pem, or TargetIP.pem or IP_xxx_xxx_xxx_xxx.pem."
Write-Host "For Example: ESXiHost001.leidos.com.pem or 192.168.1.1.pem or IP_192_168_1_1.pem"
Write-Host


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

$vmHosts = Import-CSV -Path $FilePath -Delimiter ',' -Encoding UTF8 | Select-Object fqdn,ip

# Initialize summary results array
$SummaryResults = @()


foreach ($vmHost in $vmHosts)
{

    Remove-Variable -Force -ErrorAction Ignore -Name "CommonName", "IPAddress", "PemFilePath", "$PemFilePathFqdn", "$PemFilePathIP", "$PemFilePathIPUnderscore"

    $CommonName = $Target.fqdn
    $IPAddress  = $Target.ip

    # Define possible PEM file paths
    $PemFilePathFqdn        = Join-Path $FolderPath "$CommonName.pem"
    $PemFilePathIP          = Join-Path $FolderPath "$IPAddress.pem"
    $PemFilePathIPUnderscore = Join-Path $FolderPath ("IP_" + ($IPAddress -replace '\.', '_') + ".pem")

    #Test if file path starts with "cert- or not"
    

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


    if ($vmHost.ConnectionState -ne 'Connected')
    {
        Write-Host "$vmHost is not powered on, continuing to the next host." -ForegroundColor Cyan
        continue
    }
    

    #Get-Host $vmhost command with$($._Parent)

    #Get the existing Host certificate informatiuon
    $HostCert = (Get-View -Id $vmHost.ExtensionData.ConfigManager.CertificateManager).CertificateInfo | Where-Object { $_.Subject -like "*$($vmHost.Name)*" }
    $dateBeforeRenew = $HostCert.NotBefore
    #Display existing certificate information
    
    #Private Key
    $HostPrivateKey= Get-Content $KeyFilePath

    #$HostCert
    $HostCert = Get-Content $PemFilePath

    #Cert


    $hostRef = $vmhost.ExtensionData.MoRef
    $certManager = Get-View -Id 'CertificateManager-certificateManager' #Where $($_.Parent) = $vcenter
    $taskID = $certManager.CertMgrRefreshCertificates_Task(@($hostRef))
    $taskInfo = Get-Task -Id $taskID.ToString()
    while ($taskInfo.State -eq 'Running') {
        $taskInfo = Get-Task -Id $taskID.ToString()
    }
    $dateAfterRenew = (Get-View -Id $vmHost.ExtensionData.ConfigManager.CertificateManager).CertificateInfo
    $taskInfo | Select-Object @{Name='ESXi';Expression={$vmHost.Name}}, State, StartTime, FinishTime, PercentComplete, @{Name='Before_Renew';Expression={$dateBeforeRenew.NotBefore}}, @{Name='After_Renew';Expression={$dateAfterRenew.NotBefore}}
}



foreach ($vmHost in $vmHosts)
{
    $hostParameters = New-Object VMware.Vim.ManagedObjectReference[] (1)
    $hostParameters[0] = New-Object VMware.Vim.ManagedObjectReference
    $hostParameters[0].Type = $vmHost.ExtensionData.MoRef.Type #'HostSystem'
    $hostParameters[0].Value = $vmHost.ExtensionData.MoRef.Value #'host-3023'
    $certificateManager = Get-View -Id 'CertificateManager-certificateManager'
    $taskID = $certificateManager.CertMgrRefreshCertificates_Task($hostParameters)
    $taskInfo = Get-Task -Id $taskID.ToString()
    while ($taskInfo.State -eq 'Running') {
        $taskInfo = Get-Task -Id $taskID.ToString()
    }
}





#Log-Finish -LogPath $sLogFile


