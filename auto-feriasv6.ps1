<#
.Synopsis
   Script to Automated Email Reminders when Users Enabled status change due to Paid work leave.
.DESCRIPTION
   Version 6.0 November 2022
   Requires: Windows PowerShell Module for Active Directory

   Author: Victor Menezes (MCP)
#>
#
##################################################################################################################
## Please Configure the following variables:
    # Specify where to search for users
    # Enter Your SMTP Server Hostname or IP Address
    $smtpServer="smtp.example.com"
    # From Address, eg "IT Support <support@domain.com>"
    $from="TEST - IT <test.it@example.com>"
    # Set to Enabled or Disable Logging
    $logging="Enabled"
    # Log File Path
    $logPath="c:\log-path\logs\"
    # Set to Enabled or Disable log file report
    $reportstatus="Enabled"
    # Log file recipient
    $reportto="test-report@example.com"
###################################################################################################################
#
if (($logging) -eq "Enabled")
{
    # Create Log File
    Write-Output "Criando arquivo de log"
    $logFileName = "log-$(Get-Date -format yyyyMMdd-HHmmss).txt"
    if(($logPath.EndsWith("\")))
    {
       $logPath = $logPath -Replace ".$"
    }
    $logFile = $logPath, $logFileName -join "\"
    Write-Output "Log Output: $logfile"
    # Create TXT File
    #$modifiedUsers = $FmodifiedUsers + $NmodifiedUsers + $VmodifiedUsers
        New-Item $logfile -ItemType File
        $transcript | Out-File -Encoding UTF8 -FilePath $logFile
     #   $modifiedUsers | Out-File -Encoding UTF8 -FilePath $logFile
}
#
## Start PowerShell execution log
Start-Transcript -IncludeInvocationHeader -Path $logFile -Append
#
# Load AD Module
try{
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch{
    Write-Warning "Unable to load Active Directory PowerShell Module"
}
#
# Import Credential
$password = Get-Content -path "C:\password-path\smtp-pwd.txt" | ConvertTo-SecureString
$username = "test.it@example.com"
$credential = New-Object System.Management.Automation.PSCredential($username, $password)
#
## Creating a .Net ArrayList
$FmodifiedUsers = New-Object System.Collections.ArrayList
[System.Collections.ArrayList]$FmodifiedUsers= @()
$VmodifiedUsers = New-Object System.Collections.ArrayList
[System.Collections.ArrayList]$VmodifiedUsers= @()
# 
## System Settings
$textEncoding = [System.Text.Encoding]::UTF8
#
Write-Output "`n ### Aguarde, processando... `n"
#
## Using Invoke-RestMethod to obtain from API the list of users within "F" status
$ApiUsersData = Invoke-RestMethod -Uri "http://url.example.com/rest/api/status?situation=F"
#
#Storing results for accounts with the 'sitfolha' status "F" and that have a 'userlogin'
$Fusers = ($ApiUsersData | where-object {$_.sitfolha -eq 'F' -and $_.userlogin -ne $null})
#
#Storing "F" users Active Directory login
$FusersAD = $Fusers.userlogin
#
#Storing results for accounts with the 'sitfolha' status "V" and that have a 'userlogin'
$Vusers = ($ApiUsersData | where-object {$_.sitfolha -eq 'V' -and $_.userlogin -ne $null})
#
#Storing "N" users Active Directory login
$VusersAD = $Vusers.userlogin
#
#Storing Active Directory results for accounts with the 'sitfolha' status "F"
$FusersADresults = ($FusersAD | Select-Object -Unique).ForEach({Get-ADUser -Identity $_})
#
#Storing Active Directory results for accounts with the 'sitfolha' status "V"
$VusersADresults = ($VusersAD | Select-Object -Unique).ForEach({Get-ADUser -Identity $_})
#
if($FusersADresults | where-object {$_.Enabled -eq $true}) {
    #Disabling accounts with the 'sitfolha' status "F" that are Enabled
    ($FusersAD | Select-Object -Unique).ForEach({Disable-ADAccount -Identity $_})
    #Showing results for users with 'sitfolha' status "F" that are now Disable
    $FmodifiedUsers += Write-Output "Os seguintes usuários do Active Directory foram desabilitados por estarem de férias: `n"
    $FmodifiedUsers += ($FusersAD | Select-Object -Unique).ForEach({Get-ADUser -Identity $_}) | FT Name, Enabled -Autosize
    Write-Output $FmodifiedUsers

}else {
    #Showing results for users with 'sitfolha' status "F"
    $FmodifiedUsers += Write-Output "Nenhum usuário do Active Directory precisou ser desabilitado por estar em período de férias. `n"
    Write-Output $FmodifiedUsers
}
#
if($VusersADresults | where-object {$_.Enabled -eq $false}) {
    #Enabling accounts with the 'sitfolha' status "V" that are Disabled
    ($VusersAD | Select-Object -Unique).ForEach({Enable-ADAccount -Identity $_})
    #Showing results for users with 'sitfolha' status "V" that are now Enable
    $VmodifiedUsers += Write-Output "Os seguintes usuários do Active Directory foram habilitados por estarem retornando do período de férias: `n"
    $VmodifiedUsers += ($VusersAD | Select-Object -Unique).ForEach({Get-ADUser -Identity $_}) | FT Name, Enabled -Autosize
    Write-Output $VmodifiedUsers

}else {
    #Showing results for users with 'sitfolha' status "V"
    $VmodifiedUsers += Write-Output "Nenhum usuário do Active Directory precisou ser habilitado por estar retornando de férias nesse momento. `n"
    Write-Output $VmodifiedUsers
}
#
## Stop PowerShell execution log
Stop-Transcript
#
if (($reportstatus) -eq "Enabled")
    {
        $reportSubject = "Relatório de execução da rotina AD/API - Férias"
        $reportBody ="
    Prezados,
    <p>Informamos que: <br>
    $FmodifiedUsers <br>
    $NmodifiedUsers <br>
    $VmodifiedUsers <br>
	<p>O log de execução do script segue em anexo. <br>
    <p>Agradecemos a atenção,<br>
    <p>Equipe de T.I.<br>
    </P>"
        try{
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 # Set this PowerShell session to be using TLS 1.2
        Send-Mailmessage -smtpServer $smtpServer -usessl -Port 587 -from $from -to $reportto -subject $reportSubject -body $reportBody -bodyasHTML -priority High -Encoding $textEncoding -Credential $credential -Attachments $logFile -ErrorAction Stop 
        }
        catch{
            $errorMessage = $_.Exception.Message
            Write-Output $errorMessage
        }
    }