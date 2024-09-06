<#
Title: Windows Log Collector & Parser 2.3
Date: 07/01/2014
Author: Ryan Clark
Supported Operating Systems: Windows 7/Windows Server 2008(R2) and newer
Supported PowerShell Versions: PowerShell 3.0+

© Copyright 2024 Northrop Grumman Systems Corporation. Licensed under the MIT License, a copy of which is available at https://opensource.org/license/mit 


CHANGELOG
Version:               Description:                                                                              Date:                    
--------------------------------------------------------------------------------------------------------------------------------------
| 1.0                  Initial Release                                                                           07-01-14            |
--------------------------------------------------------------------------------------------------------------------------------------
| 1.1                  -Fixed issue with $pathDir matching $LogsArchive                                          07-23-14            |
|                      -Fixed issue with "Access Denied" when backing up on certain systems by                                       |
|                       adding "-EnableAllPrivileges" to the WMI object                                                              |
--------------------------------------------------------------------------------------------------------------------------------------
| 1.2                  -Decreased parsing time and increased proficiency by using xml                            08-04-14            |
|                       queries                                                                                                      |
--------------------------------------------------------------------------------------------------------------------------------------
| 1.3                  -Filtered out Local Service, IUSR, and computers from event ID 4656                       08-08-14            |
|                      -Added "-parseOnly" paramter (only parses logs stored in $LogsArchive)                                        |
|                      -Added "-collectOnly" parameter (only collects the logs and does not parse them)                              |
|                      -Added "-computerName" parameter (can specify one computer to run against)                                    |
--------------------------------------------------------------------------------------------------------------------------------------
| 1.4                  -Added "-quiet" parameter (does not print status to the screen)                           08-12-14            |
--------------------------------------------------------------------------------------------------------------------------------------
| 1.5                  -Separated Successful and Failed Logons in the report                                     08-14-14            |   
|                      -Added logon type 11 (cached logons) to the 4624 filter                                                       |
|                      -Separated Successful and Failed Password Changes in the report                                               |
|                      -Fixed spacing in the report                                                                                  |
|                      -Added conditional statement in the 4656 filter to ignore usernames ending in "$"                             |
|                      -Added logon types in the report                                                                              |
|                      -Added an event count to each event category in the report                                                    |
--------------------------------------------------------------------------------------------------------------------------------------
| 1.6                  -Fixed issue with Clean-Up function putting logs in random folders                        08-20-14            |
|                      -Added the computer name to all the error messages that get written to the report                             |
|                      -Filtered out Local Service and computers from event ID 4616                                                  |
|                      -Added statement to indicate end of script                                                                    |
|                      -Fixed archived logs issue (backing up but not cleaning up)                                                   |
--------------------------------------------------------------------------------------------------------------------------------------
| 1.7                  -Updated Active Directory filter to only list Windows Vista,7,8 and                       12-09-14            |
|                       Server 2008 (R2), 2012 (R2)                                                                                  |
|                      -Fixed window size error; Changed width from 150 to 128 (128 is max width)                                    |
|                      -Updated $dateTime to reflect 24-hr clock opposed to standard time to distiguish time                         |
|                       of day (AM vs PM)                                                                                            |
|                      -Fixed issue with system names containing underscores; Reformatted naming scheme for                          |
|                       audit log files                                                                                              | 
|                      -Changed the name of the script to not include special characters as this makes problems                      |
|                       with running it as a scheduled task. New name is WindowsLogCollectorAndParserX.X.ps1                         |
|                      -Fixed issue with clean-up function not cleaning all of the audit log files. Adding                           |
|                       sleep time to the clean-up function seemed to partially fix the issue. Added new                             |
|                       function, post-clean, to handle left-over files from the clean-up function.                                  |
|                      -Added capability of hashing logfiles after copying to verify integrity before removing                       |
|                      -Added filter to query the end of each log file for the system name to filter out the                         |
|                       events that contain the system name in the username field.                                                   |
--------------------------------------------------------------------------------------------------------------------------------------
| 1.8                  -Added a query for all logon types on 4624, 4625, 4634 event IDs                          06-15-15            |
|                      -Changed naming convention of saved audit log files to Year-Month-Day@Time.evtx                               |
|                      -Removed the color-write function and used write-host instead                                                 |
|                      -Added to suppress query to filter out SYSTEM, Local Service, and Network Service                             |
|                       from 4624, 4634, 4616, 4656 event IDs                                                                        |
|                      -Updated suppress query to filter out SYSTEM from 4720, 4722, 4723, 4724, 4725, 4726,                         |
|                       4781, 4767, and 4732 event IDs                                                                               |
|                      -Added screen output to show each log being parsed                                                            |
|                      -Removed -quiet parameter (Not Used)                                                                          |
|                      -Fixed formatting for screen output and the report                                                            |
|                      -Added script configuration file so that users would be able to easily modify the                             |
|                       config file without editing the script.                                                                      |
--------------------------------------------------------------------------------------------------------------------------------------
| 1.9                  -Fixed issue with script creating a secondary backup of the logs on the root of C:        06-19-15            |
|                       Added some conditional statements to handle when a backup server is not defined                              |
|                      -Built in functionality to run on local (standalone) system if a domain is not found                          |
--------------------------------------------------------------------------------------------------------------------------------------
| 2.0                  -Fixed issue with reading a list of hosts from a file                                     11-02-15            |
|                      -Fixed issue with processing/saving logs on the same system the script is ran from                            |
|                      -Changed Active Directory computer query to only search for active computers                                  |
|                      -Added feature to check the accuracy of the host file against a domain computer query                         |
|                       and vice-versa                                                                                               |
|                      -Added a path check in addition to the ping check for system availability                                     |
--------------------------------------------------------------------------------------------------------------------------------------
| 2.1                  -Fixed issue with running the script from a remote system and saving the logs on a        01-07-16            | 
|                       system that is being processed.                                                                              |                                          
|                      -Added Help Content (To see type Get-Help .\WLCAPx.x.ps1)                                                     |
|                      -Added a check to report if the EventLog was not cleared                                                      |
|                      -Updated list of Event IDs to more accurately show what is being parsed. Some Event                           |
|                       IDs were removed because the events would never be generated in a DSS compliant setting.                     |
|                      -Added a list of Event IDs captured to the README                                                             |
|                      -Fixed issue with auto rotated application and system logs being put in the parsing                           |
|                       folder and not directly in their respective folder.                                                          |
|                      -Separated the successful/failed screen unlock events from the successful/failed                              |
|                       logon sections of the report. Successful/Failed screen unlock events will have their                         |
|                       own section in the report. This helps clean up the successful/failed logon section of                        |
|                       the report for large environments.                                                                           | 
|                      -Removed Type 7 (Screen Unlock) 4634 (Logoff) events from the report. These events are                        |
|                       generated simultaneous to and as a result of a Type 7 (Screen Unlock) 4624 (Logon).                          | 
|                       Therefore, the events have no value.                                                                         |
|                      -Added the parsing of the System log (Event ID 1074) for Shutdowns. The Security log does                     |
|                       not provide a shutdown event.                                                                                |
|                      -Added logic to parse event IDs 1100, 4739, and 4906. The Event IDs were being pulled but                     |
|                       not parsed.                                                                                                  |
--------------------------------------------------------------------------------------------------------------------------------------
| 2.2                  -Removed check for specific versions of Windows and now just check for "Windows"          08-27-19            |
|                      -Added Unclassified headers and footers in the report output as well as a "(U)"                               |
|                       in the log file and report file names.                                                                       |
|                      -Made the collection portion of the script more verbose to show filenames and filepaths                       |
|                      -Added Event ID 800, 4688                                                                                     |
|                      -Added SYSTEM as the user for event IDs 1100, 4608, 4719, 4739, 4906, 5024, 5025 as                           |
|                       there is no user associated with the events.                                                                 |
|                      -Filtered out 4625 network logon events generated by SYSTEM                                                   |
|                      -Filtered out DWM-1, DWM-2, DWM-3, UMFD0, UMFD1, UMFD2, UMFD3, from 4624, 4634, and 4648                      |
|                      -Changed over to start-bitstransfer instead of copy-item to show progress for large files                     |
|                      -Updated 1074 filter to include support for windows 10, server 2016 and newer                                 |
|                      Updates Done by Sophie Pokorney:                                                                              |
|                      - Added Event ID's:                                                                                           |
|                         307, 4670, 4707, 4713, 4727, 4730, 4731, 4732, 4733, 4734, 4744, 4748, 4749,                               |
|                         4753, 4754, 4758, 4759, 4763, 5024, 5025, 6416                                                             |
|                      - Updated Event ID 800 to specify if it were Powershell, as well as what command was used                     |
|                      - Cleaned up and sorted "if" statements in the parsing function                                               |
--------------------------------------------------------------------------------------------------------------------------------------
| 2.3                  -Fixed issue with script not copying files (Start-BitsTransfer was the problem),          11-12-20            |
|                       by reverting back to the old way of copying files (copy-item).                                               |
|                      -Updated the script to prompt the user to hit enter to exit only if                                           |
|                       the session is interactive.                                                                                  |
|                      -Added clean-up routine to collect only                                                                       |
|                      -Added Excel output option (requires PS 5.1+)                                                                 |
|                      -Events are now stored in objects for easier importing into Excel (requires PS 3+)                            |
|                      -Added event ID 4756 per AD STIG V-43712                                                                      |
|                      -Added event ID to message output for powershell commands (event ID 800)                                      |
|                      -Added event status success/fail to output                                                                    |
|                      -Added schTask parameter to add script to scheduled task automatically                                        |
|                      -Change the way log files are backed up. Using wevtutil vs wmi object                                         |
|                      -Added a report opener function to ask the user which report to open                                          |
|                      -Fixed issue with restart events reporting the wrong user                                                     |
--------------------------------------------------------------------------------------------------------------------------------------
#>

<#
.SYNOPSIS
The Purpose of WLCAP is to automate the collection and parsing of audit logs on Windows7/Server 2008 and newer 
Operating Systems. By default, WLCAP will determine if the system is on a domain or not. If it is on a domain,
it queries the Domain for a list of systems and runs against the systems found. WLCAP first collects the logs 
from each system and then parses the logs. If unable to reach a system, WLCAP will report the failure to the 
screen in yellow and write it to the report. If no domain is found, WLCAP will run against the local system. 
WLCAP is also capable of reading a list of hosts if defined. In each case if WLCAP is unable to save, clear, 
or backup the logs, it will report the failure to the screen in red and write it to the report. 

.DESCRIPTION
WLCAP is a script that collects and parses eventlogs based on DSS audit requirements.

.EXAMPLE
.\WLCAPx.x.ps1
Executes the script with defaults


.EXAMPLE
.\WLCAPx.x.ps1 -ComputerName SystemX
Executes the script for a designated computer (Where SystemX is the target computer name)

.EXAMPLE
.\WLCAPx.x.ps1 -CollectOnly
Executes the script to only collect the logs and not parse them

.EXAMPLE
.\WLCAPx.x.ps1 -ParseOnly
Executes the script to only parse logs that are in the Logs_Archive folder (designated in the config file)

.EXAMPLE
.\WLCAPx.x.ps1 -schTask
Executes the script to create a scheduled task to execute the script once a week. The account used defaults to SYSTEM.
If running the script for all domain computers, change the username of the task to an account with appropriate permissions.

.NOTES
***The config file must be located in the same directory as the script.
***Windows disables powershell script execution by default. For WLCAP to work, script execution must be turned 
   on. Do this by opening a powershell window as Admin and enter the following: 
   
   "set-executionpolicy -force unrestricted"

.LINK

#>

Param(
      [switch]$collectOnly,
      [switch]$parseOnly,
      [string]$computerName,
      [switch]$schTask
     )
if ($computerName) {
    $computerParam = " -computerName:$computerName"
} #end if   


#Run script as admin
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $arguments = "& '" + $myinvocation.mycommand.definition + "'" + "-schTask:$" + $schTask + " -parseOnly:$" + $parseOnly + " -collectOnly:$" + $collectOnly + $computerParam 
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Break
} #end if


#Script Config
$hostName = ((gwmi win32_computersystem).Name)
$psHost = (get-host).UI.RawUI
$psHost.WindowTitle = "Windows Log Collector & Parser 2.3"
$newSize = $psHost.buffersize
$newSize.height = 5000
$newSize.width = 250
$psHost.buffersize = $newSize
$newSize = $psHost.windowsize
$newSize.height = 50
$newSize.width = 128
$psHost.windowsize = $newSize
$headerBreak = "#########################################################################################################################################################"
$lineBreak = "---------------------------------------------------------------------------------------------------------------------------------------------------------"
$ulineBreak = "_________________________________________________________________________________________________________________________________________________________"
$sysBreak = "*********************************************************************************************************************************************************"
$blankSpace = ""
$sectionHeader = "Date/Time              Computer Name     User Name         Status         Event Message"
$scriptPath = Split-Path -Parent $myinvocation.MyCommand.Definition
$schTaskScriptPath = '\"' + $scriptPath + "\" + 'WLCAP2.3.ps1\"'
$WLCAP = "$scriptPath\WLCAP.cfg"
$InstallExcelDir = "$scriptPath\ImportExcel"
$chkImportExcel = (Get-Module ImportExcel).Name
$UI = [Environment]::UserInteractive


#Check for Powershell Version. Version 3 or higher is required.
$PSVer = $PSVersionTable.PSVersion.Major
if ($PSVer -lt 3) {
    "Error....Powershell is at version $PSVer and must be version 3 or higher. Install version 3 or higher in order to run this script. 
    
    Press any key to exit...." | Write-Host -ForegroundColor Red
    if ($UI) {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    exit
}#end if

if ((Test-Path $WLCAP) -eq $True) {
    Get-Content $WLCAP | ForEach-Object -Begin {$conf=@{}} -Process { $k = [regex]::Split($_,'='); if (($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("[") -ne $True)) { $conf.Add($k[0], $k[1]) } }
} #end if
else {
    "Error....Failed to load config file WLCAP.cfg (Incorrect file name or config file is not in the same directory as the script)
    
    Press any key to exit...." | Write-Host -ForegroundColor Red
    if ($UI) {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    exit
} #end else
$ErrorActionPreference = $conf.Get_Item("ERROR_ACTION_PREFERENCE")


#Get Config from config file
$LogFolder = $conf.Get_Item("LOG_FOLDER")
$LogsArchive = $conf.Get_Item("LOG_ARCHIVE")
$enableBackupArchive = $conf.Get_Item("ENABLE_BACKUP_ARCHIVE")
$CollectFWEvents = $conf.Get_Item("COLLECT_FW_EVENTS")
$BackupArchive = $conf.Get_Item("BACKUP_ARCHIVE")
$outputFolder = $conf.Get_Item("OUTPUT_FOLDER")
$outputFN = $conf.Get_Item("OUTPUT_FILE")
$enableHostFile = $conf.Get_Item("ENABLE_HOST_FILE")
$hostFile = $conf.Get_Item("HOST_FILE")
$enableHostDiff = $conf.Get_Item("ENABLE_HOST_DIFF")
$enableTextReport = $conf.Get_Item("ENABLE_TEXT_REPORT")
$enableExcelReport = $conf.Get_Item("ENABLE_EXCEL_REPORT")
# Global Variables
$dateTime = "{0:yyyy-MM-dd@HHmmss}" -f [DateTime]::now
$envUser = [System.Environment]::UserName
$outputTextFN = $outputFN + ".txt"
$outputExcelFN = $outputFN + ".xlsx"
$outputFile = "$outputFolder\(U){0}_{1}" -f $dateTime,$outputTextFN
$outputExcel = "$outputFolder\(U){0}_{1}" -f $dateTime,$outputExcelFN
$tempFolder = "Temp"
$localHost = ((gwmi win32_computersystem).Name)
$domainMem = ((gwmi -computername $localHost win32_computersystem).partofdomain)


#Check some required settings in the config file
#Check for LogFolder
if ($LogFolder -eq $null -or $LogFolder -eq "")
{
    "Error....Failed to find a value for the LOG_FOLDER setting in the config file. 
         The LOG_FOLDER setting is required for the script to run (Default is Audit_Logs).
    
    Press any key to exit...." | Write-Host -ForegroundColor Red
    if ($UI) {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    exit
} #end if

#Check for LogsArchive
if ($LogsArchive -eq $null -or $LogsArchive -eq "")
{
    "Error....Failed to find a path for the LOG_ARCHIVE setting in the config file. 
         The LOG_ARCHIVE setting is required for the script to run.
    
    Press any key to exit...." | Write-Host -ForegroundColor Red
    if ($UI) {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    exit
} #end if

#Check for enableBackupArchive
if ($enableBackupArchive -eq $null -or $enableBackupArchive -eq "")
{
    "Error....Failed to find a value for the ENABLE_BACKUP_ARCHIVE setting in the config file. 
         The ENABLE_BACKUP_ARCHIVE must be set to enabled or disabled for the script to run.
    
    Press any key to exit...." | Write-Host -ForegroundColor Red
    if ($UI) {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    exit
} #end if

#Check for enableBackupArchive
if ($enableBackupArchive -eq "enabled" -and $BackupArchive -eq $null -or $enableBackupArchive -eq "enabled" -and $BackupArchive -eq "")
{
    "Error....Failed to find a path for the BACKUP_ARCHIVE setting in the config file. 
         The BACKUP_ARCHIVE setting is required when the ENABLE_BACKUP_ARCHIVE setting is set to enabled.
    
    Press any key to exit...." | Write-Host -ForegroundColor Red
    if ($UI) {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    exit
} #end if

#Check for outputFN
if ($outputFN -eq $null -or $outputFN -eq "")
{
    "Error....Failed to find a value for the OUTPUT_FILE setting in the config file. 
         The OUTPUT_FILE setting is required for the script to run (Default is weekly-output.txt).
    
    Press any key to exit...." | Write-Host -ForegroundColor Red
    if ($UI) {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    exit
} #end if

#Check for outputFolder
if ($outputFolder -eq $null -or $outputFolder -eq "")
{
    "Error....Failed to find a value for the OUTPUT_FOLDER setting in the config file. 
         The OUTPUT_FOLDER setting is required for the script to run (Default is ""Same path as LOG_ARCHIVE\Audit-output"").
    
    Press any key to exit...." | Write-Host -ForegroundColor Red
    if ($UI) {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    exit
} #end if

#Check enableHostFile
if ($enableHostFile -eq $null -or $enableHostFile -eq "")
{
    "Error....Failed to find a value for the ENABLE_HOST_FILE setting in the config file. 
         The ENABLE_HOST_FILE must be set to enabled or disabled for the script to run.
    
    Press any key to exit...." | Write-Host -ForegroundColor Red
    if ($UI) {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    exit
} #end if

#Check hostFile
if ($enableHostFile -eq "enabled" -and $hostFile -eq $null -or $enableHostFile -eq "enabled" -and $hostFile -eq "")
{
    "Error....Failed to find a path for the HOST_FILE setting in the config file. 
         The HOST_FILE setting is required when the ENABLE_HOST_FILE setting is set to enabled.
    
    Press any key to exit...." | Write-Host -ForegroundColor Red
    if ($UI) {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    exit
} #end if

#Check enableHostDiff
if ($enableHostDiff -eq $null -or $enableHostDiff -eq "")
{
    "Error....Failed to find a value for the ENABLE_HOST_DIFF setting in the config file. 
         The ENABLE_HOST_DIFF must be set to enabled or disabled for the script to run.
    
    Press any key to exit...." | Write-Host -ForegroundColor Red
    if ($UI) {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    exit
} #end if

#Check for enableTextReport and enableExcelReport
if (($enableTextReport -eq $null -and $enableExcelReport -eq $null) -or ($enableTextReport -eq "" -and $enableExcelReport -eq "") -or ($enableTextReport -eq "disabled" -and $enableExcelReport -eq "disabled"))
{
    "Error....Failed to find a value for the ENABLE_TEXT_REPORT and ENABLE_EXCEL_REPORT setting in the config file. 
         One of these must be set to enabled for the script to run and produce a report.
    
    Press any key to exit...." | Write-Host -ForegroundColor Red
    if ($UI) {
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    exit
} #end if


#Check to see if ImportExcel is installed and install if needed. 
if ($enableExcelReport -eq "enabled") {
    if (! $schTask.IsPresent -and ! $chkImportExcel) {
        "Loading Excel Report Module...." | Write-Host -ForegroundColor Green
        #cd $InstallExcelDir
        #Unblock-File -Path .\InstallModule.ps1
        #Invoke-Expression -Command "powershell.exe -ExecutionPolicy Bypass -File .\InstallModule.ps1" | Out-Null
        cd $scriptPath
        if (! (Test-Path C:\Windows\System32\WindowsPowerShell\v1.0\Modules\ImportExcel)) { 
            Unblock-File -Path .\ImportExcel-master.zip
            Expand-Archive -Path .\ImportExcel-master.zip -DestinationPath .\
            Rename-Item -Path .\ImportExcel-master -NewName ImportExcel
            Copy-Item -Path .\ImportExcel -Destination C:\Windows\System32\WindowsPowerShell\v1.0\Modules -Recurse
            Import-Module ImportExcel -force
        }#end if
        else {
            Import-Module ImportExcel -force
        }#end else
        #Checking to see if ImportExcel was installed successfully
        $chkImportExcel = (Get-Module ImportExcel).Name 
        echo $chkImportExcel
        if (! $chkImportExcel) {
            "Error....Failed to install the ImportExcel Module. You may have to install manually. The install script is located here: $InstallExcelDir 
    
            Press any key to exit...." | Write-Host -ForegroundColor Red
            if ($UI) {
                $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            }
            exit
        }#end if
        clear 
    }#end if
} # end if

Function Write-ReportHeader
{
    if (!(Test-Path $outputFolder))
    {
        New-Item $outputFolder -type Directory -force | out-Null
    } #end if
    $headerBreak | Add-Content -Path $outputFile -PassThru | write-host
    "####################################################################--UNCLASSIFIED--#####################################################################" | Add-Content -Path $outputFile
    "#################################################################--Collection Report--###################################################################" | Add-Content -Path $outputFile -PassThru | write-host
    $headerBreak | Add-Content -Path $outputFile -PassThru | write-host
    $lineBreak | Add-Content -Path $outputFile -PassThru | write-host
} #end function Print-ReportHeader


Function Hash($thisFile)
{
    $algorithm = [System.Security.Cryptography.HashAlgorithm]::Create("SHA1")
    $fileStream = ([IO.StreamReader]$thisFile).BaseStream 
    -join ($algorithm.ComputeHash($fileStream) | foreach { "{0:x2}" -f $_ })
    $fileStream.Close()
} #end function Hash


Function Translate-Access ($code) {
    foreach ($AL in $code){
        switch ($AL) {
            "%%4416" {$list += "ReadData (or ListDirectory) "}
            "%%4417" {$list += "WriteData (or AddFile) "}
            "%%4418" {$list += "AppendData (or AddSubdirectory or CreatePipeInstance) "}
            "%%4419" {$list += "ReadEA "}
            "%%4420" {$list += "WriteEA`n"}
            "%%4421" {$list += "Execute/Traverse "}
            "%%4422" {$list += "DeleteChild "}
            "%%4423" {$list += "ReadAttributes "}
            "%%4424" {$list += "WriteAttributes "}
            "%%1537" {$list += "DELETE "}
            "%%1538" {$list += "READ_CONTROL "}
            "%%1539" {$list += "WRITE_DAC "}
            "%%1540" {$list += "WRITE_OWNER "}
            "%%1541" {$list += "SYNCHRONIZE "}
            "%%1542" {$list += "ACCESS_SYS_SEC "}
            default {$list += "Access "}
        }#end switch
    }#end foreach
    return $list
}#end Translate-Access


Function Get-ADComputers
{
    #Search for active computers only
    $ADComputers = ([adsisearcher]'(&(objectcategory=computer) (! userAccountControl:1.2.840.113556.1.4.803:=2))').findall() | foreach {$_.properties}
    foreach ($ADComputer in $ADComputers)
    {
        $OS = $ADComputer.operatingsystem
        $HN = $ADComputer.name
        #Only get Windows Operating Systems (just in case the domain has Linux/Unix in the same domain)
        if ($OS -match "Windows")
        {
            $HN
        } #end if
    } #end foreach
} #end Get-AdComputers function


Function Test-ComputerConnection
{
    foreach ($System in $Computers)
    {
        $computer = $System | %{$_.split('.')[0]}
        if ($domainMem -eq $True)
        {
            $Result = Get-WmiObject -Class win32_pingstatus -Filter "address='$System'"
            if ($Result.Statuscode -eq 0 -and (Test-Path "\\$System\C$") -eq $True -and $computer.length -ge 1)
            {
                Get-BackUpFolder
	            Copy-ArchivedLogs

            } else 
            { 
                "- Skipping $computer .. not accessible" | Add-Content -Path $outputFile -PassThru | write-host -ForegroundColor Yellow
            } #end else
        } elseif($computer.length -ge 1) 
        { 
            Get-BackUpFolder
	        Copy-ArchivedLogs
         } #end if
    } #end foreach
    $lineBreak | Add-Content -Path $outputFile
    $blankSpace | Add-Content -Path $outputFile
    $blankSpace | Add-Content -Path $outputFile
} #end Test-ComputerConnection


Function Get-BackUpFolder
{
    $folder = $computer
    if ($domainMem -eq $True)
    {
        $folders = "$LogsArchive\$folder","$outputFolder","\\$computer\c$\$LogFolder","\\$computer\c$\$LogFolder\$tempFolder"
    } else
    {
        $folders = "$LogsArchive\$folder","$outputFolder","C:\$LogFolder","C:\$LogFolder\$tempFolder"
    } #end else

    $backupFolder = "$BackupArchive\$folder"

    foreach ($dir in $folders)
    {
        if (!(Test-Path $dir))
        {
            New-Item $dir -type Directory -force | out-Null
        } #end if
    } #end foreach
    if ($enableBackupArchive -eq "enabled" -and $BackupArchive -ne $null -or $enableBackupArchive -eq "enabled" -and $BackupArchive -ne "" -and !(Test-Path $backupFolder))
    {
       New-Item $backupFolder -type Directory -force | out-Null
    } #end if
    Backup-EventLogs($Folder)
} #end Get-BackUpFolder function


Function Backup-EventLogs {
    "+ Collecting Logs For $computer" | write-host -ForegroundColor Green
    $EventLogs = "Application","Security","System","Windows PowerShell","Microsoft-Windows-PrintService/Operational"
    foreach($log in $EventLogs) {
        if ($log -match "Microsoft-Windows-PrintService") {
            $fileName = $log.split("/")[0]
        }
        else {
            $fileName = $log
        }
        $logName = "(U){0}.{1}.{2}.evtx" -f $dateTime,$computer,$fileName
        "    + Saving and clearing $fileName...New name is $logName" | write-host -ForegroundColor DarkGreen
        if ($localHost -eq $computer -or $LogsArchive -match "\\\\$computer.*") {
            if ($domainMem -eq $True) {
                $path = ("\\{1}\c$\$LogFolder\temp\(U){0}.{1}.{2}.evtx" -f $dateTime,$computer,$fileName)
            } 
            else {
                $path = ("C:\$LogFolder\temp\(U){0}.{1}.{2}.evtx" -f $dateTime,$computer,$fileName)
            } #end else
        } 
        else {
            if ($domainMem -eq $True) {
                $path = ("\\{1}\c$\$LogFolder\(U){0}.{1}.{2}.evtx" -f $dateTime,$computer,$fileName)
            } 
            else {
                $path = ("C:\$LogFolder\(U){0}.{1}.{2}.evtx" -f $dateTime,$computer,$fileName)
            } #end else
        } #end else
        wevtutil epl $log $path /r:$computer
        if ($? -eq $True) {
            wevtutil cl $log /r:$computer
        } 
        else {
            "        - Unable to clear event log because backup failed on $computer" | Add-Content -Path $outputFile -PassThru | write-host -ForegroundColor Red
        } #end else
        Copy-EventLogsToArchive -path $path -Folder $Folder
    } #end foreach log
    if ($CollectFWEvents -eq "enabled") {
        if ($computer -eq $localHost) {
             "    + Collecting Forwarded Event Logs From $computer" | write-host -ForegroundColor DarkGreen
             Backup_FWEvents ([ref]$ColErrs)
        } #end if
    } #end if
} #end Backup-EventLogs function


Function Backup_FWEvents()
{
    $FWEventCount = (get-winevent -ListLog ForwardedEvents).RecordCount
    $FWLog = "C:\$LogFolder\(U){0}.{1}.ForwardedEvents.evtx" -f $dateTime,$computer
    if (! $FWEventCount -eq "" -or ! $FWEventCount -eq $null)
    {
        $BkupRES = wevtutil export-log forwardedevents $FWLog
        if ($BkupRES -eq $null)
        {
            $ClrRES = wevtutil clear-log forwardedevents
            if ($ClrRES -ne $null)
            {
                if ($TextReport -eq "enabled")
                {
                    "        - Forwarded Event Log was saved but could not be cleared on $computer" | Add-Content -Path $outputFile -PassThru | write-host -ForegroundColor Red
                } # end if
                $ColErrs.value += "$computer     Forwarded Event Log was saved but could not be cleared."
            } # end if
        } else
        {
            if ($TextReport -eq "enabled")
            {
                "        - Forwarded Event Log could not be saved on $computer" | Add-Content -Path $outputFile -PassThru | write-host -ForegroundColor Red
            } # end else
            $ColErrs.value += "$computer     Forwarded Event Log could not be saved."        
        } # end else
    } elseif ($TextReport -eq "enabled")
    {
        "        - Forwarded Event Count is 0. There are no Forwarded Events to collect on $computer" | write-host -ForegroundColor Yellow
        $ColErrs.value += "$computer     Forwarded Event Count is 0. There are no Forwarded Events to collect."
    } #end else
} #end Function Backup_FWEvents


Function Copy-EventLogsToArchive($path, $folder, [ref]$ColErrs) {
    $shortName = split-path -Path $path -Leaf -Resolve
    "        + Copying $shortName to primary backup location $LogsArchive to be parsed." | write-host -ForegroundColor DarkGreen
	#Start-BitsTransfer -Source $path -Destination "$LogsArchive" -Description "Copying $path to $LogsArchive"
    Copy-Item -path $path -destination "$LogsArchive" -force
    if ($enableBackupArchive -eq "enabled" -and $BackupArchive -ne $null -or $enableBackupArchive -eq "enabled" -and $BackupArchive -ne "") {
        "        + Copying $shortName to secondary backup location: $BackupArchive\$folder" | write-host -ForegroundColor DarkGreen
        #Start-BitsTransfer -Source $path -Destination "$BackupArchive\$folder" -Description "Copying $path to $BackupArchive\$folder"
        Copy-Item -path $path -destination "$BackupArchive\$folder" -force
        $testbackupLog = test-path "$BackupArchive\$computer\$logName"
        $testbackupLoc = test-path "$BackupArchive\$computer"
        $backupHash = Hash("$BackupArchive\$computer\$logName")
    } #end if
    $logType = $log.LogFileName
    $testarchiveLog = test-path "$LogsArchive\$logName"
    $origlogHash = Hash($path)
    $netlogHash = Hash("$LogsArchive\$logName")
    if ($testarchiveLog -eq "True" -and $netlogHash -eq $origlogHash) {
        if ($testbackupLoc -eq "True") {
            if ($testbackupLog -ne "True" -or $backupHash -ne $origlogHash) {
                "        - Could not determine if the $logType log on $computer was successfully copied to the backup location. Copy manually." | Add-Content -Path $outputFile -PassThru | write-host -ForegroundColor Red
            } #end if
        }#end if 
        remove-item $path -force
    }#end if
    else {
        if ($domainMem -eq $True) {
            "        - Could not determine if the $logType log on $computer was successfully copied to the archive location.`n  Check \\$computer\C$\$LogFolder for logs and backup manually." | Add-Content -Path $outputFile -PassThru | write-host -ForegroundColor Red
        }#end if 
        else {
            "        - Could not determine if the $logType log on $computer was successfully copied to the archive location.`n  Check C:\$LogFolder for logs and backup manually." | Add-Content -Path $outputFile -PassThru | write-host -ForegroundColor Red
        } #end else
    } #end else
} #end Copy-EventLogsToArchive function


Function Copy-ArchivedLogs
{
    #Function Variables
    if ($domainMem -eq $True)
    {
        $archivedLogs = get-childitem "\\$computer\C$\Windows\System32\winevt\Logs\Archive*"
        $archlogDir = "\\$computer\C$\Windows\System32\winevt\Logs"
    } else
    {
        $archivedLogs = get-childitem "C:\Windows\System32\winevt\Logs\Archive*"
        $archlogDir = "C:\Windows\System32\winevt\Logs"
    } #end else
    #Look for rotated logs 
    if ($archivedLogs -ne $null)
    {
        "    + Archived Logs Found on $computer ....Collecting Archived Logs" | write-host -ForegroundColor DarkGreen
        foreach ($log in $archivedLogs)
        {
            $logName = $log.name
		    $date = $logName | %{$_.split('-')[2,3,4]}
            $time = $logName | %{$_.split('-')[5,6,7]} | %{$_.split('.')[0]}
            $logType = $logName | %{$_.split('-')[1]}
            $joinDate = $date -join "-"
            $joinTime = $time -join ""
            $renameLog = "(U){0}@{1}.{2}.{3}.evtx" -f $joinDate,$joinTime,$computer,$logType

            #Start-BitsTransfer -Source $log -Destination "$LogsArchive\$renameLog" -Description "Copying $log to $LogsArchive\$renameLog"
            copy-item -path $log -destination "$LogsArchive\$renameLog" -force
            if ($enableBackupArchive -eq "enabled" -and $BackupArchive -ne $null -or $enableBackupArchive -eq "enabled" -and $BackupArchive -ne "") {
                #Start-BitsTransfer -Source $log -Destination "$BackupArchive\$computer\$renameLog" -Description "Copying $log to $BackupArchive\$computer\$renameLog"
                copy-Item -path $log -destination "$BackupArchive\$computer\$renameLog" -force
                $testbackupLog = test-path "$BackupArchive\$computer\$renameLog"
                $testbackupLoc = test-path "$BackupArchive\$computer"
                $backupHash = Hash("$BackupArchive\$computer\$renameLog")
            } #end if
            $testarchiveLog = test-path "$LogsArchive\$renameLog"
            $origlogHash = Hash("$archlogDir\$logName")
            $netlogHash = Hash("$LogsArchive\$renameLog")
            if ($testarchiveLog -eq "True" -and $netlogHash -eq $origlogHash) {
                if ($testbackupLoc -eq "True") {
                    if ($testbackupLog -ne "True" -or $backupHash -ne $origlogHash) {
                        "        - Could not determine if the auto archived $logType log on $computer was successfully copied to the backup location. Copy manually." | Add-Content -Path $outputFile -PassThru | write-host -ForegroundColor Red
                    } #end if
                } #end if
                remove-item $log -force
            } elseif ($domainMem -eq $True) {
                "        - Could not determine if the auto archived log on $computer was successfully copied to the archive location.`n  Check \\$computer\C$\Windows\System32\winevt\Logs\ for logs and collect manually." | Add-Content -Path $outputFile -PassThru | write-host -ForegroundColor Red
            } 
            else {
                "        - Could not determine if the auto archived log on $computer was successfully copied to the archive location.`n  Check C:\Windows\System32\winevt\Logs\ for logs and collect manually." | Add-Content -Path $outputFile -PassThru | write-host -ForegroundColor Red
            } #end else
        } #foreach
    } #end if
} #end Copy-ArchivedLogs function

Function Parse-Logs
{
    #Function Variables
    $logBack = get-childitem "$LogsArchive\*.evt*" | foreach {$_.Name}
    $logCount = $logBack.count
    $Sys = (([adsisearcher]"objectcategory=computer").findall()) | foreach {($_.properties).name}
    $blankSpace | write-host
    $blankSpace | write-host     
    $headerBreak | write-host
    "################################################################--Parsing Audit Logs--###################################################################" | write-host #$this comment is here so that this command doesn't show up in the report
    $headerBreak | write-host
    $lineBreak | write-host
    if (!(Test-Path $outputFolder))
    {
        New-Item $outputFolder -type Directory -force | out-Null
    } #end if
    if ($logBack -ne $null)
    {
        $SLogons = @()
        $FLogons = @()
        $Logoffs = @()
        $SScrnUnlock = @()
        $FScrnUnlock = @()
        $LockedAccounts = @()
        $SPasswdChanges = @()
        $FPasswdChanges = @()
        $AcctManages = @()
        $SysIntegrity = @()
        $SecObjects = @()
        $CommandLine = @()
        $Print = @()
        $PolicyChange = @() 
        $SystemEvents = @() 
        $RStorageConnect = @() 
        $PermObjects = @() 
        #$RStorageAccess = @() #added Too many events generated with 4663
        $FileListScript = @()
        $AVScript = @()
        $AVTScript = @()

        
     
        "+ Parsing Audit Logs" | write-host -ForegroundColor Green #$this comment is here so that this command doesn't show up in the report
        foreach ($logs in $logBack)
        {
            $sysAccount = $logs.split('.')[1] + "$" #This is to filter out events by the system account.....probably won't work with forwarded event logs
            "     Parsing $logs" | write-host -ForegroundColor DarkGreen #$this comment is here so that this command doesn't show up in the report
            #$Anon = "S-1-5-7"
            $IUSR = "S-1-5-17"
            $SYSTEM = "S-1-5-18"
            $LService = "S-1-5-19"
            $NService = "S-1-5-20"
            #XPath 1.0 Search Query
            $filter = @"
            <QueryList>
	        <Query Id="0" Path="file://$LogsArchive\$logs">
		    <Select Path="file://$LogsArchive\$logs">
            *[System[(EventID=307 or EventID=800 or EventID=1074 or EventID=1100 or EventID=1102 or EventID=4608 or EventID=4616 or EventID=4624 or EventID=4625 or EventID=4634 or EventID=4648 or EventID=4656)]]
            or
            *[System[(EventID=4670 or EventID=4688 or EventID=4706 or EventID=4707 or EventID=4713 or EventID=4719 or EventID=4720 or EventID=4722 or EventID=4723 or EventID=4724 or EventID=4725 or EventID=4726)]]
            or
            *[System[(EventID=4727 or EventID=4728 or EventID=4730 or EventID=4731 or EventID=4732 or EventID=4733 or EventID=4734 or EventID=4739 or EventID=4740 or EventID=4744 or EventID=4748 or EventID=4749)]]
            or
            *[System[(EventID=4753 or EventID=4754 or EventID=4758 or EventID=4759 or EventID=4763 or EventID=4767 or EventID=4781 or EventID=4906 or EventID=5024 or EventID=5025 or EventID=6416 or EventID=4756)]]
 		    </Select>
            <Suppress Path="file://$LogsArchive\$logs">
            *[EventData[Data[@Name='TargetUserSid']='$SYSTEM']
            or
            EventData[Data[@Name='TargetUserSid']='$LService']
            or
            EventData[Data[@Name='TargetUserSid']='$NService']
            or
            EventData[Data[@Name='TargetDomainName']='Window Manager']
            or
            EventData[Data[@Name='TargetDomainName']='Font Driver Host']
            or
            EventData[Data[@Name='LogonType']='3']
            and
            System[(EventID='4624' or EventID='4634' or EventID='4648')]]
            or
            *[EventData[Data[@Name='TargetUserName']='$sysAccount']
            or
            EventData[Data[@Name='SubjectUserSid']='$SYSTEM']
            and
            System[(EventID='4648')]]
            or
            *[System[(EventID='4616' or EventID='4656' or EventID='4670' or EventID='4688')]
            and
            EventData[Data[@Name='SubjectUserSid']='$SYSTEM']
            or
            EventData[Data[@Name='SubjectUserSid']='$LService']
            or
            EventData[Data[@Name='SubjectUserSid']='$NService']]
            or
            *[System[(EventID='4720' or EventID='4722' or EventID='4723' or EventID='4724' or EventID='4725' or EventID='4726' or EventID='4781' or EventID='4767' or EventID='4732')]
            and
            EventData[Data[@Name='SubjectUserSid']='$SYSTEM']]
            or
            *[System[(EventID='4688')]
            and
            EventData[Data[@Name='TokenElevationType']='\%\%1936']
            or
            EventData[Data[@Name='CommandLine']='\??\C:\WINDOWS\system32\conhost.exe 0xffffffff -ForceV1']]
            </Suppress>
	        </Query>
            </QueryList>
"@

            $events = get-winevent -oldest -filterXml $filter
            if ($events -ne $null)
            {
                foreach ($logEntry in $events)
                {
                    $time = $logEntry.TimeCreated
                    $entry = [xml]$logEntry.ToXml()
                    $sysName = $entry.Event.System.Computer | %{$_.split('.')[0]}
                    $sysJustify = (15 - $sysName.count) + 4
                    $eventID = $entry.Event.System.EventID
                    $evtStatus = $entry.Event.System.Keywords
                    $success = "0x8020000000000000"
                    $failure = "0x8010000000000000"

                    #Setting event status
                    if ($evtStatus -eq $success) {
                        $status = "Success"
                    }#end if
                    elseif ($evtStatus -eq $failure) {
                        $status = "Failure"
                    }#end elseif
                    else {
                        $status = "Information"
                    }#end else


                    if($eventID -eq 307){
                        $userName = $entry.Event.UserData.DocumentPrinted.Param3
                        $fileName = $entry.Event.UserData.DocumentPrinted.Param2
                        $pages = $entry.Event.UserData.DocumentPrinted.Param8
                        $usrJustify = (15 - $userName.count) + 4
                        $message = "$eventID - Printed $fileName ( + $pages +  page(s))"
                        #Create object to store event
                        $Prnt = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $Print += $Prnt
                    } elseif($eventID."#text" -eq 800) #"#text" needed to work for some reason???
                    {
                        $eventID = $eventID."#text" #This is so that the event ID will print out correctly in the report
                        $eventData = $entry.Event.EventData.Data
                        $CMD = (($eventData | select-string -pattern 'CommandLine\=.*' -AllMatches | %{$_.Matches} | %{$_.Value}).split('=')[1]).trim()
                        if ($CMD -notmatch '\\s*$' -and $CMD -notmatch '\$' -and $CMD -notmatch 'Microsoft\.PowerShell\.Core' -and $CMD -notmatch 'RequiredAssemblies'-and $CMD -ne "" -and $CMD -ne $null -and $CMD -notmatch '^C\:\\.*') {
                            $userName = (($eventData | select-string -pattern 'UserId\=.*' -AllMatches | %{$_.Matches} | %{$_.Value}).split('=')[1]).split('\')[1]
                            $usrJustify = (15 - $userName.count) + 4
                            $message = "$eventID - Execution of Powershell Command: $CMD"
                            #Create object to store event
                            $CL = [PSCustomObject]@{
                            Time = $time
                            System = $sysName
                            User = $userName
                            Message = $message
                            Status = $status
                            }#end object
                            $CommandLine += $CL
                        }
                    } elseif ($eventID -eq 1074 -or $eventID."#text" -eq 1074) #"#text" needed to work for some reason???
                    {
					    #clear userName so it doesn't retain old values
						$userName = ""
                        if ($entry.SelectSingleNode("//*[@Name='param1']")) {
                            $eventID = $eventID."#text" #This is so that the event ID will print out correctly in the report
                            $type = ($entry.SelectSingleNode("//*[@Name='param5']"))."#text"
                            $userName = (($entry.SelectSingleNode("//*[@Name='param7']"))."#text").split('\')[1]
                            if ($type -match '[Rr]estart') {
                                $message = "$eventID - Restarted Computer"
                            } #end if
                            elseif ($type -match '[Pp]ower [Oo]ff') {
                                $message = "$eventID - Powered Off Computer"
                            } #end elseif
                            else {
                                $message = "$eventID - $type"
                            } #end else
                        }#end if    
                        else {
                            $eventID = $eventID."#text" #This is so that the event ID will print out correctly in the report
                            $MSG = @()       
                            $Data = $entry.Event.EventData.Data
                            foreach ($line in $Data) { 
                                $MSG += $line
                            } #end foreach
                            if ($MSG[0] -notmatch '[Ee]xplorer') {
                                if ($MSG[6] -match '\\') {
                                    $userName = $MSG[6].split('\')[1]
                                } #end if
                                else {
                                    $userName = $MSG[6]
                                } #end else    
                                $type = $MSG[4]
                                if ($type -match '[Rr]estart') {
                                    $message = "$eventID - Restarted Computer"
                                } #end if
                                elseif ($type -match '[Pp]ower [Oo]ff') {
                                    $message = "$eventID - Powered Off Computer"
                                } #end elseif
                                else {
                                    $message = "$eventID - $type"
                                } #end else
                            }#end if
                        }#end else
                        $SI = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $SysIntegrity += $SI
                    } elseif ($eventID -eq 1100)
                    { 
                        $message = "$eventID - The Eventlog Service Shut Down (Likely A System Shutdown)"
                        $userName = "SYSTEM"
                        #Create object to store event
                        $SI = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $SysIntegrity += $SI
                    } elseif ($eventID -eq 1102)
                    { 
                        $userName = $entry.Event.UserData.LogFileCleared.SubjectUserName
                        $usrJustify = (15 - $userName.count) + 4
                        $message = "$eventID - Cleared The Event Log"
                        #Create object to store event
                        $SI = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $SysIntegrity += $SI
                    } elseif ($eventID -eq 4608)
                    { 
                        $message = "$eventID - System Started Up"
                        $userName = "SYSTEM"
                        #Create object to store event
                        $SI = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $SysIntegrity += $SI
                    } elseif ($eventID -eq 4616)
                    {
                        if ($entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text" -ne "*$"){  
                            $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                            $usrJustify = (15 - $userName.count) + 4
                            $message = "$eventID - Changed The System Time"
                            #Create object to store event
                            $SI = [PSCustomObject]@{
                            Time = $time
                            System = $sysName
                            User = $userName
                            Message = $message
                            Status = $status
                            }#end object
                            $SysIntegrity += $SI
                        } #end if
                    } elseif ($eventID -eq 4624)
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        if ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "2")
                        {
                            $message = "$eventID - Logged On Interactively"
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "3")
                        {
                            $message = "$eventID - Network Logon"
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "4")
                        {
                            $message = "$eventID - Logged On As A Batch Job Or Scheduled Task"
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "5")
                        {
                            $message = "$eventID - Logged On As A Service"
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "7")
                        {
                            $message = "$eventID - Unlocked The Screen"
                            #Create hash table to store event
                            $SUL = [PSCustomObject]@{
                            Time = $time
                            System = $sysName
                            User = $userName
                            Message = $message
                            Status = $status
                            }#end object
                            $SScrnUnlock += $SUL
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "8")
                        {
                            $message = "$eventID - Logged On With Cleartext Credentials (Likely IIS related)"
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "9")
                        {
                            $message = "$eventID - Logged On With Different Credentials"
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "10")
                        {
                            $message = "$eventID - Logged On Remotely"
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "11")
                        {
                            $message = "$eventID - Logged On With Cached Credentials"
                        } else
                        {
                            $message = "$eventID - Logged On With Unknown Type"
                        } #end else
                        if ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -ne "7")
                        {
                            #Create object to store event
                            $SL = [PSCustomObject]@{
                            Time = $time
                            System = $sysName
                            User = $userName
                            Message = $message
                            Status = $status
                            }#end object
                            $SLogons += $SL
                        } #end if
                    } elseif ($eventID -eq 4625)
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $wsName = $entry.SelectSingleNode("//*[@Name='WorkstationName']")."#text"
                        $ipAddr = $entry.SelectSingleNode("//*[@Name='IpAddress']")."#text"
                        $domain = $entry.SelectSingleNode("//*[@Name='TargetDomainName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        if ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "2")
                        {
                            $message = "$eventID - Failed To Logon Interactively"
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "3")
                        {
                            $message = "$eventID - Failed Network Logon Workstation: $wsName IP Address: $ipAddr Domain: $domain"
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "4")
                        {
                            $message = "$eventID - Failed Batch Logon"
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "5")
                        {
                            $message = "$eventID - Failed Service Logon"
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "7")
                        {
                            $message = "$eventID - Failed To Unlock"
                            #Create object to store event
                            $FUL = [PSCustomObject]@{
                            Time = $time
                            System = $sysName
                            User = $userName
                            Message = $message
                            Status = $status
                            }#end object
                            $FScrnUnlock += $FUL
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "8"){
                            $message = "$eventID - Failed Netork Cleartext Logon"
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "9")
                        {
                            $message = "$eventID - Failed Logon With New Credentials"
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "10")
                        {
                            $message = "$eventID - Failed To Logon Remotely"
                        } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "11")
                        {
                            $message = "$eventID - Failed To Logon With Cached Credentials"
                        } else
                        {
                            $message = "$eventID - Failed To Logon With Unknown Type"
                        } #end else 
                        if ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -ne "7"){
                            #Create object to store event
                            $FL = [PSCustomObject]@{
                            Time = $time
                            System = $sysName
                            User = $userName
                            Message = $message
                            Status = $status
                            }#end object
                            $FLogons += $FL
                        }
                    } elseif ($eventID -eq 4634)
                    { 
                      $userName = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                      $usrJustify = (15 - $userName.count) + 4
                      if ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "2")
                      {
                          $message = "$eventID - Logged Off Interactively"
                      } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "3")
                      {
                          $message = "$eventID - Logged Off From A Network Logon"
                      } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "4")
                      {
                          $message = "$eventID - Logged Off As A Batch Job Or Scheduled Task"
                      } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "5")
                      {
                          $message = "$eventID - Logged Off As A Service"
                      } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "7")
                      {
                          $message = "$eventID - Logged Off From A Screen Lock Session"
                      } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "8")
                      {
                          $message = "$eventID - Logged Off From A Cleartext Logon (Likely IIS related)"
                      } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "9")
                      {
                          $message = "$eventID - Logged Off From Using Different Credentials"
                      } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "10")
                      {
                          $message = "$eventID - Logged Off Remotely"
                      } elseif ($entry.SelectSingleNode("//*[@Name='LogonType']")."#text" -eq "11")
                      {
                          $message = "$eventID - Logged Off With Cached Credentials"
                      } else
                      {
                          $message = "$eventID - Logged Off With Unknown Type"
                      } #end else
                          #Create object to store event
                          $LO = [PSCustomObject]@{
                          Time = $time
                          System = $sysName
                          User = $userName
                          Message = $message
                          Status = $status
                          }#end object
                          $Logoffs += $LO
                    #} elseif($eventID -eq 4647) #added SP #Generates duplicates?
                    #{
                    #    $userName = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                    #    $usrJustify = (15 - $userName.count) + 4
                    #    $message = "User Successfully Initiated Logoff"
                    #    $Logoffs += "$time    " + $sysName.PadRight($sysJustify, " ") + $userName.PadRight($usrJustify, " ") + $message
                    #
                    } elseif ($eventID -eq 4648)
                    {
                         $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                         $tUserName = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                         $message = "$eventID - Logged in using explicit credentials with UserName: " + $tUserName
                         #Create object to store event
                         $SL = [PSCustomObject]@{
                         Time = $time
                         System = $sysName
                         User = $userName
                         Message = $message
                         Status = $status
                         }#end object
                         $SLogons += $SL
                    } 
                    elseif ($eventID -eq 4656) {    
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $object = $entry.SelectSingleNode("//*[@Name='ObjectName']")."#text"
                        $accessList = $entry.SelectSingleNode("//*[@Name='AccessList']")."#text"
                        $accessList = -Split $accessList 
                        $accessType = Translate-Access $accessList
                        $message = "$eventID - File Access To $object"
                        #Create object to store event
                        $SO = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Access =  $accessType
                        Status = $status
                        }#end object
                        $SecObjects += $SO
                    #} elseif($eventID -eq 4663) #added SP Too many events get generated and make the script unusable
                    #{ 
                    #    $RSpath = $entry.SelectSingleNode("//*[@Name='ObjectName']")."#text"
                    #    if ($RSpath -match '^\\Device.*') {
                    #        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                    #        $usrJustify = (15 - $userName.count) + 4
                    #        $message = "A Removable Storage Device/Path Was Accessed: " + $RSpath #This is assumed here because the xpath filter only gets Removable Storage Task Category events
                    #        $RStorageAccess += "$time    " + $sysName.PadRight($sysJustify, " ") + $userName.PadRight($usrJustify, " ") + $message
                    #    }
                    } 
                    elseif($eventID -eq 4670) #added SP
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $objPath = $entry.SelectSingleNode("//*[@Name='ObjectName']")."#text"
                        $message = "$eventID - Permissions On An Object Were Successfully Changed: " + $objPath
                        #Create object to store event
                        $PO = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $PermObjects += $PO
                    } elseif ($eventID -eq 4688) #added RC
                    {
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $CMD = ($entry.SelectSingleNode("//*[@Name='CommandLine']")."#text").trim()
                        #$TokenType = $entry.SelectSingleNode("//*[@Name='TokenElevationType']")."#text" #Doing Token elevation type in the xpath filter
                        $message = "$eventID - Command Line: " + $CMD
                        if ($CMD -ne "" -and $CMD -ne $null -and $CMD -notmatch 'C\:.*'){ 
                            #Create object to store event
                            $CL = [PSCustomObject]@{
                            Time = $time
                            System = $sysName
                            User = $userName
                            Message = $message
                            Status = $status
                            }#end object
                            $CommandLine += $CL
                        } #end if
                    } elseif($eventID -eq 4706) #added SP
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $message = "$eventID - A Trust To A Domain Was Created"
                        #Create object to store event
                        $PC = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $PolicyChange += $PC
                    } elseif($eventID -eq 4707) #added SP
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $message = "$eventID - A Trust To A Domain Was Removed"
                        #Create object to store event
                        $PC = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $PolicyChange += $PC
                    } elseif($eventID -eq 4713) #added SP
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $message = "$eventID - Kerberos Policy Was Changed"
                        #Create object to store event
                        $PC = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $PolicyChange += $PC
                    #} elseif($eventID -eq 4715) #added #Doesn't provide object name
                    #{ 
                    #    $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                    #    $usrJustify = (15 - $userName.count) + 4
                    #    $message = "The Audit Policy On An Object Was Changed"
                    #    $PolicyChange += "$time    " + $sysName.PadRight($sysJustify, " ") + $userName.PadRight($usrJustify, " ") + $message
                    } elseif ($eventID -eq 4719)
                    { 
                        #$userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text" #username is always the system account
                        $userName = "SYSTEM"
                        $usrJustify = (15 - $userName.count) + 4
                        $subCatID = $entry.SelectSingleNode("//*[@Name='SubcategoryGuid']")."#text"
                        $subCat = auditpol /list /subcategory:* -v | where {$_ -match $subCatID} | %{$_.split('{')[0]}
                        $message = "$eventID - Audit Policy Changed: $subCat"
                        #Create object to store event
                        $PC = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $PolicyChange += $PC
                    } elseif ($eventID -eq 4720)
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $acct = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - Created Account $acct"
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif ($eventID -eq 4722)
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $acct = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - Enabled Account $acct"
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif ($eventID -eq 4723)
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $acct = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $keyWord = $entry.Event.System.Keywords
                        if ($keyWord -eq "0x8010000000000000")
                        {
                            $message = "$eventID - Failed To Reset Password On Account $acct"
                            #Create object to store event
                            $FP = [PSCustomObject]@{
                            Time = $time
                            System = $sysName
                            User = $userName
                            Message = $message
                            Status = $status
                            }#end object
                            $FPasswdChanges += $FP
                        } else
                        {
                            $message = "$eventID - Successfully Reset Password On Account $acct"
                            #Create object to store event
                            $SP = [PSCustomObject]@{
                            Time = $time
                            System = $sysName
                            User = $userName
                            Message = $message
                            Status = $status
                            }#end object
                            $SPasswdChanges += $SP
                        } #end else
                    } elseif ($eventID -eq 4724)
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $acctSid = $entry.SelectSingleNode("//*[@Name='TargetSid']")."#text"
                        $acct = ([wmi]"\\$sysName\root\cimv2:win32_sid.sid='$acctSid'").AccountName
                        $keyWord = $entry.Event.System.Keywords
                        if ($keyWord -eq "0x8010000000000000"){
                            $message = "$eventID - Failed To Reset Password On Account $acct"
                            #Create object to store event
                            $FP = [PSCustomObject]@{
                            Time = $time
                            System = $sysName
                            User = $userName
                            Message = $message
                            Status = $status
                            }#end object
                            $FPasswdChanges += $FP
                        } else
                        {
                            $message = "$eventID - Successfully Reset Password On Account $acct"
                            #Create object to store event
                            $SP = [PSCustomObject]@{
                            Time = $time
                            System = $sysName
                            User = $userName
                            Message = $message
                            Status = $status
                            }#end object
                            $SPasswdChanges += $SP
                        } #end else
                    } elseif ($eventID -eq 4725)
                    {
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $acct = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                          $message = "$eventID - Disabled Account $acct"
                          #Create object to store event
                          $AM = [PSCustomObject]@{
                          Time = $time
                          System = $sysName
                          User = $userName
                          Message = $message
                          Status = $status 
                          }#end object
                          $AcctManages += $AM
                      } elseif ($eventID -eq 4726)
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $acct = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - Deleted Account $acct"
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif($eventID -eq 4727) #added SP
                    {
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $targetGroup = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - A Security-Enabled Global Group Was Successfully Created: " + $targetGroup
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif ($eventID -eq 4728) # added RC
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $member = $entry.SelectSingleNode("//*[@Name='MemberName']")."#text"
                        $targetGroup = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - " + $member + " Was Added To A Security-Enabled Global Group: " + $targetGroup
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif($eventID -eq 4730) #added RC
                    {
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $targetGroup = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - A Security-Enabled Global Group was Deleted: " + $targetGroup
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif($eventID -eq 4731)#added RC
                    {
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $targetGroup = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - A Security-Enabled Local Group Was Created: " + $targetGroup
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif ($eventID -eq 4732)
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $group = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $acctSID = $entry.SelectSingleNode("//*[@Name='MemberSid']")."#text"
                        $acct = ([wmi]"\\$sysName\root\cimv2:win32_sid.sid='$acctSid'").AccountName
                        $message = "$eventID - Added Account $acct To Group $group"
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif ($eventID -eq 4733)# added RC
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $member = $entry.SelectSingleNode("//*[@Name='MemberName']")."#text"
                        $targetGroup = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - " + $member + " Was Removed From A Security-enabled Local Group: " + $targetGroup
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif ($eventID -eq 4734)#added RC
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $targetGroup = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - A Security-Enabled Local Group was Deleted: " + $targetGroup
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif ($eventID -eq 4739) 
                    {
                        $Change = $entry.SelectSingleNode("//*[@Name='DomainPolicyChanged']")."#text"
                        $userName = "SYSTEM"
                        $message = "$eventID - $Change Has Been Changed"
                        #Create object to store event
                        $SI = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $SysIntegrity += $SI
                    } elseif ($eventID -eq 4740)
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $remoteSys = $entry.SelectSingleNode("//*[@Name='TargetDomainName']")."#text"
                        $message = "$eventID - Locked Account From $remoteSys"
                        #Create object to store event
                        $LA = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $LockedAccounts += $LA
                    } elseif ($eventID -eq 4744)#added RC
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $targetGroup = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - A Security-Disabled Local Group Was Created: " + $targetGroup
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif($eventID -eq 4748)#added RC
                    {
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $targetGroup = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - A Security-Disabled Local Group Was Deleted: " + $targetGroup
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif($eventID -eq 4749)#added RC
                    {
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $targetGroup = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - A Security-Disabled Global Group Was Created: " + $targetGroup
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif($eventID -eq 4753)#added RC
                    {
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $targetGroup = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - A Security-Disabled Global Group was Deleted: " + $targetGroup
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif($eventID -eq 4754)#added RC
                    {
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $targetGroup = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - A Security-Enabled Universal Group Was Successfully Created: " + $targetGroup
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif($eventID -eq 4756)#added RC
                    {
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $group = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $acctSID = $entry.SelectSingleNode("//*[@Name='MemberSid']")."#text"
                        $acct = ([wmi]"\\$sysName\root\cimv2:win32_sid.sid='$acctSid'").AccountName
                        $message = "$eventID - Added Account $acct To Group $group"
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif ($eventID -eq 4758)#added RC
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $targetGroup = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - A Security-Enabled Universal Group was Deleted: " + $targetGroup
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        }#end object
                        $AcctManages += $AM
                    } elseif($eventID -eq 4759)#added RC
                    {
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $targetGroup = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - A Security-Disabled Universal Group Was Created: " + $targetGroup
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif($eventID -eq 4763) #added RC
                    {
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $targetGroup = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - A Security-Disabled Universal Group Was Deleted: " + $targetGroup
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif ($eventID -eq 4767)
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $acct = $entry.SelectSingleNode("//*[@Name='TargetUserName']")."#text"
                        $message = "$eventID - Unlocked Account $acct"
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif ($eventID -eq 4781)
                    { 
                        $userName = $entry.SelectSingleNode("//*[@Name='SubjectUserName']")."#text"
                        $usrJustify = (15 - $userName.count) + 4
                        $acct = $entry.SelectSingleNode("//*[@Name='OldTargetUserName']")."#text"
                        $newAcct = $entry.SelectSingleNode("//*[@Name='NewTargetUserName']")."#text"
                        $message = "$eventID - Account Name Changed From $acct To $newAcct"
                        #Create object to store event
                        $AM = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $AcctManages += $AM
                    } elseif ($eventID -eq 4906)
                    {
                        $Value = $entry.SelectSingleNode("//*[@Name='CrashOnAuditFailValue']")."#text"
                        $userName = "SYSTEM"
                        if ($Value -eq 0)
                        {
                            $message = "$eventID = Crash On Audit Fail Has Been Set To Disabled"
                            #Create object to store event
                            $SI = [PSCustomObject]@{
                            Time = $time
                            System = $sysName
                            User = $userName
                            Message = $message
                            Status = $status
                            }#end object
                            $SysIntegrity += $SI
                        } else
                        {
                            $message = "$eventID = Crash On Audit Fail Has Been Set To Enabled"
                            #Create object to store event
                            $SI = [PSCustomObject]@{
                            Time = $time
                            System = $sysName
                            User = $userName
                            Message = $message
                            Status = $status
                            }#end object
                            $SysIntegrity += $SI
                        } #end else
                    } elseif ($eventID -eq 5024) #added SP
                    { 
                        $message = "$eventID - The Windows Firewall Service Has Started Successfully"
                        $userName = "SYSTEM"
                        $usrJustify = (15 - $userName.count) + 4
                        #Create object to store event
                        $SE = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $SystemEvents += $SE
                    } elseif ($eventID -eq 5025) #added SP
                    { 
                        $message = "$eventID - The Windows Firewall Service Has Been Stopped"
                        $userName = "SYSTEM"
                        $usrJustify = (15 - $userName.count) + 4
                        #Create object to store event
                        $SE = [PSCustomObject]@{
                        Time = $time
                        System = $sysName
                        User = $userName
                        Message = $message
                        Status = $status
                        }#end object
                        $SystemEvents += $SE
                    } elseif($eventID -eq 6416) #added SP
                    {
                        $deviceType = $entry.SelectSingleNode("//*[@Name='ClassName']")."#text"
                        if ($deviceType -eq "DiskDrive" -or $deviceType -eq "CDROM") {
                            $userName = "SYSTEM"
                            $usrJustify = (15 - $userName.count) + 4
                            $deviceDescription = $entry.SelectSingleNode("//*[@Name='DeviceDescription']")."#text"
                            $message = "$eventID - A Removable Storage Device Was Recognized By The System: " + $deviceDescription
                            #Create object to store event
                            $RSC = [PSCustomObject]@{
                            Time = $time
                            System = $sysName
                            User = $userName
                            Message = $message
                            Status = $status
                            }#end object
                            $RStorageConnect += $RSC
                        }#end if
                    }#end elseif
                } #end if
            } #end if
        } #end foreach
     } #end if


    #Output Variables
    $SLogons = $SLogons | Get-Unique -AsString
    $SLogonsCnt = $SLogons.count
    $FLogons = $FLogons | Get-Unique -AsString
    $FLogonsCnt = $FLogons.count
    $Logoffs = $Logoffs | Get-Unique -AsString
    $LogoffsCnt = $Logoffs.count
    $SScrnUnlock = $SScrnUnlock | Get-Unique -AsString
    $SScrnUnlockCnt = $SScrnUnlock.count
    $FScrnUnlock = $FScrnUnlock | Get-Unique -AsString
    $FScrnUnlockCnt = $FScrnUnlock.count
    $LockedAccounts = $LockedAccounts | Get-Unique -AsString
    $LockedAccountsCnt = $LockedAccounts.count
    $SPasswdChanges = $SPasswdChanges | Get-Unique -AsString
    $SPasswdChangesCnt = $SPasswdChanges.count
    $FPasswdChanges = $FPasswdChanges | Get-Unique -AsString
    $FPasswdChangesCnt = $FPasswdChanges.count
    $AcctManages = $AcctManages | Get-Unique -AsString
    $AcctManagesCnt = $AcctManages.count
    $SysIntegrity = $SysIntegrity | Get-Unique -AsString
    $SysIntegrityCnt = $SysIntegrity.count
    $SecObjects = $SecObjects | Get-Unique -AsString
    $SecObjectsCnt = $SecObjects.count
    $PermObjects = $PermObjects | Get-Unique -AsString
    $PermObjectsCnt = $PermObjects.count
    $CommandLine = $CommandLine | Get-Unique -AsString
    $CommandLineCnt = $CommandLine.count
    $Print = $Print | Get-Unique -AsString
    $PrintCnt = $Print.count
    $PolicyChange = $PolicyChange | Get-Unique -AsString
    $PolicyChangeCnt = $PolicyChange.count
    $SystemEvents = $SystemEvents | Get-Unique -AsString
    $SystemEventsCnt = $SystemEvents.count
    $RStorageConnect = $RStorageConnect | Get-Unique -AsString
    $RStorageConnectCnt = $RStorageConnect.count
    #$RStorageAccess = $RStorageAccess | Get-Unique -AsString
    #$RStorageAccessCnt = $RStorageAccess.count

    #Excel Report
    if ($enableExcelReport -eq "enabled") {
        $blankSpace | write-host
        $blankSpace | write-host     
        $headerBreak | write-host
        "#################################################################--Generating Report--###################################################################" | write-host #$this comment is here so that this command doesn't show up in the report
        $headerBreak | write-host
        $lineBreak | write-host
        "Generating Excel Report`n`n" | write-host -ForegroundColor Green

        if ($SLogons) {
            $SLogons | Select Time, System, User, Message, Status | Export-Excel -Path $outputExcel -WorksheetName 'Logons - Success' -Title "Logons - Success (Number Of Events: $SLogonsCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'Logons - Success' -Title "Logons - Success (Number Of Events: $SLogonsCnt)" 
        } #end else

        if ($FLogons) {
            $FLogons | Select Time, System, User, Message, Status | Export-Excel -Path $outputExcel -WorksheetName 'Logons - Failed' -Title "Logons - Failed (Number Of Events: $FLogonsCnt)" -AutoSize -AutoFilter 
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'Logons - Failed' -Title "Logons - Failed (Number Of Events: $FLogonsCnt)"
        } #end else

        if ($Logoffs) { 
            $Logoffs | Select Time, System, User, Message, Status | Export-Excel -Path $outputExcel -WorksheetName 'Logoffs' -Title "Logoffs (Number Of Events: $LogoffsCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'Logoffs' -Title "Logoffs (Number Of Events: $LogoffsCnt)"
        } #end else

        if ($SScrnUnlock) {
            $SScrnUnlock | Select Time, System, User, Message, Status | Export-Excel -Path $outputExcel -WorksheetName 'Screen Unlock - Success' -Title "Screen Unlock - Success (Number Of Events: $SScrnUnlockCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'Screen Unlock - Success' -Title "Screen Unlock - Success (Number Of Events: $SScrnUnlockCnt)"
        } #end else

        if ($FScrnUnlock) {
            $FScrnUnlock | Select Time, System, User, Message, Status | Export-Excel -Path $outputExcel -WorksheetName 'Screen Unlock - Failed' -Title "Screen Unlock - Failed (Number Of Events: $FScrnUnlockCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'Screen Unlock - Failed' -Title "Screen Unlock - Failed (Number Of Events: $FScrnUnlockCnt)"
        } #end else

        if ($LockedAccounts) {
            $LockedAccounts | Select Time, System, User, Message, Status | Export-Excel -Path $outputExcel -WorksheetName 'Locked Accounts' -Title "Locked Accounts (Number Of Events: $LockedAccountsCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'Locked Accounts' -Title "Locked Accounts (Number Of Events: $LockedAccountsCnt)"
        } #end else

        if ($SPasswdChanges) {
            $SPasswdChanges | Select Time, System, User, Message, Status | Export-Excel -Path $outputExcel -WorksheetName 'Password Changes - Success' -Title "Password Changes - Success (Number Of Events: $SPasswdChangesCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'Password Changes - Success' -Title "Password Changes - Success (Number Of Events: $SPasswdChangesCnt)"
        } #end else

        if ($FPasswdChanges) {
            $FPasswdChanges | Select Time, System, User, Message, Status | Export-Excel -Path $outputExcel -WorksheetName 'Password Changes - Failed' -Title "Password Changes - Failed (Number Of Events: $FPasswdChangesCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'Password Changes - Failed' -Title "Password Changes - Failed (Number Of Events: $FPasswdChangesCnt)"
        } #end else

        if ($AcctManages) {
            $AcctManages | Select Time, System, User, Message, Status | Export-Excel -Path $outputExcel -WorksheetName 'Account Management' -Title "Account Management (Number Of Events: $AcctManagesCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'Account Management' -Title "Account Management (Number Of Events: $AcctManagesCnt)"
        } #end else

        if ($SysIntegrity) {
            $SysIntegrity | Select Time, System, User, Message, Status | Export-Excel -Path $outputExcel -WorksheetName 'System Integrity' -Title "System Integrity (Number Of Events: $SysIntegrityCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'System Integrity' -Title "System Integrity (Number Of Events: $SysIntegrityCnt)"
        } #end else

        if ($PermObjects) {
            $PermObjects | Select Time, System, User, Message, Status | Export-Excel -Path $outputExcel -WorksheetName 'Object Permission Change' -Title "Object Permission Change (Number Of Events: $PermObjectsCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'Object Permission Change' -Title "Object Permission Change (Number Of Events: $PermObjectsCnt)"
        } #end else

        if ($SecObjects) {
            $SecObjects | Select Time, System, User, Message, Access, Status | Export-Excel -Path $outputExcel -WorksheetName 'Object Access' -Title "Object Access (Number Of Events: $SecObjectsCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'Object Access' -Title "Object Access (Number Of Events: $SecObjectsCnt)"
        } #end else

        if ($CommandLine) {
            $CommandLine | Select Time, System, User, Message, Status | Export-Excel -Path $outputExcel -WorksheetName 'Command Line' -Title "Command Line (Number Of Events: $CommandLineCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'Command Line' -Title "Command Line (Number Of Events: $CommandLineCnt)"
        } #end else

        if ($Print) {
            $Print | Select Time, System, User, Message, Status | Export-Excel -Path $outputExcel -WorksheetName 'Print' -Title "Print (Number Of Events: $PrintCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'Print' -Title "Print (Number Of Events: $PrintCnt)"
        } #end else

        if ($PolicyChange) {
            $PolicyChange | Select Time, System, User, Message, Status | Export-Excel -Path $outputExcel -WorksheetName 'Policy Change' -Title "Policy Change (Number Of Events: $PolicyChangeCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'Policy Change' -Title "Policy Change (Number Of Events: $PolicyChangeCnt)"
        } #end else

        if ($SystemEvents) {
            $SystemEvents | Select Time, System, User, Message, Status | Export-Excel -Path $outputExcel -WorksheetName 'System Events' -Title "System Events (Number Of Events: $SystemEventsCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'System Events' -Title "System Events (Number Of Events: $SystemEventsCnt)"
        } #end else

        if ($RStorageConnect) {
            $RStorageConnect | Select Time, System, User, Message, Status  | Export-Excel -Path $outputExcel -WorksheetName 'Removable Storage Connections' -Title "Removable Storage Connections (Number Of Events: $RStorageConnectCnt)" -AutoSize -AutoFilter
        } #end if
        else {
            Export-Excel -Path $outputExcel -WorksheetName 'Removable Storage Connections' -Title "Removable Storage Connections (Number Of Events: $RStorageConnectCnt)"
        } #end else
    }#end if

    #Generate Text Report
    if ($enableTextReport) {
        "Generating Text Report`n`n" | write-host -ForegroundColor Green
        $blankSpace | Add-Content -Path $outputFile -PassThru | write-host
        $blankSpace | Add-Content -Path $outputFile -PassThru | write-host
        $sysBreak | Add-Content -Path $outputFile
        "***********************************************************************-Log Report-**********************************************************************" | Add-Content -Path $outputFile
        $sysBreak | Add-Content -Path $outputFile
        $lineBreak | Add-Content -Path $outputFile
        "Report Date: $dateTime" | Add-Content -Path $outputFile
        "Found $logCount Logs" | Add-Content -Path $outputFile
        $lineBreak | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "Successful Account Logons (Number Of Events: $SLogonsCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile 
        foreach ($element in $SLogons) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "Failed Account Logons (Number Of Events: $FLogonsCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $FLogons) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "Account Logoffs (Number Of Events: $LogoffsCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $Logoffs) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "Successful Screen Unlocks (Number Of Events: $SScrnUnlockCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $SScrnUnlock) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "Failed Screen Unlocks (Number Of Events: $FScrnUnlockCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $FScrnUnlock) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "Locked Accounts (Number Of Events: $LockedAccountsCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $LockedAccounts) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "Successful Password Changes (Number Of Events: $SPasswdChangesCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $SPasswdChanges) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "Failed Password Changes (Number Of Events: $FPasswdChangesCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $FPasswdChanges) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "Account Management (Number Of Events: $AcctManagesCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $AcctManages) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "System Integrity (Number Of Events: $SysIntegrityCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $SysIntegrity) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "Permission changes to Objects (Number Of Events: $PermObjectsCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $PermObjects) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "Object Access (Number Of Events: $SecObjectsCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $SecObjects) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message + " With Access Type: " + [string]$element.Access
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "Command Line Events (Number of Events: $CommandLineCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $CommandLine) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "Print Events (Number of Events: $PrintCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $Print) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "Policy Change Events (Number of Events: $PolicyChangeCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $PolicyChange) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "System Events (Number of Events: $SystemEventsCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $SystemEvents) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        "Removable Storage Connection (Number of Events: $RStorageConnectCnt)" | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        $sectionHeader | Add-Content -Path $outputFile
        $ulineBreak | Add-Content -Path $outputFile
        foreach ($element in $RStorageConnect) {
             #String message for text output
             [string]$strMSG = [string]$element.Time + "    " + ([string]$element.System).PadRight($sysJustify, " ") + ([string]$element.User).PadRight($usrJustify, " ") + ([string]$element.Status).PadRight(15, " ") + [string]$element.Message 
             $strMSG | Add-Content -Path $outputFile
        } #end foreach
        $blankSpace | Add-Content -Path $outputFile
        $blankSpace | Add-Content -Path $outputFile
        #"Removable Storage Access (Number of Events: $RStorageAccessCnt)" | Add-Content -Path $outputFile
        #$ulineBreak | Add-Content -Path $outputFile
        #$sectionHeader | Add-Content -Path $outputFile
        #$ulineBreak | Add-Content -Path $outputFile
        #$RStorageAccess | Add-Content -Path $outputFile
        #$blankSpace | Add-Content -Path $outputFile
        #$blankSpace | Add-Content -Path $outputFile
        "####################################################################--UNCLASSIFIED--#####################################################################" | Add-Content -Path $outputFile
    }#end if
    Clean-Up   
} #end Parse-Logs function

Function Clean-Up
{
    $logDirs = get-childitem "$LogsArchive\*" | where {$_.PSIsContainer} 
    $logFiles = get-childitem "$LogsArchive\*.evt*"
    $lineBreak
    "+ Performing Cleanup" | write-host -ForegroundColor Green #$This comment enables this line to be filtered out from the powershell command events

    foreach ($logFile in $logFiles)
    {
        $shortName = $logFile.name | %{$_.split('.')[1]}
        $logName = $logFile.name
        foreach ($logDir in $logDirs)
        {
            if ($logDir.name -eq $shortName)
            {
                #Start-BitsTransfer -Source $logFile -Destination "$logDir" -Description "Copying $logFile to $logDir"
                copy-item -path $logFile -destination $logDir -force
                $origlogHash = Hash("$LogsArchive\$logName")
                $copylogHash = Hash("$logDir\$logName")
                $testCopy = test-path "$logDir\$logName"
                start-sleep 1 #$sleep so that the parse function does not lock the audit files
                if ($testCopy -eq "True" -and $copylogHash -eq $origlogHash)
                {
                    remove-item $logFile -force
                } #end if
            }#end if
        } #end foreach
    } #end foreach

    $logFiles = $null
    $logFiles = get-childitem "$LogsArchive\*.evt*"
    if ($logFiles -ne $null)
    {
        "- There are rogue files left over after the Clean-Up function ran. Initializing the Post-Clean function to handle`n  the rogue files." | write-host -ForegroundColor Yellow #$This comment enables this line to be filtered out from the powershell command events
        $lineBreak | Add-Content -Path $outputFile -PassThru | write-host
        Post-Clean
    } else
    {
        $lineBreak | Add-Content -Path $outputFile -PassThru | write-host
    } #end else         
} #end Clean-Up function


Function Post-Clean
{
    $logDirs = get-childitem "$LogsArchive\*" | where {$_.PSIsContainer} 
    $logFiles = get-childitem "$LogsArchive\*.evt*"
 
    "+ Performing Post Cleanup for Rogue Files" | write-host -ForegroundColor Green #$This comment enables this line to be filtered out from the powershell command events

    foreach ($logFile in $logFiles)
    {
        $shortName = $logFile.name | %{$_.split('.')[1]}
        $logName = $logFile.name
        foreach ($logDir in $logDirs)
        {
            if ($logDir.name -eq $shortName)
            {
                $testCopy = test-path "$logDir\$logName"
                $origlogHash = Hash("$LogsArchive\$logName")
                $copylogHash = Hash("$logDir\$logName")
                if ($testCopy -eq "True" -and $copylogHash -eq $origlogHash)
                {
                    start-sleep 1 #$sleep so that the parse function does not lock the audit files
                    remove-item $logFile -force
                    start-sleep 1 #$sleep so that the parse function does not lock the audit files
                } else
                {
                    #Start-BitsTransfer -Source $logFile -Destination "$logDir" -Description "Copying $logFile to $logDir"
                    copy-item -path $logFile -destination $logDir -force
                    start-sleep 1 #$sleep so that the parse function does not lock the audit files
                    $testCopy = test-path "$logDir\$logName"
                    $origlogHash = Hash("$LogsArchive\$logName")
                    $copylogHash = Hash("$logDir\$logName")
                    if ($testCopy -eq "True" -and $copylogHash -eq $origlogHash)
                    {
                        remove-item $logFile -force
                        start-sleep 1 #$sleep so that the parse function does not lock the audit files
                    } #end if
                } #end else
            } #end if
        } #end foreach
    } #end foreach
    $logFiles = $null
    $logFiles = get-childitem "$LogsArchive\*.evt*"
    if ($logFiles -eq $null)
    {
        "+ Handled the rogue files successfully" | write-host -ForegroundColor Green #$This comment enables this line to be filtered out from the powershell command events
        $lineBreak | write-host
    } else
    {
        "- Clean-up and Post-Clean functions failed to clean up all the audit files. Please clean manually." | write-host -ForegroundColor Red #$This comment enables this line to be filtered out from the powershell command events
        $lineBreak | write-host
    } #end else  
} #end Post-Clean Function


Function ReportOpener {

[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null
[reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null

$form1 = New-Object System.Windows.Forms.Form
$button1 = New-Object System.Windows.Forms.Button
$button2 = New-Object System.Windows.Forms.Button
$listBox1 = New-Object System.Windows.Forms.ListBox
$checkBox3 = New-Object System.Windows.Forms.CheckBox
$checkBox2 = New-Object System.Windows.Forms.CheckBox
$checkBox1 = New-Object System.Windows.Forms.CheckBox
$InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState


$b1= $false
$b2= $false
$b3= $false

#----------------------------------------------
#Generated Event Script Blocks
#----------------------------------------------

$handler_button1_Click= 
{
    $listBox1.Items.Clear();    

    if ($checkBox1.Checked) {
        $listBox1.Items.Add( "Opening Text Report....")
        notepad.exe $outputFile
        Start-Sleep 2
        $listBox1.Items.Clear() 
    }

    if ($checkBox2.Checked) {
        $listBox1.Items.Add( "Opening Excel Report...."  )
        $objExcel = New-Object -ComObject Excel.Application
        $objExcel.Visible = $true
        $objExcel.Workbooks.Open($outputExcel)
        Start-Sleep 2
        $listBox1.Items.Clear()
    }

}

$handler_button2_Click= 
{
    $listBox1.Items.Add( "Exiting...."  )
    Start-Sleep 2
    $form1.Close()
}

$OnLoadForm_StateCorrection=
{#Correct the initial state of the form to prevent the .Net maximized form issue
    $form1.WindowState = $InitialFormWindowState
}

#----------------------------------------------
#region Generated Form Code
$form1.Text = "WLCAP - Reports"
$form1.Name = "WLCAP - Reports"
$form1.DataBindings.DefaultDataSourceUpdateMode = 0
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 450
$System_Drawing_Size.Height = 236
$form1.ClientSize = $System_Drawing_Size

$button1.TabIndex = 4
$button1.Name = "button1"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 75
$System_Drawing_Size.Height = 23
$button1.Size = $System_Drawing_Size
$button1.UseVisualStyleBackColor = $True

$button1.Text = "Open"

$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 27
$System_Drawing_Point.Y = 156
$button1.Location = $System_Drawing_Point
$button1.DataBindings.DefaultDataSourceUpdateMode = 0
$button1.add_Click($handler_button1_Click)

$form1.Controls.Add($button1)

$button2.TabIndex = 4
$button2.Name = "button2"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 75
$System_Drawing_Size.Height = 23
$button2.Size = $System_Drawing_Size
$button2.UseVisualStyleBackColor = $True

$button2.Text = "Exit"

$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 27
$System_Drawing_Point.Y = 200
$button2.Location = $System_Drawing_Point
$button2.DataBindings.DefaultDataSourceUpdateMode = 0
$button2.add_Click($handler_button2_Click)

$form1.Controls.Add($button2)


$listBox1.FormattingEnabled = $True
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 301
$System_Drawing_Size.Height = 212
$listBox1.Size = $System_Drawing_Size
$listBox1.DataBindings.DefaultDataSourceUpdateMode = 0
$listBox1.Name = "listBox1"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 137
$System_Drawing_Point.Y = 13
$listBox1.Location = $System_Drawing_Point
$listBox1.TabIndex = 3

$form1.Controls.Add($listBox1)


$checkBox2.UseVisualStyleBackColor = $True
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 104
$System_Drawing_Size.Height = 24
$checkBox2.Size = $System_Drawing_Size
$checkBox2.TabIndex = 1
$checkBox2.Text = "Excel Report"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 27
$System_Drawing_Point.Y = 44
$checkBox2.Location = $System_Drawing_Point
$checkBox2.DataBindings.DefaultDataSourceUpdateMode = 0
$checkBox2.Name = "checkBox2"

$form1.Controls.Add($checkBox2)



$checkBox1.UseVisualStyleBackColor = $True
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 104
$System_Drawing_Size.Height = 24
$checkBox1.Size = $System_Drawing_Size
$checkBox1.TabIndex = 0
$checkBox1.Text = "Text Report"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 27
$System_Drawing_Point.Y = 13
$checkBox1.Location = $System_Drawing_Point
$checkBox1.DataBindings.DefaultDataSourceUpdateMode = 0
$checkBox1.Name = "checkBox1"

$form1.Controls.Add($checkBox1)


#Save the initial state of the form
$InitialFormWindowState = $form1.WindowState
#Init the OnLoad event to correct the initial state of the form
$form1.add_Load($OnLoadForm_StateCorrection)
#Show the Form
$form1.ShowDialog()| Out-Null

} #End Function


# Script Main
#Put script in Scheduled Task
if ($schTask.IsPresent) {
    $blankSpace | write-host
    $blankSpace | write-host     
    $headerBreak | write-host
    "##############################################################--Creating Scheduled Task--################################################################" | write-host #$this comment is here so that this command doesn't show up in the report
    $headerBreak | write-host
    $lineBreak | write-host
    schtasks.exe /RU SYSTEM /RL HIGHEST /CREATE /SC WEEKLY /d SUN /MO 1 /TN "WLCAP" /TR "`'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`' $schTaskScriptPath" /ST 23:00
    
    if ((Get-ScheduledTask -TaskName WLCAP).TaskName) {
        "Scheduled Task added successfully. Make sure to test the scheduled task to make sure it works properly" | write-host -ForegroundColor Green
    }#end if
    else {
        "Scheduled Task was not added. Check Task Scheduler and add the task manually." | write-host -ForegroundColor Red
    }#end else

    if ($UI) {
    "`n`nPress any key to exit." | write-host -ForegroundColor Green #$This comment enables this line to be filtered out from the powershell command events
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
    } #end if
}#end if 


if ($parseOnly.IsPresent)
{
    Parse-Logs
} elseif ($collectOnly.IsPresent)
{
    #Check for ComputerName script parameter. The script parameter takes presedence over the host file and domain query.
    if ($computerName)
    {
        $Computers = $computerName
        Write-ReportHeader
        Test-ComputerConnection
        Clean-Up
    } else
    {
        #Check for HostFile
        if ($hostFile -ne $null -and $enableHostFile -eq "enabled" -or $hostFile -ne "" -and $enableHostFile -eq "enabled")
        {
            $Computers = get-content $hostFile | Where-Object {$_.Trim() -match '[A-Za-z*0-9*]'}
            Write-ReportHeader #$This comment enables this line to be filtered out from the powershell command events
            if ($domainMem -eq $True -and $enableHostDiff -eq "enabled")
            {
                $DomainComputers = Get-ADComputers
                $CompareResults = Compare-Object $Computers $DomainComputers
                foreach ($Result in $CompareResults)
                {
                    if ($Result.SideIndicator -eq "=>")
                    {
                        "- " + $Result.InputObject + " Was found in Active Directory and is not in the Host List!`nThe System will not be processed until it is added to the Host List.`n" | Add-Content -Path $outputFile -PassThru | write-host -ForegroundColor Yellow
                    } elseif ($Result.SideIndicator -eq "<=")
                    {
                        "- " + $Result.InputObject + " Was found in the Host List and not in Active Directory!`nIf it is skipped below because of inaccessibility, remove it from the Host List`n" | Add-Content -Path $outputFile -PassThru | write-host -ForegroundColor Yellow
                    } #end if
                } #end foreach
            }
            Test-ComputerConnection
            Clean-Up
        } else
        {
            #Check to see local system is on the domain
            if ($domainMem -eq $False)
            {
                $Computers = $localHost
                Write-ReportHeader
                Test-ComputerConnection
                Clean-Up
            } elseif ($Computers -eq $null)
            {
                $Computers = Get-ADComputers
                Write-ReportHeader
                Test-ComputerConnection
                Clean-Up
            } #end elseif
        } #end else
    } #end else
} else
{
    #Check for ComputerName script parameter. The script parameter takes presedence over the host file and domain query.
    if ($computerName)
    {
        $Computers = $computerName
        Write-ReportHeader
        Test-ComputerConnection
        Parse-Logs
    } elseif ($hostFile -ne $null -and $enableHostFile -eq "enabled" -or $hostFile -ne "" -and $enableHostFile -eq "enabled") #Check for HostFile
    {
        $Computers = get-content $hostFile | Where-Object {$_.Trim() -match '[A-Za-z*0-9*]'}
        Write-ReportHeader
        if ($domainMem -eq $True -and $enableHostDiff -eq "enabled")
        {
            $DomainComputers = Get-ADComputers
            $CompareResults = Compare-Object $Computers $DomainComputers
            foreach ($Result in $CompareResults)
            {
                if ($Result.SideIndicator -eq "=>")
                {
                    "- " + $Result.InputObject + " Was found in Active Directory and is not in the Host List!`nThe System will not be processed until it is added to the Host List.`n" | Add-Content -Path $outputFile -PassThru | write-host -ForegroundColor Yellow
                } elseif ($Result.SideIndicator -eq "<=")
                {
                    "- " + $Result.InputObject + " Was found in the Host List and not in Active Directory!`nIf it is skipped below because of inaccessibility, remove it from the Host List`n" | Add-Content -Path $outputFile -PassThru | write-host -ForegroundColor Yellow
                } #end elseif
            } #end for
            Test-ComputerConnection
            Parse-Logs
        } else
        {
            Test-ComputerConnection
            Parse-Logs
        } #end else
    } elseif ($domainMem -eq $False) #Check to see local system is on the domain
    {
        $Computers = $localHost
        Write-ReportHeader
        Test-ComputerConnection
        Parse-Logs
    } elseif ($Computers -eq $null)
    {
        $Computers = Get-ADComputers
        Write-ReportHeader
        Test-ComputerConnection
        Parse-Logs
    } #end elseif
} #end else


if ($UI) {
    #Minimize all windows
    $shell = New-Object -ComObject "Shell.Application"
    $shell.minimizeall() 
    #Open report popup
    ReportOpener
    "The Script Has Completed Successfully.`n`nPress any key to exit." | write-host -ForegroundColor Green #$This comment enables this line to be filtered out from the powershell command events
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
} #end if
