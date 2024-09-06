#########################################--README - Windows Log Collector And Parser--############################################

The Purpose of WLCAP is to automate the collection and parsing of audit logs on Windows7/Server 2008 and newer Operating Systems. 
By default, WLCAP will determine if the system is on a domain or not. If it is on a domain, it queries the Domain for a list of 
systems and runs against the systems found. WLCAP first collects the logs from each system and then parses the logs. If unable to 
reach a system, WLCAP will report the failure to the screen in yellow and write it to the report. If no domain is found, WLCAP 
will run against the local system. WLCAP is also capable of reading a list of hosts if defined. In each case if WLCAP is unable 
to save, clear, or backup the logs, it will report the failure to the screen in red and write it to the report. 

© Copyright 2024 Northrop Grumman Systems Corporation. Licensed under the MIT License, a copy of which is available at https://opensource.org/license/mit 

#######################
Configuring WLCAP:
#######################


NOTES: 
For domain systems, the system that the script is ran from should be able to ping the target systems and access the default admin share (C$) of all target systems in order for the script to run successfully. Ensure the following is configured on all systems. 
 
	-Configure the following predefined Windows Firewall rules (Inbound) in your default domain policy or custom policy that is applied to all domain systems.: 
		Remote event log management (RPC) 
		Remote event monitor (RPC) 
		Remote service management (RPC) 
		ICMPv4 (ping)
		ICMPv6 (if applicable)
		File and Print share 

	-RPC service is running 
	-The config file must be located in the same directory as the script. 
	-The ImportExcel zip and folder (after the script extracts it) must be located in the same directory as the script. 
	-Windows disables powershell script execution by default. For WLCAP to work, script execution must be turned on. Do this by opening a powershell window as Admin and enter the following: 
		set-executionpolicy -force unrestricted


WLCAP has a config file named "WLCAP.cfg". Use this file to configure the storage location of the logs and more. See available options below.

[Script Config]

ERROR_ACTION_PREFERENCE
	This setting is for debugging purposes. Set it to no value (i.e. "ERROR_ACTION_PREFERENCE=") to see powershell errors. 
        This setting will be set to "ERROR_ACTION_PREFERENCE=SilentlyContinue" as a default. This surpresses powershell errors.



ENABLE_BACKUP_ARCHIVE
	This setting enables/disables the ability to designate an additional server/path to store a backup copy of the event 
	logs. This is not needed if the	server/path designated in LOG_ARCHIVE is backed up (i.e. backed up to tape). Set this to 
	enabled to create a backup of the event logs in another locaton (Must put a valid path in BACKUP_ARCHIVE in the 
	[Folder Locations] section below). This setting will be set to "ENABLE_BACKUP_ARCHIVE=disabled" as a default.



ENABLE_HOST_FILE
	This setting enables/disables the ability to define a list of systems in a text file to run against (Must put a vailid file 
	path in the HOST_FILE setting in the [Folder Locations] section below i.e. "HOST_FILE=C:\temp\computers.txt"). This setting
	will be set to "ENABLE_HOST_FILE=disabled" as a default.



ENABLE_HOST_DIFF
	This setting enables/disables the ability to check the accuracy of the host file against a domain computer query and 
	vice-versa (Default is disabled). Must be in a domain environment for this to work. Systems found in the domain query that 
 	are not in the host file will be written to the report to show the addition of system(s) to the domain. Add the new system(s) 
	to the host file to make the message(s) go away. If systems are found in the host file and not in the domain query, then it 
	will be written to the report to show the need to cleanup the host file.
	NOTE: ENABLE_HOST_FILE and HOST_FILE must be defined.


 
ENABLE_TEXT_REPORT
	This setting enables/disables the ability to generate a text report (.txt file). This is enabled by default. Enabling only
	one output option (either ENABLE_TEXT_REPORT or ENABLE_EXCEL_REPORT) will speed up the amount of time the script takes to run. 



ENABLE_EXCEL_REPORT
	This setting enables/disables the ability to generate a Microsoft Excel report (.txt file). This requires PowerSHell 5.1 or 
	higher. This is enabled by default. Enabling only one output option (either ENABLE_TEXT_REPORT or ENABLE_EXCEL_REPORT) 
	will speed up the amount of time the script takes to run.



[Folder/File Names]

LOG_FOLDER
	This setting defines the name of the local folder where event logs are temporarily stored until moved to the server 
	(LOG_ARCHIVE). This folder is used on each system for which the event logs are collected. A folder name is required to be 
	defined. If the folder does not exist, it will be created. Please ensure that this folder is locked down to Administrators 
	only and has auditing set since it will potentially have event log files in it. The setting will be set to 
 	"LOG_FOLDER=Audit_Logs".



OUTPUT_FILE=weekly-output.txt
	This setting defines the name of the report file that is generated by WLCAP. It can be named to anything. By default, a 
	date and time will proceed this name and cannot be changed. This setting will be set to "OUTPUT_FILE=weekly-output.txt"
	as a default.



[Folder Locations]

LOG_ARCHIVE
	This setting defines the central location for the logs to be stored. This can be a local path or a network path. This 
	setting will be set to "LOG_ARCHIVE=C:\Audit_Logs" as a default.



BACKUP_ARCHIVE
	This setting defines the backup location for the logs to be stored (Must set ENABLE_BACKUP_ARCHIVE to enbabled 
	"ENABLE_BACKUP_ARCHIVE=enabled"). This is not needed if the server/path designated in LOG_ARCHIVE is backed up 
	(i.e. backed up to tape). Set this to a valid path to create a backup of the event logs in another locaton. This setting will 
	be set to "BACKUP_ARCHIVE=" (blank) as a default.


 
OUTPUT_FOLDER
	This setting defines the report folder location where the reports are stored. It can be named to anything. The setting will 
	be set to "OUTPUT_FOLDER=C:\Audit_Logs\Audit_Output" as a default.



HOST_FILE
	This setting defines the path to a file with a list of systems to run against (Must set ENABLE_HOST_FILE to enabled
	"ENABLE_HOST_FILE=enabled"). By default, this will be set "to HOST_FILE=" (blank) and WLCAP will run locally or domain wide
	(depending if a domain was found).


###################
Running WLCAP:
###################
To run WLCAP, either right-click on WLCAPx.x.ps1 (where x.x is the version number) and click "Run with PowerShell" or open a 
powershell console, cd to the directory that contains WLCAP and type ".\WLCAPx.x.ps1" (Note: WLCAP will have to be invoked from an 
existing powershell console in order to specify the parameters).
        
Parameters:
	-ComputerName
		This parameter allows WLCAP to run on a specified system. Syntax is: ".\WLCAPx.x.ps1 -ComputerName SystemX" (where x.x
		is the version number and SystemX is the computername)
	
	-ParseOnly
		This parameter allows WLCAP to parse logs found in the LOG_ARCHIVE folder. This is usefull if logs had to be manually
		collected. Just place the logs in the LOG_ARCHIVE folder and run WLCAP with the -ParseOnly parameter to parse the logs.
		Syntax is: ".\WLCAPx.x.ps1 -ParseOnly" (where x.x is the version number)
       
    -CollectOnly
       	This parameter allows the collection of logs without parsing. This can be usefully if parsing does not need to be done or will be done at a later time. Syntax is: ".\WLCAPx.x.ps1 -CollectOnly" (where x.x is the version number)
    
	-schTask 
        This parameter creates a scheduled task to run WLCAP. This defaults to using the system account which works fine for standalone systems (SUSA, MUSA), however, must be changed if running across a domain. To do this, go into Task Manager and find the WLCAP task, open it and change the user from SYSTEM to a domain account with admin rights. Syntax is: .\WLCAPx.x.ps1 -schTask (where x.x is the version number) 



###################
EVENT IDS CAPTURED
###################

Microsoft-Windows-PrintService:
---------------------------------------------------------------------
307 - A document was printed (Added in 2.2)


PowerShell:
---------------------------------------------------------------------
800 - Pipeline execution details (Powershell Commands) (Added in 2.2) 


Security:
---------------------------------------------------------------------
1100 - The event logging service has shut down 
1102 - The audit log was cleared 
4608 - Windows is starting up 
4616 - The system time was changed 
4624 - An account was successfully logged on 
4625 - An account failed to log on 
4634 - An account was logged off 
4648 - Logon using explicit credentials (Added in 2.2) 
4656 - A handle to an object was requested 
4670 - Permissions on an object were changed (Added in 2.2) 
4688 - A new process has been created (Command Line Only) (Added in 2.2) 
4706 - A trust to a domain was created (Added in 2.2) 
4707 - A trust to a domain was removed (Added in 2.2) 
4713 - Kerberos policy was changed (Added in 2.2) 
4719 - System audit policy was changed 
4720 - A user account was created 
4722 - A user account was enabled 
4723 - An attempt was made to change an account's password 
4724 - An attempt was made to reset an accounts password 
4725 - A user account was disabled 
4726 - A user account was deleted 
4727 - A security-enabled global group was created (Added in 2.2) 
4728 - A member was added to a security-enabled global group 
4730 - A security-enabled global group was deleted (Added in 2.2) 
4731 - A security-enabled local group was created (Added in 2.2) 
4732 - A member was added to a security-enabled local group 
4733 - A member was removed from a security-enabled local group (Added in 2.2) 
4734 - A security-enabled local group was deleted (Added in 2.2) 
4739 - Domain Policy was changed 
4740 - A user account was locked out 
4744 - A security-disabled local group was created (Added in 2.2) 
4748 - A security-disabled local group was deleted (Added in 2.2) 
4749 - A security-disabled global group was created (Added in 2.2) 
4753 - A security-disabled global group was deleted (Added in 2.2) 
4754 - A security-enabled universal group was created (Added in 2.2)
4756 - A member was added to a security-enabled universal group (Added in 2.3)
4758 - A security-enabled universal group was deleted (Added in 2.2) 
4759 - A security-disabled universal group was created (Added in 2.2) 
4763 - A security-disabled universal group was deleted (Added in 2.2) 
4767 - A user account was unlocked 
4781 - The name of an account was changed 
4906 - The CrashOnAuditFail value has changed 
5024 - The Windows Firewall Service has started successfully (Added in 2.2) 
5025 - The Windows Firewall Service has been stopped (Added in 2.2) 
6416 - A new removable media device was recognized by the system (Added in 2.2) 


System:
-------------------
1074 - USER32 System Shutdown


###################
CHANGELOG
###################
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

###################
Contact Info:
###################
Use the contact info below if there are any questions, comments, or recommendations:

Author:  Ryan Clark

