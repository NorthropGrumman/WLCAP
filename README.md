# Windows Log Collector And Parser

The Purpose of WLCAP is to automate the collection and parsing of audit logs on Windows7/Server 2008 and newer Operating Systems. 
By default, WLCAP will determine if the system is on a domain or not. If it is on a domain, it queries the Domain for a list of 
systems and runs against the systems found. WLCAP first collects the logs from each system and then parses the logs. If unable to 
reach a system, WLCAP will report the failure to the screen in yellow and write it to the report. If no domain is found, WLCAP 
will run against the local system. WLCAP is also capable of reading a list of hosts if defined. In each case if WLCAP is unable 
to save, clear, or backup the logs, it will report the failure to the screen in red and write it to the report. 

© Copyright 2024 Northrop Grumman Systems Corporation. Licensed under the MIT License, a copy of which is available at https://opensource.org/license/mit 

## Configuring WLCAP:

NOTES: 
For domain systems, the system that the script is ran from should be able to ping the target systems and access the default admin share (C$) of all target systems in order for the script to run successfully. Ensure the following is configured on all systems. 
 
- Configure the following predefined Windows Firewall rules (Inbound) in your default domain policy or custom policy that is applied to all domain systems:

		Remote event log management (RPC) 
		Remote event monitor (RPC) 
		Remote service management (RPC) 
		ICMPv4 (ping)
		ICMPv6 (if applicable)
		File and Print share 

- RPC service is running 
- The config file must be located in the same directory as the script. 
- The ImportExcel zip and folder (after the script extracts it) must be located in the same directory as the script. 
- Windows disables powershell script execution by default. For WLCAP to work, script execution must be turned on. Do this by opening a powershell window as Admin and enter the following: 

		set-executionpolicy -force unrestricted


- WLCAP has a config file named "WLCAP.cfg". Use this file to configure the storage location of the logs and more. See available options below.

## Script Configuration
The following settings are found in WLCAP.cfg under the `[Script Config]` section.

`ERROR_ACTION_PREFERENCE`

	This setting is for debugging purposes. Set it to no value (i.e. "ERROR_ACTION_PREFERENCE=") to see powershell errors. This setting will be set to "ERROR_ACTION_PREFERENCE=SilentlyContinue" as a default. This surpresses powershell errors.

`ENABLE_BACKUP_ARCHIVE`

	This setting enables/disables the ability to designate an additional server/path to store a backup copy of the event 
	logs. This is not needed if the	server/path designated in LOG_ARCHIVE is backed up (i.e. backed up to tape). Set this to 
	enabled to create a backup of the event logs in another locaton (Must put a valid path in BACKUP_ARCHIVE in the 
	[Folder Locations] section below). This setting will be set to "ENABLE_BACKUP_ARCHIVE=disabled" as a default.

`ENABLE_HOST_FILE`

	This setting enables/disables the ability to define a list of systems in a text file to run against (Must put a vailid file 
	path in the HOST_FILE setting in the [Folder Locations] section below i.e. "HOST_FILE=C:\temp\computers.txt"). This setting
	will be set to "ENABLE_HOST_FILE=disabled" as a default.

`ENABLE_HOST_DIFF`

	This setting enables/disables the ability to check the accuracy of the host file against a domain computer query and 
	vice-versa (Default is disabled). Must be in a domain environment for this to work. Systems found in the domain query that 
 	are not in the host file will be written to the report to show the addition of system(s) to the domain. Add the new system(s) 
	to the host file to make the message(s) go away. If systems are found in the host file and not in the domain query, then it 
	will be written to the report to show the need to cleanup the host file.
	NOTE: ENABLE_HOST_FILE and HOST_FILE must be defined.

`ENABLE_TEXT_REPORT`

	This setting enables/disables the ability to generate a text report (.txt file). This is enabled by default. Enabling only
	one output option (either ENABLE_TEXT_REPORT or ENABLE_EXCEL_REPORT) will speed up the amount of time the script takes to run. 

`ENABLE_EXCEL_REPORT`

	This setting enables/disables the ability to generate a Microsoft Excel report (.txt file). This requires PowerSHell 5.1 or 
	higher. This is enabled by default. Enabling only one output option (either ENABLE_TEXT_REPORT or ENABLE_EXCEL_REPORT) 
	will speed up the amount of time the script takes to run.

## Folder/File Names
The following settings are found in WLCAP.cfg under the `[Folder/File Names]` section.

`LOG_FOLDER`

	This setting defines the name of the local folder where event logs are temporarily stored until moved to the server 
	(LOG_ARCHIVE). This folder is used on each system for which the event logs are collected. A folder name is required to be 
	defined. If the folder does not exist, it will be created. Please ensure that this folder is locked down to Administrators 
	only and has auditing set since it will potentially have event log files in it. The setting will be set to 
 	"LOG_FOLDER=Audit_Logs".



`OUTPUT_FILE=weekly-output.txt`

	This setting defines the name of the report file that is generated by WLCAP. It can be named to anything. By default, a 
	date and time will proceed this name and cannot be changed. This setting will be set to "OUTPUT_FILE=weekly-output.txt"
	as a default.


## Folder Locations
The following settings are found in WLCAP.cfg under the `[Folder Locations]` section.

`LOG_ARCHIVE`

	This setting defines the central location for the logs to be stored. This can be a local path or a network path. This 
	setting will be set to "LOG_ARCHIVE=C:\Audit_Logs" as a default.



`BACKUP_ARCHIVE`

	This setting defines the backup location for the logs to be stored (Must set ENABLE_BACKUP_ARCHIVE to enbabled 
	"ENABLE_BACKUP_ARCHIVE=enabled"). This is not needed if the server/path designated in LOG_ARCHIVE is backed up 
	(i.e. backed up to tape). Set this to a valid path to create a backup of the event logs in another locaton. This setting will 
	be set to "BACKUP_ARCHIVE=" (blank) as a default.


 
`OUTPUT_FOLDER`

	This setting defines the report folder location where the reports are stored. It can be named to anything. The setting will 
	be set to "OUTPUT_FOLDER=C:\Audit_Logs\Audit_Output" as a default.



`HOST_FILE`

	This setting defines the path to a file with a list of systems to run against (Must set ENABLE_HOST_FILE to enabled
	"ENABLE_HOST_FILE=enabled"). By default, this will be set "to HOST_FILE=" (blank) and WLCAP will run locally or domain wide
	(depending if a domain was found).

## Running WLCAP:

To run WLCAP, either right-click on WLCAPx.x.ps1 (where x.x is the version number) and click "Run with PowerShell" or open a 
powershell console, cd to the directory that contains WLCAP and type ".\WLCAPx.x.ps1" (Note: WLCAP will have to be invoked from an 
existing powershell console in order to specify the parameters).
        
### Parameters:
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



## EVENT IDS CAPTURED

- Microsoft-Windows-PrintService

  307 - A document was printed (Added in 2.2)

- PowerShell

  800 - Pipeline execution details (Powershell Commands) (Added in 2.2) 

- Security

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

- System

  1074 - USER32 System Shutdown

## Contact Info:

Use the contact info below if there are any questions, comments, or recommendations:

Author:  Ryan Clark

E-Mail: william.clark@ngc.com

Feel free to create an issue or pull request for issues or enhancements. Contributing guidance will be coming soon. 

© Copyright 2024 Northrop Grumman Systems Corporation. Licensed under the MIT License, a copy of which is available at https://opensource.org/license/mit 

