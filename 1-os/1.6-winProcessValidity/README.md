# What is Process Validity and Why it Matters

## What is Process Validity?

   - Being able to distinguish a Process as a known good from a possible bad from its attributes and characteristics.

   - Today’s Malware typically use their stealth and obfuscation abilities in order to hide in various artifacts such as:

       - processes

       - files

       - registry keys

       - drivers

       - etc.

   - They try to leave as little evidence of their presence as possible by mimicking or by hooking onto legitimate processes or services.

## Why is Process Validity Important?

   - OCO - Offensive Operations

       - We need to protect our toolset (malware we’ve created).

       - Find any other types of malware on the box that could compromise our tools.

   - DCO - Defensive Operations

       - Find malware and defend our networks

       - Make sure we are not compromised or have sensitive information stolen from us.

           - Could be the difference between life and death for soldiers on mission.

# Processes, DLLs, and Services

## What are they?

   - What is a process?

       - A program running on your computer, whether executed by the user or running in the background.

       - Examples include:

           - Background tasks like spell checker

           - Executables like Google Chrome and Notepad

   - What is a DLL?

       - Dynamic Link Library

           - A non-standalone program that can be run by (linked to) multiple programs at the same time.

           - Cannot be directly executed. Dependent on an exe to use as an entry point, such as RUNDLL.EXE (a process that calls on the functionality of the DLL)

           - Allows developers to make minor changes without affecting other parts of the program.

       - Some Examples Include:

           - Comdlg32 - Performs common dialog box related functions.

           - Device drivers

           - ActiveX Controls

       - If you want to dig deeper: [Ask Microsoft](https://docs.microsoft.com/en-us/troubleshoot/windows-client/deployment/dynamic-link-library)

   - What is a Service?

       - Long-running executables that run in their own Windows sessions (i.e. in the background)

           - Can be set to auto start when the computer boots or a user logs on.

           - Can be paused and restarted.

           - Do not interact with/show any user interface.

       - If you want to dig deeper: [Ask Microsoft](https://docs.microsoft.com/en-us/dotnet/framework/windows-services/introduction-to-windows-service-applications)

## How to view Processes and DLLs

   - Q: Which Windows commands let us view processes?

       - **PowerShell**: `Get-Process` - [Microsoft Reference](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-7.1)

       - **CMD**: `tasklist`

### View Processes In PowerShell

   - View all Processes, not sorted.

       - `Get-Process`
```
PS C:\Users\student> Get-Process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    278      18     9420      18984       3.61   6304   1 ApplicationFrameHost
    342      19     4516       3988              4624   0 armsvc
    958      57   127900     202620      51.38    632   1 atom
    572      82   182356     266836     117.64   3148   1 atom
    321      33    92760     164644       0.56   7864   1 atom
    222      15     6884      28916       0.03   8024   1 atom
    733      27   143268     172480      38.33  13980   1 atom
     68       5     2040       4128       0.02   7504   1 cmd
```

   - View all Processes, sort them by PID.

       - `Get-Process | Sort -Property Id | more`
```
PS C:\Users\student> Get-Process | Sort -Property Id | more

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
      0       0       60          8                 0   0 Idle
   4240       0      192         96                 4   0 System
      0       0      184      22332                72   0 Secure System
      0      17     6552      28656               132   0 Registry
    168      11     1432       3484               452   0 wininit
     53       3     1056        940               504   0 smss

-- More --
```

   - View all processes, but sort by PID and only show the properties I define.

       - `Get-Process | Select Name, Id, Description | Sort -Property Id | more`
```
PS C:\Users\student> Get-Process | Select Name, Id, Description | Sort -Property Id | more

Name                       Id Description
----                       -- -----------
Idle                        0
System                      4
Secure System              72
Registry                  132
wininit                   452
smss                      504
LsaIso                    572
csrss                     576
svchost                   624
atom                      632 Atom
svchost                   852
rundll32                 1616 Windows host process (Rundll32)
CompPkgSrv               1788 Component Package Support Server
Slack                    1816 Slack

-- More --
```

   - View only the processes I define and sort by PID

     - `Get-Process SMSS,CSRSS,LSASS | Sort -Property Id`
```
PS C:\Users\student> Get-Process SMSS,CSRSS,LSASS | Sort -Property Id

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
     53       3     1056        940               504   0 smss
    717      33     3684       3688               576   1 csrss
    784      24     1928       2788               876   0 csrss
   1612      39    10352      18076              1028   0 lsass
```

   - View modules/DLLs used by defined process and their file locations.

       - `Get-Process chrome | foreach {$_.modules} | more`

       - `Get-Process -Name "*chrome*" | Select-Object -ExpandProperty Modules | more`

```
PS C:\Users\student> Get-Process chrome | foreach {$_.modules} | more

   Size(K) ModuleName                                         FileName
   ------- ----------                                         --------
      2244 chrome.exe                                         C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
      2008 ntdll.dll                                          C:\WINDOWS\SYSTEM32\ntdll.dll
       756 KERNEL32.DLL                                       C:\WINDOWS\System32\KERNEL32.DLL
      2852 KERNELBASE.dll                                     C:\WINDOWS\System32\KERNELBASE.dll
      1016 chrome_elf.dll                                     C:\Program Files (x86)\Google\Chrome\Application\88.0.4324...
        40 VERSION.dll                                        C:\WINDOWS\SYSTEM32\VERSION.dll

-- More --
```

   - View only modules/DLLs used by Chrome with "chrome" in the name and their file locations.

       - `Get-Process chrome | foreach {$_.modules} | Where-Object ModuleName -like '*chrome*' | more`

       - `Get-Process -Name "*chrome*" | Select-Object -ExpandProperty Modules | Where-Object ModuleName -like '*chrome*' | more`

           - Pipe in a `ft -wrap` to see full file name/path.
```
PS C:\Users\student> Get-Process chrome | foreach {$_.modules} | Where-Object ModuleName -like '\*chrome*' | more

   Size(K) ModuleName                                         FileName
   ------- ----------                                         --------
      2244 chrome.exe                                         C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
      1016 chrome_elf.dll                                     C:\Program Files (x86)\Google\Chrome\Application\88.0.4324...
      2244 chrome.exe                                         C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
      1016 chrome_elf.dll                                     C:\Program Files (x86)\Google\Chrome\Application\88.0.4324...
    152776 chrome.dll                                         C:\Program Files (x86)\Google\Chrome\Application\88.0.4324...

-- More --
```

   - Use the `Get-Ciminstance Win32_Process` cmdlet to veiw processes with PPID

   - 1) View Process instances with Win32 process.

       - `Get-Ciminstance Win32_Process`
```
PS C:\WINDOWS\system32>  Get-CimInstance Win32_Process

ProcessId Name                        HandleCount WorkingSetSize VirtualSize
--------- ----                        ----------- -------------- -----------
0         System Idle Process         0           8192           4096
4         System                      4114        36864          3997696
108       Registry                    0           34344960       93061120
372       smss.exe                    59          425984         2203359731712
476       csrss.exe                   583         2076672        2203413258240
552       wininit.exe                 165         1449984        2203387731968
560       csrss.exe                   360         1101824        2203404800000
/---OUTPUT TRUNCATED---/
```

   - 2) View the additional Properties with `Get-Member`
```
PS C:\WINDOWS\system32>  Get-CimInstance Win32_Process | Get-Member
   TypeName:
Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_Process

Name                       MemberType     Definition
----                       ----------     ----------
/---OUTPUT TRUNCATED---/
ParentProcessId            Property       uint32 ParentProcessId {get;}
/---OUTPUT TRUNCATED---/
```
   - 3) View the processes with PID and PPID sorted by PID
```
PS C:\WINDOWS\system32>  Get-CimInstance Win32_Process | select name,ProcessId,ParentProcessId | sort processid

name                        ProcessId ParentProcessId
----                        --------- ---------------
System Idle Process                 0               0
System                              4               0
msedge.exe                         32            9744
Registry                          108               4
smss.exe                          372               4
svchost.exe                       396             696
dwm.exe                           408             612
csrss.exe                         476             468
notepad.exe                       488            7524
/---OUTPUT TRUNCATED---/
```

   - View an instance of all Win32 (system) services.

       - `Get-Ciminstance Win32_service | Select Name, Processid, Pathname | more`

           - Pipe in `ft -wrap` to see full file name/path
```
PS C:\Users\student> Get-Ciminstance Win32_service | Select Name, Processid, Pathname | ft -wrap | more

Name                                                   Processid Pathname
----                                                   --------- --------
AdobeARMservice                                             4624 "C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\armsvc.exe"
AJRouter                                                       0 C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted -p
ALG                                                            0 C:\WINDOWS\System32\alg.exe
AppIDSvc                                                       0 C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted -p
Appinfo                                                     7752 C:\WINDOWS\system32\svchost.exe -k netsvcs -p
AppReadiness                                                   0 C:\WINDOWS\System32\svchost.exe -k AppReadiness -p
AppXSvc                                                    13292 C:\WINDOWS\system32\svchost.exe -k wsappx -p
AudioEndpointBuilder                                        3168 C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p
Audiosrv                                                    3920 C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p
autotimesvc                                                    0 C:\WINDOWS\system32\svchost.exe -k autoTimeSvc
AxInstSV                                                       0 C:\WINDOWS\system32\svchost.exe -k AxInstSVGroup
BDESVC                                                      1628 C:\WINDOWS\System32\svchost.exe -k netsvcs -p
BFE                                                         3908 C:\WINDOWS\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p
BITS                                                           0 C:\WINDOWS\System32\svchost.exe -k netsvcs -p
BrokerInfrastructure                                        1172 C:\WINDOWS\system32\svchost.exe -k DcomLaunch -p

-- More --
```

### View Processes in Command Prompt

   - View all processes

       - `tasklist`
```
C:\Users\student> tasklist | more

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          8 K
System                           4 Services                   0         96 K
Secure System                   72 Services                   0     22,332 K
Registry                       132 Services                   0     28,948 K
smss.exe                       504 Services                   0        940 K
csrss.exe                      876 Services                   0      2,800 K
wininit.exe                    452 Services                   0      3,484 K
csrss.exe                      576 Console                    1      3,648 K
winlogon.exe                   916 Console                    1      6,204 K
services.exe                   976 Services                   0      6,996 K

-- More --
```

   - Display verbose task information in the output

       - `tasklist /v`
```
C:\Users\student> tasklist /v | more
svchost.exe                   3012 Services                   0      5,364 K Unknown         N/A
Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                      CPU Time Window Title
========================= ======== ================ =========== ============ =============== ========================   ===============================
System Idle Process              0 Services                   0          8 K Unknown         NT AUTHORITY\SYSTEM              1628:26:24 N/A
System                           4 Services                   0         96 K Unknown         N/A                              0:44:21 N/A
Secure System                   72 Services                   0     22,332 K Unknown         N/A                              0:00:00 N/A
Registry                       132 Services                   0     37,948 K Unknown         N/A                              0:00:12 N/A
smss.exe                       504 Services                   0        940 K Unknown         N/A                              0:00:00 N/A
csrss.exe                      876 Services                   0      2,908 K Unknown         N/A                              0:00:06 N/A
wininit.exe                    452 Services                   0      3,488 K Unknown         N/A                              0:00:00 N/A

-- More --
```
   - Display service information for each process without truncation

       - `tasklist /svc`
```
C:\Users\student> tasklist /svc

Image Name                     PID Services
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
Secure System                   72 N/A
Registry                       132 N/A
smss.exe                       504 N/A
csrss.exe                      876 N/A
wininit.exe                    452 N/A
csrss.exe                      576 N/A
winlogon.exe                   916 N/A
services.exe                   976 N/A
LsaIso.exe                     572 N/A
lsass.exe                     1028 EFS, KeyIso, SamSs, VaultSvc
svchost.exe                   1172 BrokerInfrastructure, DcomLaunch, PlugPlay,
                                   Power, SystemEventsBroker

-- More --
```

   - Display modules/dlls associated to all processes.

       - `tasklist /m | more`
```
C:\Users\student> tasklist /m | more

Image Name                     PID Modules
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
Secure System                   72 N/A
Registry                       132 N/A
smss.exe                       504 N/A
csrss.exe                      876 N/A
wininit.exe                    452 N/A
csrss.exe                      576 N/A
winlogon.exe                   916 N/A
services.exe                   976 N/A
LsaIso.exe                     572 N/A
lsass.exe                     1028 N/A
svchost.exe                   1160 N/A
sihost.exe                    4720 ntdll.dll, KERNEL32.DLL, KERNELBASE.dll,
                                   msvcp_win.dll, ucrtbase.dll, combase.dll,
                                   RPCRT4.dll, sechost.dll, advapi32.dll,
                                   msvcrt.dll, CoreMessaging.dll, WS2_32.dll,
                                   ntmarta.dll, kernel.appcore.dll,
-- More --
```

   - Display modules/dlls associated to a specific process.

       - `tasklist /m /fi "IMAGENAME eq chrome.exe"`
```
C:\Users\student> tasklist /m /fi "IMAGENAME eq chrome.exe" | more

Image Name                     PID Modules
========================= ======== ============================================
chrome.exe                    8260 ntdll.dll, KERNEL32.DLL, KERNELBASE.dll,
                                   chrome_elf.dll, VERSION.dll, msvcrt.dll,
                                   ADVAPI32.dll, sechost.dll, RPCRT4.dll,
                                   CRYPTBASE.DLL, bcryptPrimitives.dll,
                                   ntmarta.dll, ucrtbase.dll, user32.dll,
                                   win32u.dll, GDI32.dll, gdi32full.dll,
                                   msvcp_win.dll, IMM32.DLL, SHELL32.dll,
                                   windows.storage.dll, combase.dll, Wldp.dll,
                                   SHCORE.dll, shlwapi.dll, chrome.dll,

-- More  --
```

   - Formatting options

       - `tasklist /fo:{table|list|csv}`
```
C:\Users\student> tasklist /fo:table | more

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          8 K
System                           4 Services                   0         96 K
Secure System                   72 Services                   0     22,332 K
Registry                       132 Services                   0     37,876 K
smss.exe                       504 Services                   0        964 K
csrss.exe                      876 Services                   0      2,940 K
wininit.exe                    452 Services                   0      3,712 K

-- More --
```
```
C:\Users\student> tasklist /fo:list | more

Image Name:   System Idle Process
PID:          0
Session Name: Services
Session#:     0
Mem Usage:    8 K

Image Name:   System
PID:          4
Session Name: Services
Session#:     0
Mem Usage:    96 K

Image Name:   Secure System
PID:          72
Session Name: Services
Session#:     0
Mem Usage:    22,332 K

-- More --
```
```
C:\Users\student> tasklist /fo:csv | more

"Image Name","PID","Session Name","Session#","Mem Usage"
"System Idle Process","0","Services","0","8 K"
"System","4","Services","0","96 K"
"Secure System","72","Services","0","22,332 K"
"Registry","132","Services","0","37,876 K"
"smss.exe","504","Services","0","964 K"
"csrss.exe","876","Services","0","2,940 K"
"wininit.exe","452","Services","0","3,712 K"
"csrss.exe","576","Console","1","4,948 K"
"winlogon.exe","916","Console","1","6,600 K"
"services.exe","976","Services","0","7,636 K"

-- More --
```

   - Filtering for specific string/process

       `tasklist /fi "IMAGENAME eq lsass.exe"`
```
C:\Users\student>tasklist /fi "IMAGENAME eq lsass.exe

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
lsass.exe                     1028 Services                   0     17,984 K
```

### View Processes in the GUI

   - Task Manager

       - Microsoft Default

   - Procexp.exe

       - We’ll go over it in Sysinternal Tools Lesson

       - [Microsoft Reference](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer)

## How to View Services

   - Q: Which Windows commands let us view information on services?

       - In Powershell:

           - `Get-Ciminstance` - [Microsoft Reference](https://docs.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance?view=powershell-7.1)

           - `Get-Service` - [Microsoft Reference](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-service?view=powershell-7.1)

       - In Command Prompt:

           - `net start` - Shows currently running services

           - `sc query` - [Microsoft Reference](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query)

### View Services in PowerShell

   - View only system services and display Name, PID, and the path they are initiated from.

       - `Get-Ciminstance Win32_service | Select Name, Processid, Pathname | more`

           - Pipe in a `ft -wrap` to see full pathname.
```
PS C:\Users\student> Get-Ciminstance Win32_service | Select Name, Processid, Pathname | more

Name                                                   Processid Pathname
----                                                   --------- --------
AdobeARMservice                                             4624 "C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\armsvc.exe"
AJRouter                                                       0 C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestri...
ALG                                                            0 C:\WINDOWS\System32\alg.exe
AppIDSvc                                                       0 C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestri...
Appinfo                                                     7752 C:\WINDOWS\system32\svchost.exe -k netsvcs -p
AppReadiness                                                   0 C:\WINDOWS\System32\svchost.exe -k AppReadiness -p
AppXSvc                                                        0 C:\WINDOWS\system32\svchost.exe -k wsappx -p
AudioEndpointBuilder                                        3168 C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestric...
Audiosrv                                                    3920 C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestri...

-- More --
```

   - View all services.

       - `Get-Service`

```
PS C:\Users\student> get-service | more

Status   Name               DisplayName
------   ----               -----------
Stopped  AarSvc_5d854       Agent Activation Runtime_5d854
Running  AdobeARMservice    Adobe Acrobat Update Service
Stopped  AJRouter           AllJoyn Router Service
Stopped  ALG                Application Layer Gateway Service
Stopped  AppIDSvc           Application Identity

-- More  --
```

   - View a defined service, showing all properties in list format.

       - `get-service ALG | format-list *`
```
PS C:\Users\student> get-service ALG | format-list *

Name                : ALG
RequiredServices    : {}
CanPauseAndContinue : False
CanShutdown         : False
CanStop             : False
DisplayName         : Application Layer Gateway Service
DependentServices   : {}
MachineName         : .
ServiceName         : ALG
ServicesDependedOn  : {}
ServiceHandle       :
Status              : Stopped
ServiceType         : Win32OwnProcess
StartType           : Manual
Site                :
Container           :
```

   - View only currently running services.

       - `Get-Service | Where-Object {$_.Status -eq "Running"}`
```
PS C:\Users\student> Get-Service | Where-Object {$_.Status -eq "Running"} | more

Status   Name               DisplayName
------   ----               -----------
Running  AdobeARMservice    Adobe Acrobat Update Service
Running  Appinfo            Application Information
Running  AppXSvc            AppX Deployment Service (AppXSVC)
Running  AudioEndpointBu... Windows Audio Endpoint Builder
Running  Audiosrv           Windows Audio
Running  BDESVC             BitLocker Drive Encryption Service
Running  BFE                Base Filtering Engine

-- More  --
```

### View Services in Command Prompt

   - View Services

       - `sc query`
```
C:\Users\student>sc query | more

SERVICE_NAME: AdobeARMservice
DISPLAY_NAME: Adobe Acrobat Update Service
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

SERVICE_NAME: Appinfo
DISPLAY_NAME: Application Information

-- More --
```
   - View extended information for all services.

       - `sc queryex type=service`
```
C:\Users\student>sc queryex type=service | more

SERVICE_NAME: AdobeARMservice
DISPLAY_NAME: Adobe Acrobat Update Service
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 4624
        FLAGS              :

SERVICE_NAME: Appinfo
DISPLAY_NAME: Application Information

-- More  --
```

   - Additional examples of the SC command
```
C:\sc /?                           # Basic service enumeration
C:\sc qc                           # Configuration information for a service
C:\sc queryex eventlog             # Information for the eventlog service including pid
C:\sc qdescription eventlog        # Query eventlog service description
C:\sc qc eventlog                  # Show the binary command that loads the service
C:\sc showsid eventlog             # Displays the service SID and status
c:\sc enmudepend                   # Lists the services that cannot run unless the specified service is running
```

   - View all currently running services.

       - `net start`
```
C:\Users\student>net start | more
These Windows services are started:

   Adobe Acrobat Update Service
   Application Information
   AppX Deployment Service (AppXSVC)
   AVCTP service
   Background Tasks Infrastructure Service
   Base Filtering Engine

-- More  --
```
### View Services in the GUI

   - `services.msc`

       - Pull it up in the Windows search bar and show them around if you’d like.

   - PsService

       - Sysinternal Tool

       - Microsoft Reference

# Scheduled Tasks

## What are Scheduled Tasks?

   - Schedule the launch of programs or scripts when defined conditions are met, such as:

       - Pre-set time (ex. 0900 on Sundays)

       - When the local machine boots up.

       - When a user logs on.

   - Easy way to hide Malware and have itself set to execute at set times.

       - Separate files can be run from schedule tasks that calls the malware, like a script

   - Good way to establish Persistence.

## How to view Scheduled tasks

### View Scheduled Tasks In PowerShell

   - View all properties of the first scheduled task.

       - `Get-ScheduledTask | Select * | select -First 1`
```
PS C:\Users\student> Get-ScheduledTask | Select * | select -First 1

State                 : Ready
Actions               : {MSFT_TaskExecAction}
Author                : Adobe Systems Incorporated
Date                  :
Description           : This task keeps your Adobe Reader and Acrobat applications up to date with the latest enhancements and security fixes
Documentation         :
Principal             : MSFT_TaskPrincipal2
SecurityDescriptor    :
Settings              : MSFT_TaskSettings3
Source                :
TaskName              : Adobe Acrobat Update Task
TaskPath              : \
Triggers              : {MSFT_TaskLogonTrigger, MSFT_TaskDailyTrigger}
URI                   : \Adobe Acrobat Update Task
Version               :
PSComputerName        :
CimClass              : Root/Microsoft/Windows/TaskScheduler:MSFT_ScheduledTask
CimInstanceProperties : {Actions, Author, Date, Description...}
CimSystemProperties   : Microsoft.Management.Infrastructure.CimSystemProperties
```

### View Scheduled Tasks In Command Prompt
```
schtasks /query /tn "IchBinBosh" /v /fo list

Folder: \
HostName:                             ADMIN-STATION
TaskName:                             \IchBinBosh
Next Run Time:                        6/1/2021 5:02:00 PM
Status:                               Ready
Logon Mode:                           Interactive only
Last Run Time:                        6/1/2021 4:47:00 PM
Last Result:                          0
Author:                               ADMIN-STATION\andy.dwyer
Task To Run:                          powershell.exe -win hidden -encode JABMAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABjAHAATABpAHMAdABlAG4AZQByACgANgA2ADYANgApADsAJABMAC4AUwB0AGEAcgB0ACgAKQA7AFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0AcwAgADYAMAA=
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          andy.dwyer
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        One Time Only, Minute
Start Time:                           4:02:00 PM
Start Date:                           6/1/2021
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        0 Hour(s), 15 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled
```
Q: What odd command do we see occurring in the output above?

A: Powershell is running encoded strings

Q: How do we decode encoded strings?

A: Cyberchef website

### View Scheduled Tasks in the GUI

   - Windows Default

       - Task Scheduler

   - Sysinternal tool

       - Autoruns.

           - We’ll go over this more in Sysinternal Tools.

           - [Microsoft Reference](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)

### Autorun Registry Locations

   - Q: What are some Registry keys that can be used for autoruns?

       - Registry Keys Locations, Locations connected with Services.

           - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` - Local Machine

           - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`

           - `HKLM\System\CurrentControlSet\Services`

       - Remember that the Users have individual Hives with autoruns as well as the Current User.

           - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` - Current User

           - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`

           - `HKU\<sid>\Software\Microsoft\Windows\CurrentVersion\Run` - Specific User

           - `HKU\<sid>\Software\Microsoft\Windows\CurrentVersion\RunOnce`

       - The order in which services are loaded can be adjusted.

           - `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\ServiceGroupOrder`

           - `HKEY_LOCAL_MACHINE\CurrentControlSet\Control\GroupOrderList`

## DEMO: Create Task to open listening Port via the PowerShell Process.

### Create IchBinBosh task

    Opens port listening on port 6666 every 15 minutes.
```
1. In CMD, run the following.

schtasks /Create /TN IchBinBosh /SC MINUTE /MO 15 /TR "powershell.exe -win hidden -encode JABMAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABjAHAATABpAHMAdABlAG4AZQByACgANgA2ADYANgApADsAJABMAC4AUwB0AGEAcgB0ACgAKQA7AFMAdABhAHIAdAAtAFMAbABlAGUAcAAgAC0AcwAgADYAMAA="

----- OR -----

2. *If the script stops working* - run the following commands instead in Powershell to create a listening port:

$command = '$L=New-Object System.Net.Sockets.TcpListener(6666);$L.Start();Start-Sleep -s 60'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
powershell.exe -encodedCommand $encodedCommand
```

### Confirm IchBinBosh exists and View Properties

   - In Command Prompt

       - `schtasks /query | select-string -pattern IchBinBosh -Context 2,4`

   - In PowerShell

       - `Get-ScheduledTask | Select * | select-string -pattern IchBinBosh -Context 2,4`

   - In GUI

       - Show in either Task Scheduler or AutoRuns.

# Network Connections

## View Network Connections In PowerShell

   - Show all Connections in the "Established" state.

      - `Get-NetTCPConnection -State Established`
```
PS C:\Users\andy.dwyer> Get-NetTCPConnection -State Established

LocalAddress        LocalPort RemoteAddress      RemotePort State       AppliedSetting OwningProcess
------------        --------- -------------      ---------- -----       -------------- -------------
10.23.0.2           49701     52.177.165.30      443        Established Internet       2988
10.23.0.2           22        10.250.0.15        59038      Established Internet       2944
```
## View Network Connections in Command Prompt

   - Show netstat help and point out the following:

       - `netstat /?`
```
-a   Displays all connections and listening ports
-n   Displays addresses and port numbers in numerical form
-o   Displays the owning process ID (PID) associated with each connection
-b   Displays the executable involved in creating each connection (must have admin rights)
```

   - Displays all TCP/UDP connections with ports in numerical form with PID and executable associated to the connections

       - `netstat -anob | more`
```
andy.dwyer@ADMIN-STATION C:\Users\andy.dwyer>netstat -anob | more

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       2944
 [sshd.exe]
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       832
  RpcSs
 [svchost.exe]
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
 Can not obtain ownership information
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       304
  TermService
 [svchost.exe]
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       4456
  CDPSvc

-- More --
```

## View Network Connections in the GUI

   - TCPView

       - We will go over this in Sysinternal tools

       - If you want to dig deeper: [Microsoft Reference](https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview)

# Identifying Abnormalities/Suspicious Activity

   - **Q: What are some Abnormal things we could see in a process list?**

       - Misspelling of process names and descriptions.

           - Ex. scvhost instead of svchost

       - Directory the process is running out of.

    - **Q: Which directory are windows executables typically run out of?**

           - System Processes run from C:\Windows\System32

           - Third party processes will run elsewhere.

           - Ex. Chrome runs from C:\Program Files

       - Processes that have non-standard listening ports open or ports with SYN/SENT.

           - Like HTTP being used on any port other than 80. (ex. HTTP over port 808 or 880)

       - Multiple processes with the same name that should be unique such as LSASS, SMSS

           - System process with a high PID.

       - Handles or DLLs a process is using.

           - Dig Deeper into DLLs:

               - [Microsoft Compromised DLLs](https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/)

               - [DLL Hijacking](https://itm4n.github.io/windows-dll-hijacking-clarified/)

   - **Q: Where’s Waldo??? Using what we’ve learned so far, what stands out about this Task List?**

```
System Idle Process              0 Services       0          8 K Unknown         NT AUTHORITY\SYSTEM        368:23:24 N/A
System                           4 Services       0         24 K Unknown         N/A                        0:13:27 N/A
Registry                        88 Services       0     46,944 K Unknown         N/A                        0:00:11 N/A
smss.exe                       288 Services       0        344 K Unknown         N/A                        0:00:00 N/A
csrss.exe                      392 Services       0      1,768 K Unknown         N/A                        0:00:06 N/A
wininit.exe                    464 Services       0        876 K Unknown         N/A                        0:00:00 N/A
csrss.exe                      476 Console        1      1,872 K Running         N/A                        0:00:16 N/A
winlogon.exe                   560 Console        1      3,772 K Unknown         N/A                        0:00:00 N/A
services.exe                   576 Services       0      8,756 K Unknown         N/A                        0:02:28 N/A
lsass.exe                      604 Services       0     11,980 K Unknown         N/A                        0:14:15 N/A
svchost.exe                    716 Services       0        908 K Unknown         N/A                        0:00:00 N/A
fontdrvhost.exe                724 Console        1      2,572 K Unknown         N/A                        0:00:01 N/A
fontdrvhost.exe                736 Services       0        680 K Unknown         N/A                        0:00:00 N/A
svchost.exe                    800 Services       0     20,396 K Unknown         N/A                        0:04:37 N/A
svchost.exe                    848 Services       0     10,804 K Unknown         N/A                        0:01:42 N/A
svchost.exe                    896 Services       0      4,144 K Unknown         N/A                        0:01:05 N/A
dwm.exe                        992 Console
firefox.exe                   2396 Console        1     53,008 K Running         ARMY\andy.dwyer         0:00:01 OleMainThreadWndName
cmd.exe                       4372 Console        1      3,132 K Running         ARMY\andy.dwyer         0:00:00 Command Prompt - tasklist  /v
conhost.exe                   4128 Console        1     19,536 K Running         ARMY\andy.dwyer         0:00:18 N/A
firefox.exe                   6952 Console        1     36,340 K Not Responding  ARMY\andy.dwyer         0:00:00 OleMainThreadWndName
dllhost.exe                   6324 Console        1     16,084 K Running         ARMY\andy.dwyer         0:00:00 N/A
cmd.exe                       5788 Console        1      3,204 K Running         ARMY\andy.dwyer         0:00:00 C:\windows\system32\cmd.exe
conhost.exe                   6240 Console        1     15,956 K Running         ARMY\andy.dwyer         0:00:00 N/A
SecHealthUI.exe               1828 Console        1     54,808 K Running         ARMY\andy.dwyer         0:00:03 CicMarshalWnd
dllhost.exe                   7316 Console        1      9,532 K Running         ARMY\andy.dwyer         0:00:00 OleMainThreadWndName
bad.exe                       3648 Services       0      6,680 K Unknown         N/A                        0:00:00 N/A
conhost.exe                   8604 Console        1     17,832 K Running         ARMY\andy.dwyer         0:00:00 N/A
smartscreen.exe               5916 Console        1     20,268 K Unknown         ARMY\andy.dwyer         0:00:00 N/A
smss.exe                      8972 Console        1     14,412 K Running         ARMY\andy.dwyer         0:00:00 Installer Language
svchost.exe                   8976 Services       0      5,632 K Unknown         N/A                        0:00:00 N/A
WmiPrvSE.exe                  9212 Services       0      8,824 K Unknown         N/A                        0:00:00 N/A
reqedit.exe                   8760 Console        1     12,556 K Running         ARMY\andy.dwyer         0:00:00 PuTTY Configuration
tasklist.exe                  8308 Console
SystemSettingsBroker.exe      5600 Console        1      2,536 K Unknown         ARMY\andy.dwyer         0:00:00 N/A
explorer.exe                  5416 Console        1     19,276 K Running         ARMY\andy.dwyer         0:00:30 N/A
MsMpEng.exe                   6616 Services       0     88,688 K Unknown         N/A                        0:09:55 N/A
regedit.exe                   2624 Console        1      3,200 K Running         ARMY\andy.dwyer         0:00:00 Registry Editor
mmc.exe                       3352 Console        1      5,380 K Running         ARMY\andy.dwyer         0:00:02 OLEChannelWnd
svchost.exe                   4200 Services       0      8,716 K Unknown         N/A                        0:00:01 N/A
dllhost.exe                   4868 Console        1      6,236 K Running         ARMY\andy.dwyer         0:00:00 OleMainThreadWndName
powershell_ise.exe            4940 Console        1    406,740 K Running         ARMY\andy.dwyer         0:01:20 Windows PowerShell ISE
taskhostw.exe                 5864 Console        1      7,524 K Running         ARMY\andy.dwyer         0:00:00 Task Host Window
MicrosoftEdge.exe             6928 Console        1        712 K Running         ARMY\andy.dwyer         0:00:00 Microsoft Edge
browser_broker.exe            1108 Console        1        972 K Running         ARMY\andy.dwyer         0:00:00 OleMainThreadWndName
svchost.exe
```

   - **A: High PID duplicate, unfamiliar process name, and misspelling.**

       - Two smss.exe, one with a high PID of 8972

       - bad.exe

       - reqedit.exe
```
== 6. Resources

{empty} +

* Processes
** https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-7.1[Microsoft Reference - Get-Process]
** https://docs.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance?view=powershell-7.1[Microsoft Reference - Get-Ciminstance]

* Services
** https://docs.microsoft.com/en-us/dotnet/framework/windows-services/introduction-to-windows-service-applications[Microsoft Reference - Services.msc]
** https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-service?view=powershell-7.1[Microsoft Reference - Get-Service]
** https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query[Microsoft Reference - SC Query]

* Network Connections
** https://social.technet.microsoft.com/wiki/contents/articles/30571.netstat-for-beginners.aspx#a_parameter[Netstat for Beginners]

* DLL Info
** link:https://docs.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree[DLLs and Services]
** link:https://docs.microsoft.com/en-us/troubleshoot/windows-client/deployment/dynamic-link-library[Microsoft Reference - DLL]
** link:https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/[Microsoft Compromised DLLs]
** link:https://itm4n.github.io/windows-dll-hijacking-clarified/[DLL Hijacking]

* Sysinternal Tools
** link:https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer[Microsoft Reference - ProcExp]
** link:https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns[Microsoft Reference - AutoRuns]
** link:https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview[Microsoft Reference - TCPView]
```
