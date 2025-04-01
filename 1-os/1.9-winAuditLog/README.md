# Windows Artifacts

Gain an understanding of what artifacts are and to track user or system activity with them.

At the end of this lesson you will be able to describe and pull information from the following artifacts:

   - UserAssist

   - Windows Background Activity Moderator (BAM)

   - Recycle Bin

   - Prefetch

   - Jump Lists

   - Recent Files

   - Browser Artifacts

## What is an artifact?

Artifacts are objects or areas within a computer system that contain important information relevant to the activities performed on the system by the user.

These artifacts must be identified, processed, and analyzed in order to prove or disprove any observations made during forensic analysis.However, the absence of information in an artifact does not indicate that an activity didn’t occur.

There are multiple artifacts in the Windows environment that serve as important evidence in the forensic examination process.

[SANS Windows Artifact Analysis](https://in-addr.nl/mirror/SANS-Digital-Forensics-and-Incident-Response-Poster-2012.pdf)

[Forensically relevent Registry locations](https://resources.infosecinstitute.com/windows-systems-and-artifacts-in-digital-forensics-part-i-registry/)

Many artifacts will require the use of a **Security Identifer (SID)** to dig into the user specific registry locations for the artifact information.
```
PS C:\> Get-LocalUser | select Name,SID 
Name               SID
----               ---
Admin              S-1-5-21-1584283910-3275287195-1754958050-1000
Administrator      S-1-5-21-1584283910-3275287195-1754958050-500
cloudbase-init     S-1-5-21-1584283910-3275287195-1754958050-1002
DefaultAccount     S-1-5-21-1584283910-3275287195-1754958050-503
Guest              S-1-5-21-1584283910-3275287195-1754958050-501
andy.dwyer         S-1-5-21-1584283910-3275287195-1754958050-1005
sshd               S-1-5-21-1584283910-3275287195-1754958050-1003
student            S-1-5-21-1584283910-3275287195-1754958050-1004
WDAGUtilityAccount S-1-5-21-1584283910-3275287195-1754958050-504

PS C:\> Get-WmiObject win32_useraccount | select name,sid 
name               sid
----               ---
Admin              S-1-5-21-1584283910-3275287195-1754958050-1000
Administrator      S-1-5-21-1584283910-3275287195-1754958050-500
cloudbase-init     S-1-5-21-1584283910-3275287195-1754958050-1002
DefaultAccount     S-1-5-21-1584283910-3275287195-1754958050-503
Guest              S-1-5-21-1584283910-3275287195-1754958050-501
andy.dwyer         S-1-5-21-1584283910-3275287195-1754958050-1005
sshd               S-1-5-21-1584283910-3275287195-1754958050-1003
student            S-1-5-21-1584283910-3275287195-1754958050-1004
WDAGUtilityAccount S-1-5-21-1584283910-3275287195-1754958050-504
_Output_Truncated_
```
-	`Get-LocalUser` will show local Users and SID on a system
-	`Get-WmiObject` will show local and domain Users and SID
```
{empty} +
```

**Get SIDS in Command Prompt**
```
C:\windows\system32>wmic UserAccount get name,sid 
Name                SID
Admin               S-1-5-21-1584283910-3275287195-1754958050-1000
Administrator       S-1-5-21-1584283910-3275287195-1754958050-500
cloudbase-init      S-1-5-21-1584283910-3275287195-1754958050-1002
DefaultAccount      S-1-5-21-1584283910-3275287195-1754958050-503
Guest               S-1-5-21-1584283910-3275287195-1754958050-501
andy.dwyer          S-1-5-21-1584283910-3275287195-1754958050-1005
sshd                S-1-5-21-1584283910-3275287195-1754958050-1003
student             S-1-5-21-1584283910-3275287195-1754958050-1004
WDAGUtilityAccount  S-1-5-21-1584283910-3275287195-1754958050-504
```
-	`wmic useraccount get name,sid` will show local Users and SID

# UserAssist
	Run ALL Artifacts demos on Workstation2 while in a ssh from the Admin-Station

The UserAssist registry key tracks the GUI-based programs that were ran by a particular user.

## Location

They are located in `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count\` * they are encoded in ROT13

The **GUID** represents a particular file extension.

   - `CEBFF5CD-ACE2-4F4F-9178-9926F41749EA` A list of applications, files, links, and other objects that have been accessed

   - `F4E57C4B-2036-45F0-A9AB-443BCFE33D9F` Lists the Shortcut Links used to start programs

## Demo
**CEBFF5CD: Executable File Execution**
```
PS C:\> Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" 

HRZR_PGYPHNPbhag:pgbe                                                            : {255, 255, 255, 255...}
Zvpebfbsg.Trgfgnegrq_8jrxlo3q8oojr!Ncc                                           : {0, 0, 0, 0...}
HRZR_PGYFRFFVBA                                                                  : {0, 0, 0, 0...}
Zvpebfbsg.JvaqbjfSrrqonpxUho_8jrxlo3q8oojr!Ncc                                   : {0, 0, 0, 0...}
Zvpebfbsg.JvaqbjfZncf_8jrxlo3q8oojr!Ncc                                          : {0, 0, 0, 0...}
Zvpebfbsg.Crbcyr_8jrxlo3q8oojr!k4p7n3o7ql2188l46q4ln362l19np5n5805r5k            : {0, 0, 0, 0...}
Zvpebfbsg.ZvpebfbsgFgvpxlAbgrf_8jrxlo3q8oojr!Ncc                                 : {0, 0, 0, 0...}
{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\FavccvatGbby.rkr                          : {0, 0, 0, 0...}
Zvpebfbsg.JvaqbjfPnyphyngbe_8jrxlo3q8oojr!Ncc                                    : {0, 0, 0, 0...}
{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\zfcnvag.rkr                               : {0, 0, 0, 0...}
{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\abgrcnq.rkr                               : {0, 0, 0, 0...}
Zvpebfbsg.Jvaqbjf.Pbegnan_pj5a1u2gklrjl!PbegnanHV                                : {0, 0, 0, 0...}
{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\JvaqbjfCbjreFuryy\i1.0\CbjreFuryy_VFR.rkr : {0, 0, 0, 0...}
_Output_Truncated_
```
-	Output shows the Executable files encoded with ROT13. Copy/ Paste the output into a decoder site like [Rot13](https://www.rot13.com/) or [CyberChef](https://gchq.github.io/CyberChef/)

**F4E57C4B: Shortcut File Execution**
```
PS C:\> Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count" 

HRZR_PGYPHNPbhag:pgbe                                                            : {255, 255, 255, 255...}
{0139Q44R-6NSR-49S2-8690-3QNSPNR6SSO8}\Npprffbevrf\Favccvat Gbby.yax             : {0, 0, 0, 0...}
HRZR_PGYFRFFVBA                                                                  : {0, 0, 0, 0...}
{0139Q44R-6NSR-49S2-8690-3QNSPNR6SSO8}\Npprffbevrf\Cnvag.yax                     : {0, 0, 0, 0...}
{N77S5Q77-2R2O-44P3-N6N2-NON601054N51}\Npprffbevrf\Abgrcnq.yax                   : {0, 0, 0, 0...}
{N77S5Q77-2R2O-44P3-N6N2-NON601054N51}\Jvaqbjf CbjreFuryy\Jvaqbjf CbjreFuryy.yax : {0, 0, 0, 0...}
{N77S5Q77-2R2O-44P3-N6N2-NON601054N51}\Flfgrz Gbbyf\Pbzznaq Cebzcg.yax           : {0, 0, 0, 0...}
{0139Q44R-6NSR-49S2-8690-3QNSPNR6SSO8}\Nqzvavfgengvir Gbbyf\Ertvfgel Rqvgbe.yax  : {0, 0, 0, 0...}
{0139Q44R-6NSR-49S2-8690-3QNSPNR6SSO8}\Npprffbevrf\Erzbgr Qrfxgbc Pbaarpgvba.yax : {0, 0, 0, 0...}
{9R3995NO-1S9P-4S13-O827-48O24O6P7174}\GnfxOne\Svyr Rkcybere.yax                 : {0, 0, 0, 0...}
{0139Q44R-6NSR-49S2-8690-3QNSPNR6SSO8}\Tbbtyr Puebzr.yax                         : {0, 0, 0, 0...}
_Output_Truncated_
```
-	Output shows the files run from Shortcut locations encoded with ROT13.

**Q**: Where can you look to pull all users that have logged on to the computer and have ran executables?

**Q: How can we change our command to look at all users Userassist artifacts?

**A**: From
```
PS C:\> Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
```
To
```
PS C:\> Get-ItemProperty "Registry::Hkey_Users\*\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
```

[Windows User Assist Key Additional Information](https://www.aldeid.com/wiki/Windows-userassist-keys)

# Windows Background Activity Moderator (BAM)

Windows Background Activity Moderator (BAM) BAM is a Windows service that Controls activity of background applications.This service exists in Windows 10 only after Fall Creators update – version 1709.

**BAM Provides the following:**

   - full path of an executable

   - last execution date/time.

**Q: What is the importance of knowing the path of an executable?**

## Location

**Show in Reg Edit:**
`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings` On 1809 and Newer

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings` On 1803 and below

#### CMD command to get Windows OS Version - Ran in Admin-Station

   - systeminfo
```
C:\WINDOWS\system32>systeminfo

Host Name:                 ADMIN-STATION
OS Name:                   Microsoft Windows 10 Enterprise
OS Version:                10.0.19045 N/A Build 19045 
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
/----Output Truncated----/
```
-	**see table below** - 19045 (Windows 10 (22H2)) is the last Windows 10 Version

#### Powershell cmdlet to get Windows OS Version - Ran in Admin-Station

   - Get-Computerinfo
```
Get-ComputerInfo | select osname,osversion,OsHardwareAbstractionLayer

OsName                           OsVersion   OsHardwareAbstractionLayer
------                           ---------   --------------------------
Microsoft Windows 10 Enterprise  10.0.19045  10.0.19041.2251
```                            

-	**see table below** - 19045 (Windows 10 (22H2)) is the last Windows 10 Version

|Operating System|Version Details|Build Number|
|---|---|---|
|Windows 11 | Windows 11 (22H2) | 10.0.22621|
| | Windows 11 (21H2) | 10.0.22000|
|Windows 10 | Windows 10 (22H2) | 10.0.19045|
| | Windows 10 (21H2) | 10.0.19044|
| | Windows 10 (21H1) | 10.0.19043|
| | Windows 10 (20H2) | 10.0.19042|
| | Windows 10 (2004) | 10.0.19041|
| | Windows 10 (1909) | 10.0.18363|
| | Windows 10 (1903) | 10.0.18362|
| | Windows 10 (1809) | 10.0.17763|
| | Windows 10 (1803) | 10.0.17134|
| | Windows 10 (1709) | 10.0.16299|
| | Windows 10 (1703) | 10.0.15063|
| | Windows 10 (1607) | 10.0.14393|

## Demo

**BAM entries for every user on the system**
```
PS C:\> Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\UserSettings\* 

   Hive: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\state\UserSettings
Name                           Property
----                           --------
S-1-5-18                       Version        : 1
                               SequenceNumber : 170
S-1-5-21-1584283910-3275287195 Version                                             : 1
-1754958050-1001               SequenceNumber                                      : 2
                               Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy : {102, 101, 158, 153...}
S-1-5-21-1584283910-3275287195 Version                                             : 1
-1754958050-1004               SequenceNumber                                      : 179
                               Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy : {131, 170, 94, 228...}
                               Microsoft.Windows.Cortana_cw5n1h2txyewy             : {69, 3, 57, 6...}
                               Microsoft.MicrosoftEdge_8wekyb3d8bbwe               : {37, 64, 172, 83...}
                               InputApp_cw5n1h2txyewy                              : {72, 27, 34, 188...}
S-1-5-21-1584283910-3275287195 Version                                                                    : 1
-1754958050-1005               SequenceNumber                                                             : 182
                               Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy                        : {155, 178, 178, 246...}
                               Microsoft.Windows.Cortana_cw5n1h2txyewy                                    : {14, 234, 70, 240...}
                               Microsoft.MicrosoftEdge_8wekyb3d8bbwe                                      : {9, 49, 55, 39...}
                               \Device\HarddiskVolume1\Windows\System32\cmd.exe                           : {5, 160, 0, 6...}
_Output_Truncated_
```
-	Output shows all users BAM artifacts

**Single User on the System**
```
PS C:\> wmic useraccount  get caption,sid | more 
Caption                           SID
ADMIN-STATION\Admin               S-1-5-21-1584283910-3275287195-1754958050-1000
ADMIN-STATION\Administrator       S-1-5-21-1584283910-3275287195-1754958050-500
ADMIN-STATION\cloudbase-init      S-1-5-21-1584283910-3275287195-1754958050-1002
ADMIN-STATION\DefaultAccount      S-1-5-21-1584283910-3275287195-1754958050-503
ADMIN-STATION\Guest               S-1-5-21-1584283910-3275287195-1754958050-501
ADMIN-STATION\andy.dwyer          S-1-5-21-1584283910-3275287195-1754958050-1005
_Output_Truncated_

PS C:\> Get-Itemproperty 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1584283910-3275287195-1754958050-1005' 

Version                                                                    : 1
SequenceNumber                                                             : 182
Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy                        : {155, 178, 178, 246...}
Microsoft.Windows.Cortana_cw5n1h2txyewy                                    : {14, 234, 70, 240...}
Microsoft.MicrosoftEdge_8wekyb3d8bbwe                                      : {9, 49, 55, 39...}
\Device\HarddiskVolume1\Windows\System32\cmd.exe                           : {5, 160, 0, 6...}
InputApp_cw5n1h2txyewy                                                     : {89, 33, 209, 53...}
Microsoft.WindowsCalculator_8wekyb3d8bbwe                                  : {66, 111, 53, 155...}
\Device\HarddiskVolume1\Windows\System32\conhost.exe                       : {96, 89, 201, 207...}
\Device\HarddiskVolume1\Users\andy.dwyer\Desktop\Sys Int\Autoruns.exe      : {82, 232, 89, 79...}
\Device\HarddiskVolume1\Windows\System32\notepad.exe                       : {80, 246, 8, 221...}
_Output_Truncated_
```

   - Look at the programs that have been launched and their paths.
   - Get the SID of every local user on the machine
   - Insert the SID of andy.dwyer from above. Output shows the BAM artifact from andy.dwyer
   - Note any programs that might have been launched from an irregular location.

# Recycle Bin

When a user deletes a file in Windows it goes into the Recycle bin. This data is recoverable during an investigation using built in tools.

Content in the recycle bin is identified by:

   - SID - determines which user deleted it

   - Timestamp - When it was deleted

   - `$RXXXXXX` - content of deleted files

   - `$IXXXXXX` - original PATH and name

SIDs are identified using WMIC or the Registry

## Location:

`C:\$Recycle.bin` (Hidden System Folder)

## Demo

**Find the Contents of the Recycle Bin**
```
PS C:\> Get-Childitem 'C:\$RECYCLE.BIN' -Recurse -Verbose -Force | select FullName 
FullName
--------
C:\$RECYCLE.BIN\S-1-5-18
C:\$RECYCLE.BIN\S-1-5-21-1584283910-3275287195-1754958050-1004
C:\$RECYCLE.BIN\S-1-5-21-1584283910-3275287195-1754958050-1005
C:\$RECYCLE.BIN\S-1-5-21-950816436-4199619115-1663388479-500
C:\$RECYCLE.BIN\S-1-5-18\desktop.ini
C:\$RECYCLE.BIN\S-1-5-21-1584283910-3275287195-1754958050-1004\desktop.ini
C:\$RECYCLE.BIN\S-1-5-21-1584283910-3275287195-1754958050-1005\$I8QZ1U8.txt
C:\$RECYCLE.BIN\S-1-5-21-1584283910-3275287195-1754958050-1005\$IBBLWX1.txt
C:\$RECYCLE.BIN\S-1-5-21-1584283910-3275287195-1754958050-1005\$IGJUCO3.txt
C:\$RECYCLE.BIN\S-1-5-21-1584283910-3275287195-1754958050-1005\$R8QZ1U8.txt
C:\$RECYCLE.BIN\S-1-5-21-1584283910-3275287195-1754958050-1005\$RBBLWX1.txt
C:\$RECYCLE.BIN\S-1-5-21-1584283910-3275287195-1754958050-1005\$RGJUCO3.txt
_Output_Truncated_
```
   - Output shows all of the contents of the Recycle Bin. -Recurse will look at all user’s/SID’s contents

Look at the different directories (SIDs) discuss how you would determine what users they belong to.

**Q: Since this gives us all the users on the machine, how would you find the specific user this information belongs to?**

**Match SID to USER:**
```
 PS C:\> wmic useraccount where 'sid="S-1-5-21-1584283910-3275287195-1754958050-1005"' get name 
Name
andy.dwyer
```
-	To find Recycle Bin artifacts for a specific user, match the SID, then append it to the previous command:
```
PS C:\> Get-Content 'C:\$Recycle.Bin\S-1-5-21-1584283910-3275287195-1754958050-1005\$R8QZ1U8.txt' 
This is the file for Auditing
```
-	Reads the contents of a particular file within the Recycle BIN

# Prefetch

Prefetch files are created by the windows operating system when an application is run from a specific location for the first time.

**Q: What is the windows prefetch used for?**

   - These files are named in a predetermined format and the prefetch name consists of the name of the application, hash noting the location from which the application was run, and a “.PF” file extension.

**Q: What is the purpose of analysing the prefetch?**

**Q: If you found a program in prefetch that you know you did not run, what would that be an indicator of?**

For example, the prefetch file for calc.exe would appear as CALC.EXE-0FE8F3A9.pf, where 0FE8F3A9 is a hash of the path from where the file was executed.

The prefetch files are stored in `“\Root\Windows\Prefetch”` folder.

Analysis of prefetch files reveals the evidence of the intial program execution for a user and from a specific location at a specific time.

**Prefetch entries may remain even after the program has been deleted or uninstalled.**

   - This information together with timeline analysis helps in determining what programs have been executed in the system.

   - Evidence of program execution can be a valuable resource for forensic investigators. They can prove that a suspect ran a program like CCleaner to cover up any potential wrongdoing.

   - Limited to 128 files on Win7

   - Limited to 1024 files on Win8-10

       - Win8-10 Prefetch files store the last eight execution times. The file creation time of the prefetch file will indicate the original time of execution within 10 seconds leaving the investigator with a total of nine execution times.

   - Prefetch entries record the location of the associated executable and files referenced by that executable. Look for any files executed or referenced from a temp directory as this is typically an outlier.

   - By default, Windows Server does not have Prefetch enabled.

   - Use Eric Zimmerman’s PECmd.exe utility to analyze Prefetch data

   - General Format of a prefetch file: (exename)-(hash-of-path).pf

[Prefetch Documentation](https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/)

## Location

Win7/8/10

`C:\Windows\Prefetch`

## Demo
```
PS C:\> Get-Childitem -Path 'C:\Windows\Prefetch' -ErrorAction Continue | select -First 8 
    Directory: C:\Windows\Prefetch
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/11/2021   3:53 PM                ReadyBoot
-a----        2/11/2021   3:39 PM         334168 AgAppLaunch.db
-a----        2/16/2021   2:13 PM        1450197 AgCx_S1_S-1-5-21-1584283910-3275287195-1754958050-1004.snp.db
-a----        2/23/2021   7:29 PM        1690240 AgCx_S2_S-1-5-21-1584283910-3275287195-1754958050-1005.snp.db
-a----        3/11/2021   7:21 PM          83229 AgGlFaultHistory.db
-a----        3/11/2021   7:21 PM         420736 AgGlFgAppHistory.db
-a----        3/11/2021   7:21 PM        1629990 AgGlGlobalHistory.db
-a----        2/22/2021   5:19 PM         125687 AgGlUAD_P_S-1-5-21-1584283910-3275287195-1754958050-1004.db
```
-	Output shows the programs that were run and when they were executed that are stored in the Prefetch location.

# Jump Lists

The Windows 7-10 taskbar (Jump List) is engineered to allow users to “jump” or access items they have frequently or recently used quickly and easily.

The data stored in the Automatic Destinations folder will each have a unique file prepended with the AppID of the associated application.

   - First time of execution of application.

   - Creation Time = First time item added to the AppID file.

   - Last time of execution of application w/file open.

   - Modification Time = Last time item added to the AppID file.

Jumplists allow us to get visibility about the intent or knowledge an attacker had when opening a particular file, launching a particular application or browsing a specific directory during the course of an interactive session.

[JumpLists Documentation](https://nasbench.medium.com/windows-forensics-analysis-windows-artifacts-part-ii-71b8fa68d8a1)

## Location

**Win7/8/10**

`C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations (C:\Users\king\AppData\Roaming\Microsoft\Windows\Recent)`

**Show in Explorer:**
`C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations (C:\Users\king\AppData\Roaming\Microsoft\Windows\Recent)`

## Demo

**Programs/Items that were recently used**
```
PS C:\> Get-Childitem -Recurse C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction Continue | select FullName, LastAccessTime 
FullName                                                                                                                                     LastAccessTime
--------                                                                                                                                     --------------
C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations                                                        3/11/2021 8:21:30 PM
C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1bc392b8e104a00e.automaticDestinations-ms              3/11/2021 6:24:55 PM
C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms              3/11/2021 8:16:30 PM
C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\9b9cdc69c1c24e2b.automaticDestinations-ms              3/11/2021 6:24:55 PM
C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\9d1f905ce5044aee.automaticDestinations-ms              3/11/2021 6:24:55 PM
C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\cf02284227526d80.automaticDestinations-ms              3/11/2021 7:02:30 PM

or

PS C:\> Get-Childitem -Recurse $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction SilentlyContinue | select FullName,LastAccessTime 
FullName                                                                                                                                     LastAccessTime
--------                                                                                                                                     --------------
C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations                                                        3/11/2021 8:21:30 PM
C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations                                                           3/11/2021 8:21:30 PM
C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent\14287.lnk                                                                    3/9/2021 6:15:30 PM
C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent\Active_Directory.lnk                                                         3/8/2021 7:07:26 PM
C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent\Artifacts (2).lnk                                                            3/3/2021 8:30:33 PM
C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent\Artifacts.lnk                                                                3/3/2021 7:12:42 PM

or

- Make sure sysinternals is mounted or unzipped
- Gci C:\users\student\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations | % {z:\strings.exe -accepteula $_} >> c:\recentdocs.txt
```
-	Output shows all users Jump Lists artifacts
-	Output shows the Jump Lists Artifacts for the currently logged user
-	Output redirected through strings.exe and into a file provides more readable output.

# Recent Files

Registry Key that will track the last files and folders opened and is used to populate data in “Recent” menus of the Start menu.

   - Tracks last 150 files or folders opened.

   - Entry and modification time of this key will be the time and location the last file of a specific extension was opened.

## Location

   - `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

   - `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt`

## Demo

**Query the Hex Value Stored in the Key**
```
PS C:\> Get-Item 'Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.*' 
    Hive: \HKEY_USERS\S-1-5-21-1584283910-3275287195-1754958050-1005\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
Name                           Property
----                           --------
.html                          MRUListEx : {0, 0, 0, 0...}
                               0         : {114, 0, 101, 0...}
.pdf                           0         : {49, 0, 52, 0...}
                               MRUListEx : {0, 0, 0, 0...}
.ps1                           0         : {65, 0, 114, 0...}
                               MRUListEx : {2, 0, 0, 0...}
                               1         : {65, 0, 99, 0...}
                               2         : {82, 0, 83, 0...}
.sh                            0         : {116, 0, 101, 0...}
                               MRUListEx : {0, 0, 0, 0...}
.txt                           0         : {114, 0, 101, 0...}
                               MRUListEx : {4, 0, 0, 0...}
                               1         : {114, 0, 101, 0...}
                               2         : {114, 0, 101, 0...}
                               3         : {97, 0, 117, 0...}
                               4         : {97, 0, 117, 0...}
.vcex                          MRUListEx : {0, 0, 0, 0...}
                               0         : {67, 0, 111, 0...}
```
-	With the * we can see the types of files/ information that was recently viewed.
```
PS C:\> Get-Item 'Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt' 
    Hive: \HKEY_USERS\S-1-5-21-1584283910-3275287195-1754958050-1005\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
Name                           Property
----                           --------
.txt                           0         : {114, 0, 101, 0...}
                               MRUListEx : {4, 0, 0, 0...}
                               1         : {114, 0, 101, 0...}
                               2         : {114, 0, 101, 0...}
                               3         : {97, 0, 117, 0...}
```
	With .txt we can see the text files/ information that was recently viewed. Queries the Hex Value Stored in the Key

This command will allow you to read some of the data stored within the keys:

**Converting a Single Value from Hex to Unicode**
```
[System.Text.Encoding]::Unicode.GetString((gp "REGISTRY::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt")."0") 
recent1.txt b2     敲散瑮⸱湬kH	뻯    .              recent1.lnk

	Shows the text file represented by 0, you can change number to veiw the rest of the files
```

**Convert all of a users values from HEX to Unicode**
```
[System.Text.Encoding]::Unicode.GetString((gp "REGISTRY::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt")."0")
recent1.txt b2     敲散瑮⸱湬kH	뻯    .              recent1.lnk 

PS C:\> Get-Item "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" | select -Expand property | ForEach-Object {
    [System.Text.Encoding]::Default.GetString((Get-ItemProperty -Path "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" -Name $_).$_)
}   
r e c e n t 1 . t x t   b 2           recent1.lnk H 	  ï¾        .                             r e c e n t 1 . l n k   
                ÿÿÿÿ
r e c e n t 2 . t x t   b 2           recent2.lnk H 	  ï¾        .                             r e c e n t 2 . l n k   
r e c e n t 3 . t x t   b 2           recent3.lnk H 	  ï¾        .                             r e c e n t 3 . l n k   
a u d i t i n g . t x t   f 2           auditing.lnk  J 	  ï¾        .                             a u d i t i n g . l n k   
a u d i t . t x t   \ 2           audit.lnk D 	  ï¾        .                             a u d i t . l n k
(Change/manipulate the extensions -.txt- to different extensions to view different sets of information)
```
-	Shows and converts all of the text files located in the Recent Files Registry location

# Browser Artifacts

Stores details for each user account. Records number of times a site is visited (frequency). History will record the access to the file on the website that was accessed via a link. Many sites in history will list the files that were opened from remote sites and downloaded to the local system.

## Location

**Win7/8/10:**
```
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\history
```

**Q: Does anyone know what type of files are stored here?**

**Q: How might we view information from these files if we don’t have SQLlite Viewer installed?**

   - Show Location in Explorer so students have a visual reference of where they’re pulling this information from.

**Location**: `C:\Users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\`

The location is different for every browser.

**Areas of interest in Google Chrome History Files:**

**1. URLS**
The urls table contains the basic browsing history for Chrome. This will include a single instance for all the URLs visited, a timestamp for the last time visited, and a counter for the number of times visited.

**2. Current Session/Tabs**
If you are examining a system that still has an active session available, Chrome will store the browsing activity here under current session and if there are multiple tabs open it will store it under current tabs.

**3. Top Sites**
Chrome shows the user their most frequently visited sites in panels on a homepage, which allows the user to quickly click on a frequently visited site. We recover the data around any URL that is listed as a “Top Site” in Chrome.

## Demo

	For demo purposes, open some browsers before class and navigate to a few sites so you have can content to show during your demonstrations.

**Location of the SQL Lite Text Files**
```
# Frequency
PS C:\> Z:\strings.exe 'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\History' -accepteula 
_Output_Truncated_
https://git.cybbh.space/users/sign_in
https://git.cybbh.space/users/auth/ldapmain/callback
https://git.cybbh.space/os/public/-/jobs/artifacts/master/file/os/modules/015_windows_sysinternals/pages/15_SysInternals_winSlides.html?job=generate_adoc-slides
https://git.cybbh.space/os/public/-/jobs/artifacts/master/file/os/modules/014_windows_ad/pages/12_BloodHound_Slides.html?job=generate_adoc-slides
https://git.cybbh.space/os/public/-/jobs/artifacts/master/file/os/modules/011_win_logging/pages/8_Win_Auditing_Logging.html?job=generate_adoc-slides+
_Output_Truncated_

# Most Visited
PS C:\> Z:\strings.exe 'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\Top Sites' 
_Output_Truncated_
Fox News - Breaking News Updates | Latest News Headlines | Photos & News Videos
http://10.50.24.186:8000/themes/core/static/cyberchef.htm
https://github.com/volatilityfoundation/volatility/wiki/Command-Reference
http://172.20.25.182:8000/
http://cyberchef.com/
https://www.target.com/
http://vta.cybbh.space/
http://www.yahoo.com/
_Output_Truncated_

# User Names
PS C:\> Z:\strings.exe  'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\Login Data' 
_Output_Truncated_
http://172.20.25.182:8000/ctfadmin
https://git.cybbh.space/<USERNAME>
d9Q
https://vta.cybbh.space/<USERNAME>
https://login.yahoo.com/<USERNAME>
http://172.20.25.182:8000/ctfadmin
https://git.cybbh.space/<USERNAME>
https://vta.cybbh.space/
_Output_Truncated_
```
Alternatively the Select-String cmdlet can be used if Sysinternals is not available.

-	The output includes the Links that were "clicked" on while on a site
-	The output includes the sites most visited
-	The output includes sites that captured where user credentials were entered

**Find FQDNs in Sqlite Text files**
```
$History = (Get-Content 'C:\users\student\AppData\Local\Google\Chrome\User Data\Default\History') -replace "[^a-zA-Z0-9\.\:\/]","" 

PS C:\> $History| Select-String -Pattern "(https|http):\/\/[a-zA-Z_0-9]+\.\w+[\.]?\w+" -AllMatches|foreach {$_.Matches.Groups[0].Value}| ft 
http://172.20.25
https://login.yahoo.com
https://os.cybbh.io
https://git.cybbh.space
http://172.20.25
_Output_Truncated_
```
-	Create a Variable to pull all contents from the Browswer History file
-	Output is cleaned up to only show the URLs

# Auditing

## Intro

The Auditing Windows portion of this FG covers the concept of Windows Auditing using native tools along with the analysis of generated artifacts using cmd, powershell, or the GUI based program Eventviewer.
	
Run all the Auditing Demos on the Admin-Station. Make sure to exit your pssession from Workstation2.

**Q: Why is auditing Windows systems important?**

## Demo

Enable auditing on a text file

   - Create a text file on the Desktop
```
PS C:\Users\andy.dwyer\Desktop\Audit> new-item C:\Users\andy.dwyer\Desktop\Auditing.txt
    Directory: C:\Users\andy.dwyer\Desktop
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/7/2021   2:45 PM              0 Auditing.txt
```
   - Add content to the file then show the contents
```
PS C:\Users\andy.dwyer\Desktop\Audit> set-content C:\Users\andy.dwyer\Desktop\Auditing.txt "This is the file for Auditing"

PS C:\Users\andy.dwyer\Desktop\Audit> get-content C:\Users\andy.dwyer\Desktop\Auditing.txt
This is the file for Auditing
```
   - Set audit policy to Full Control for the "User Name" object
```
Rt click <file> on the desktop > Properties > Security > Advanced > Auditing > Continue > Add > Select a Principle > Type <username> (andy.dwyer) > Check Names > Ok >  Full Control > Ok > Apply > Ok
```
   - Double click the file in Explorer, view that no auditing happened

   - In Event Viewer, observe no log was created ( eventvwr )
```
eventvwr 
> Windows Logs > Security
```
Opens Event Viewer GUI

**Enable the Audit Object Access**
```
PS C:\Users\andy.dwyer> auditpol /get /category:* 
System audit policy
Category/Subcategory                      Setting
System
  Security System Extension               No Auditing
  System Integrity                        Success and Failure
  IPsec Driver                            No Auditing
  Other System Events                     Success and Failure
  Security State Change                   Success
Logon/Logoff
  Logon                                   Success and Failure
  Logoff                                  Success
  Account Lockout                         Success
_output_truncated_
```
**Shows all of the Audit Policy settings**
```
PS C:\Users\andy.dwyer> auditpol /get /category:"Object Access" 
System audit policy
Category/Subcategory                      Setting
Object Access
  File System                             No Auditing
  Registry                                No Auditing
  Kernel Object                           No Auditing
  SAM                                     No Auditing
  Certification Services                  No Auditing
_output_truncated_
```
**Shows all of the Object Access Subcategory settings**
```
PS C:\Users\andy.dwyer> auditpol /get /subcategory:"File System" 
System audit policy
Category/Subcategory                      Setting
Object Access
  File System                             No Auditing
```

**Shows the File System subcategory setting**
```
PS C:\Users\andy.dwyer> auditpol /set /subcategory:"File System" 
The command was successfully executed.
PS C:\Users\andy.dwyer> auditpol /get /subcategory:"File System" 
System audit policy
Category/Subcategory                      Setting
Object Access
  File System                             Success
```
**Sets the File System subcategory (2) Show that the File System setting changed**

   - Open the .txt file again, and open Event Viewer to show that there is an entry in the Security log

Change the settings back to default
```
PS C:\Users\andy.dwyer> auditpol /set /subcategory:"File System" /success:disable
The command was successfully executed.
PS C:\Users\andy.dwyer>
```

# Event Logs

Logs are records of events that happen in your computer, such as when a user logs on to the computer or when a program encounters an error. Users might find the details in event logs helpful when troubleshooting problems with Windows and other programs. They also help you track what happened.

Early windows editions, starting with Windows NT, came with three Windows logs: Application event log, System event log and Security event log. Modern versions of Windows come with more than a hundred of Windows eventlogs, and third party applications can create and integrate into Windows logging their own event logs.

**Q: What type of information is logged in the Application Log?**

**Q: What type of information is logged in the Security Log?**

**Q: What type of information is logged in the System Log?**

## Locations

`*.evtx` files accessed by:

   - Windows Event View Application

   - `Get-Eventlog` or `Get-WinEvent` in Powershell

   - `wevtutil` in Command Prompt

## Demo

#### DEMO: Enable Auditing of a file

   - Create a .txt file in C:\Users\"User Name\Desktop

   - Add content to the file

   - Set audit policy to Full Control for the "User Name" object

   - Double click the file in Explorer, view that no auditing happened

   - In Event Viewer, observe no log was created

   - Enable the Audit Object Access
```
C:\windows\system32>auditpol /get /category:"Object Access" 
System audit policy
Category/Subcategory                      Setting
Object Access
  File System                             No Auditing
  Registry                                No Auditing
  Kernel Object                           No Auditing
  SAM                                     No Auditing
  Certification Services                  No Auditing
  Application Generated                   No Auditing

C:\windows\system32>auditpol /set /subcategory:"File System" 
The command was successfully executed.

C:\windows\system32>auditpol /get /category:"Object Access"
System audit policy
Category/Subcategory                      Setting
Object Access
  File System                             Success
  Registry                                No Auditing
  Kernel Object                           No Auditing

C:\windows\system32>auditpol /set /subcategory:"File System" /success:disable 
The command was successfully executed.
```
-	Shows the status of the subcategories in the Object Access category
-	Sets the File System subcategory to audit "Success"
-	Sets the File System subcategory back to "No Auditing"

   - Open the .txt file again, and open Event Viewer to see the Security log

**Command Prompt: Checking System Wide Auditing Policy for all objects**
```
 auditpol /get /category:* 
```
- Shows a list of all the Audit Policy categories and cooresponding subcategories and their current settings. Run command and show the different Categories/Subcategories.

**Viewing Logs in Command Prompt**
```
C:\windows\system32>wevtutil el 

C:\windows\system32>wevtutil el | find /c /v "" 
1149

C:\windows\system32>wevtutil gli security 
creationTime: 2019-01-03T22:39:36.602Z
lastAccessTime: 2021-03-15T15:47:53.735Z
lastWriteTime: 2021-03-15T15:47:53.735Z
fileSize: 15798272
attributes: 32
numberOfLogRecords: 17595
oldestRecordNumber: 1

C:\windows\system32>wevtutil qe security /c:3 /f:text 
Event[0]:
  Log Name: Security
  Source: Microsoft-Windows-Eventlog
  Date: 2019-01-03T20:22:38.227
  Event ID: 1102

_Output_Truncated_
```
-	Use `wevtutil` (Windows Event Utility) to show all logs available to the command prompt tool using `el` (enumerate logs)
-	Shows the number of Windows logs, you can use find with \c to count the lines containing the following string \v to invert the following string "" (a null string)
-	Shows the Security Log information
-	Shows the last 3 events with qe (query event) from the security log and view in human readable format.

**View Event Logs in Powershell**
```
PS C:\> Get-EventLog -LogName System -Newest 10 
   Index Time          EntryType   Source                 InstanceID Message
   ----- ----          ---------   ------                 ---------- -------
    1102 Mar 15 12:00  Information EventLog               2147489661 The system uptime is 2750871 seconds.
    1101 Mar 14 12:00  Information EventLog               2147489661 The system uptime is 2664471 seconds.
    1100 Mar 13 23:52  Information Microsoft-Windows...   16 The description for Event ID '16' in Source 'Microsoft-Windows-Kernel-Gen...
    1099 Mar 13 23:52  Information Microsoft-Windows...   16 The description for Event ID '16' in Source 'Microsoft-Windows-Kernel-Gen...
    1098 Mar 13 12:00  Information EventLog               2147489661 The system uptime is 2578071 seconds.
    1097 Mar 12 21:52  Information Microsoft-Windows...   16 The description for Event ID '16' in Source 'Microsoft-Windows-Kernel-Gen...
    1096 Mar 12 21:52  Information Microsoft-Windows...   16 The description for Event ID '16' in Source 'Microsoft-Windows-Kernel-Gen...
    1095 Mar 12 12:00  Information EventLog               2147489661 The system uptime is 2491671 seconds.
    1094 Mar 11 20:58  Error       DCOM                   10016 The description for Event ID '10016' in Source 'DCOM' cannot be found.  T...
    1093 Mar 11 18:27  Information Microsoft-Windows...   16 The description for Event ID '16' in Source 'Microsoft-Windows-Kernel-Gen...

PS C:\> Get-EventLog -LogName System -Newest 3 | Format-Table -Wrap 
   Index Time          EntryType   Source                 InstanceID Message
   ----- ----          ---------   ------                 ---------- -------
    1102 Mar 15 12:00  Information EventLog               2147489661 The system uptime is 2750871 seconds.
    1101 Mar 14 12:00  Information EventLog               2147489661 The system uptime is 2664471 seconds.
    1100 Mar 13 23:52  Information Microsoft-Windows-Ke   16 The description for Event ID '16' in Source
                                   rnel-General           'Microsoft-Windows-Kernel-General' cannot be found.  The local computer may not have the necessary registry information or message DLL files to display the message, or you may not have permission to access them. The following  information is part of the event:'119', '\??\C:\windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\State\dosvcState.dat', '4', '1'
```
-	Shows the newest/last 10 entries in the system log. Point out what the three dots (…​) mean and how to print the rest of the entry. (ex. | format-table -wrap)
-	Add the `format-table -wrap` option to print the truncated part of the entry.

**Search the Security Event Log and show the entire message**
```
PS C:\> Get-Eventlog -LogName Security | ft -wrap 
```
-	This is all of the information currently in the Security log. Point out the abundance of information that would need to be parsed through.

**Search through the entire Security log for a specific string**
```
PS C:\> Get-Eventlog -LogName Security | ft -wrap | findstr /i StR1nG 
```
-	Explain that you search through all of the log entries using `findstr` or `select-string` for specific strings, the biggest difference between the two is that `findstr` has a case insensitive option — `findstr /i <string>`

`Get-EventLog` is limited to the default Windows Logs of Security, Application, System,and Windows Powershell (Windows 8.1 and up)

`Get-Winevent` will cover all the default eventlogs and all of the remaining custom application logs

**Finding Log Type to Query**
```
PS C:\> Get-WinEvent -Listlog * 
LogMode   MaximumSizeInBytes RecordCount LogName
-------   ------------------ ----------- -------
Circular            20971520         993 Application
Circular            20971520           0 HardwareEvents
Circular             1052672           0 Internet Explorer
Circular            20971520           0 Key Management Service
Circular            20971520       17711 Security
Circular            20971520         576 System
Circular            15728640         176 Windows PowerShell
Circular            20971520             ForwardedEvents
Circular            10485760           0 Microsoft-AppV-Client/Admin
_Output_Trucncated_

PS C:\> (Get-WinEvent -Listlog *).count 
426

PS C:\> Get-WinEvent -Listlog * | findstr /i "Security" 
Circular            20971520       18179 Security
Circular             1052672           0 Microsoft-Windows-Security-Adminless/Operational
Circular             1052672           0 Microsoft-Windows-Security-Audit-Configuration-Client/Operational
Circular             1052672           0 Microsoft-Windows-Security-EnterpriseData-FileRevocationManager/Operational
Circular             1052672             Microsoft-Windows-Security-ExchangeActiveSyncProvisioning/Operational
Circular             1052672             Microsoft-Windows-Security-IdentityListener/Operational
_Output_Truncated_
```
-	Lists all of the logs available to `Winevent`
-	Shows the number of logs, point out the volume of possible information
-	Search through the list of logs to find logs that pertain to Security

**Checking If a User Logged on**
```
PS C:\> Get-Winevent -FilterHashtable @{logname='Security';id='4624'} | ft -Wrap 
   ProviderName: Microsoft-Windows-Security-Auditing
TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------                                    3/15/2021 7:42:19 PM          4624 Information      An account was successfully logged on.                                                        Subject:
                                                    	Security ID:		S-1-5-18
                                                    	Account Name:		ADMIN-STATION$
                                                    	Account Domain:		WORKGROUP
                                                    	Logon ID:		0x3E7
                                                    Logon Information:
                                                    	Logon Type:		5
                                                    	Restricted Admin Mode:	-
                                                    	Virtual Account:	No
                                                    	Elevated Token:		Yes
                                                    Impersonation Level:	Impersonation
                                                    New Logon:
                                                    	Security ID:		S-1-5-18
                                                    	Account Name:		SYSTEM
                                                    	Account Domain:		NT AUTHORITY
                                                    	Logon ID:		0x3E7
                                                    	Linked Logon ID:	0x0
                                                    	Network Account Name:	-
                                                    	Network Account Domain:	-
                                                    	Logon GUID:             {00000000-0000-0000-0000-000000000000}
_Output_Truncated_

PS C:\> Get-Winevent -FilterHashtable @{logname='Security';id='4624'} | ft -Wrap | findstr /i "generated" 
```
-	Using `Get-WinEvent` with `-FilterHashtable` allows you to filter for more than one criteria. In this instance filter for the Security log and the id of 4624 (discussed below).
-	Same command as above with a specific string search using `findstr /i`.

**Checking Powershell Operational Logs**
```
PS C:\> Get-WinEvent Microsoft-Windows-PowerShell/Operational | Where-Object {$_.Message -ilike "*RunspacePool*"} | Format-List 
TimeCreated  : 3/8/2021 7:28:43 PM
ProviderName : Microsoft-Windows-PowerShell
Id           : 8195
Message      : Opening RunspacePool

TimeCreated  : 3/8/2021 7:28:43 PM
ProviderName : Microsoft-Windows-PowerShell
Id           : 8194
Message      : Creating RunspacePool object
                	 InstanceId 18bed982-3d17-47b0-8f7a-0836900efea6
                	 MinRunspaces 1
                	 MaxRunspaces 1
_Output_Truncated_

Get-WinEvent Microsoft-Windows-PowerShell/Operational | Where-Object {$_.Message -ilike "*Pipeline ID = ##"} | Format-List 
```
-	Output shows searching through PowerShell Operational logs for a specific string.
-	Command used to search through PowerShell Operational logs for a specific Pipeline ID.

**Sample Event IDs to search for for malicious actors in your network**
| | ID | Level | Event Log |
|---|---|---|---|
| Account Lockouts | 4740 | Informational | Security |
| User Added to Privileged Group | 4728, 4732, 4756 | Informational | Security |
| Security-Enabled group Modification | 4735 | Informational | Security |
| Successful User Account Login | 4624 | Informational | Security |
| Failed User Account Login | 4625 | Informational | Security |
| Account Login with Explicit Credentials | 4648 | Informational | Security |
| Event Log was Cleared | 104 | | |
| Audit Log was Cleared | 1102 | | Security |
| System audit policy was changed | 4719 | | |	
| PS Module Logging (Command Execution) | 4103 | | |	
| PS Script-Block Logging (Script Execution) | 4104,4105,4106 | | |

[A more inclusive list of Windows Security Log Events](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/Default.aspx)

# PowerShell Artifacts

## PowerShell Transcripts

PowerShell Transcript is a feature that creates a record of all or part of a PowerShell session to a text file.
```
PS C:\> Start-Transcript 
Transcript started, output file is C:\Users\andy.dwyer\Documents\PowerShell_transcript.ADMIN-STATION.OGp3Fa
x7.20210316141734.txt
```
   - Creates a text file and records part of all of a PowerShell session.

You may specify the directory or path where you want to store the transcript by using the -Path parameter, by default it goes to the Documents folder of the user that enabled the transcript.

[Start-Transcript Documentation](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.host/start-transcript?view=powershell-6#syntax)

**Q: Is there a way to bypass this security feature?**

   - Short answer, Yes. If you open `cmd.exe` and then run PowerShell from within that session the Transcript will log nothing since it’s not a normal PowerShell session.

   - However, `Start-Transcript` can still be run to create a log of the session from which it is created from.

## Powershell History

Powershell history is a record of every command entered during a Powershell Session.
```
PS C:\> Get-History 
  Id CommandLine
  -- -----------
   1 Get-PSDrive
   2 get-process | select name,id,Description | sort -Property id
   3 regedit
   4 cls
_Output_Truncated_
```
	
   - Shows all of the commands entered during the current session.

#### Location:
```
C:\Users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

Use `Get-Content` to access the the history

```
PS C:\> Get-Content "C:\users\$env:username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" 
Get-CimInstance Namespace root\securitycenter2 ClassName antispywareproduct
Get-CimInstance -Namespace root\securitycenter2 -ClassName antispywareproduct
hostname
whoami
exit
get-process
_Output_Truncated_
```

-	Prints the contents of the history file

[Get-History Documentation](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-history?view=powershell-6)

## Powershell Script Block Logging

Script block logging records blocks of code as they are executed by the PowerShell engine, thereby capturing the full contents of code executed by an attacker, including scripts and commands. Due to the nature of script block logging, it also records de-obfuscated code as it is executed.

**What logs are generated by PowerShell?**

By default no logs are generated by PowerShell. This is dangerous since this basically means any actions in PowerShell have no trail to follow. By default a few of the more powerful features of Windows and PowerShell are turned off, but let’s discuss what each one means and how to use them to our advantage in defense of our machines.

   - "A PowerShell “script block” is the base level of executable code in PowerShell. It might represent a command typed interactively in the PowerShell console, supplied through the command line, or wrapped in a function, script, workflow, etc."

   - Script block logging doesn’t just look at the code that was supplied via the console or scripts that have been ran, but what the PowerShell engine actually runs.

   - This feature will show any obfuscated commands (i.e. Base64, Rot 13 or CaSe InSenSiTive StRingS, etc) as well as the decoded input that the PowerShell engine runs.

   - While not available in PowerShell 4.0, PowerShell 5.0 will automatically log code blocks if the block’s contents match on a list of suspicious commands or scripting techniques, even if script block logging is not enabled.

**Q: How do I enable Script Block logging?**
```
reg add HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\ /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```
   - **4103** is Verbose powershell command execution enabled via Script Block Logging.

   - **4104** show the actual scripts ran, the encoded and decodes versions. If it was a file it will show the files name run then another even will have the script within that file

   - **4105** is the time a script started aka the PowerShell engine was started

   - **4106** is the time a script ended aka the PowerShell engine was stopped

[Script Block Logging](https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html)
