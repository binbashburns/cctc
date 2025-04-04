# Intro to Memory Forensics

Memory forensics is a vital form of cyber investigation that allows an investigator to identify unauthorized and anomalous activity on a target computer or server. This is usually achieved by running special software that captures the current state of the system’s memory as a snapshot file, also known as a memory dump. Which an investigator can check both on and off site.

## What is Memory Forensics?

Memory forensics (also known as memory analysis) refers to the analysis of volatile data in a computer’s memory. Information security professionals conduct memory forensics to investigate and identify attacks or malicious behaviors that do not leave detectable tracks on hard drive data.


## Types of Memory

Table 1. Types of Memory
|Memory Type | Description|
|---|---|
|Volatile Memory |   Non-persistent - requires power to maintain stored information; immediate loss of data after power loss. Examples: RAM|
|Non-Volatile Memory| Persistent - Does not require a continuous power supply to retain the dta stored in a computing device.    Examples: HDD, USB|

## Importance of Memory Forensics

Memory forensics can provide unique insights into runtime system activity, including open network connections and recently executed commands or processes. Often, critical data of attacks or threats will exist solely in system memory – examples include network connections, account credentials, chat messages, encryption keys, running processes, injected code fragments, and internet history which is non-cacheable. Memory contains any executable program – malicious or otherwise – making memory forensics critical for identifying otherwise obfuscated attacks.

   - Data that has not stored on a disk is present in [memory](https://arstechnica.com/information-technology/2017/02/a-rash-of-invisible-fileless-malware-is-infecting-banks-around-the-globe/)

   - Deleted files or modified can be [scraped](https://www.wired.com/2014/09/ram-scrapers-how-they-work/) from RAM and used as evidence or for timelining an attack.

**Examples:**

   - Bash history writes to ~/.bash_history once the terminal session ends, but each command that has been ran during the current terminal session resides in RAM and can be viewed using the bash plugin

   - If a user deletes ~/.bash_history , recovery of data is still possible.

   - Volatility reads deleted or modified logs and scraped from memory using the `mfind`, `mcat` & `mls` plugins.

## Order of Volatility "The Half-life of Data"

The order of volatility denotes how quickly various types of data disappear from the system.

**Order of Volatility From Most to Least**

   - CPU registers, cache

   - Routing table, ARP cache, process table, kernel stats, memory

   - Temporary file systems

   - Disk

   - Remote logging and monitoring data

   - Physical configuration, network topology

   - Archival media - backups

**Resources**

   - [RFC 3227 - 2.1 Order of Volatility](https://tools.ietf.org/html/rfc3227#section-2.1)

# Volatility Framework

    In 2007, the first version of The Volatility Framework was released publicly at Black Hat DC. The software was based on years of published academic research into advanced memory analysis and forensics. Up until that point, digital investigations had focused primarily on finding contraband within hard drive images. Volatility introduced people to the power of analyzing the runtime state of a system using the data found in volatile storage (RAM). It also provided a cross-platform, modular, and extensible platform to encourage further work into this exciting area of research. Another major goal of the project was to encourage the collaboration, innovation, and accessibility to knowledge that had been common within the offensive software communities.

    Since that time, memory analysis has become one of the most important topics to the future of digital investigations and Volatility has become the world’s most widely-used memory forensics platform. The project is supported by one of the largest and most active communities in the forensics industry. Volatility also provides a unique platform that enables cutting edge research to be immediately transitioned into the hands of digital investigators. As a result, research built on top of Volatility has appeared at top academic conferences, and Volatility has been used on some of the most critical investigations of the past decade. It has become an indispensable digital investigation tool relied upon by law enforcement, military, academia, and commercial investigators throughout the world. 

— 2020 The Volatility Foundation
About The Volatility Foundation

## Overview

Volatility is an open source memory analysis tool for Linux, Windows, Mac, and Android systems. It is based on Python and can be run on most current operating systems. It analyzes man file types including: raw dumps, crash dumps, VMware dumps (.vmem), virtual box dumps, and many others.

   - Memory Analysis framework

   - Each operating system has its own memory acquisition tool called Persistent Memory (pmem)

       - Linpmem

       - Winpmem

       - OSXpmem

## Volatility versions

There is a Python version of Volatility as well as a **Standalone** binary version. The table below provides pros and cons to use either version.

Table 2. Versions-at-a-glance

|Version | Pros | Cons|
|---|---|---|
|Python | Updated Frequently. All profiles available. | Lengthy Install. Can’t run without Python installed.|
|Standlone | No install necessary. Quick and easy to download/run. Can run without python. | Not all profiles included. Not updated frequently|

## Understanding Profiles
	
In order for Volatility to work, it needs to know what type of system your memory dump came from, so it knows which data structures, algorithms, and symbols to use. In other words, what profile to use.

   - What is a profile?

       - A Profile provides Volatility with a memory layout based on the kernel of the machine upon which it’s created. This ensures Volatility is able to parse the memory image and return expected data when given a command

       - Volatility hosts a profile repository with most known Windows builds; however, their Linux profile selection is lacking

# Using Volatility

There are also steps for installing Notepad++ used to for the regex search/find feature when conducting analysis of memory files.

**1. Download Notepad++ (accept default settings)**
```
PS C:\windows\system32> invoke-webrequest -uri "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v7.8.8/npp.7.8.8.Installer.x64.exe" -outfile "C:\npp.7.8.8.Installer.x64.exe" 

PS C:\windows\system32> cd C:\ 

PS C:\> start-process npp.7.8.8.Installer.x64.exe -ArgumentList '/S' 
```
-	`invoke-webrequest` downloads Notepad++ 7.8.8 installer to `C:\`
-	cd to `C:\`
-	`start-process` to launch `Notepad++ 7.8.8 installer` and accept defaults

**2. These files should be on Public’s desktop in the Memory folder**

   - **infected.zip** has the `0zapftis.vmem` file used later for the Memory Analysis challenges.

   - **memdump.zip** has `cridex.vmem` file used for the Volatility demo.

   - **vol_cheatsheet.pdf** is a SAN’s cheat sheet providing different use cases and command syntax for the Volatility tool.

   - **vol_standalone** contains the executable and basic docs for standalone version of Volatility used for demo and Memory Analysis challenges.

**3. In case the volatility framework standalone.exe does not work correctly**

   - Download the correlated version that is being used in this FG
```
invoke-webrequest -uri "http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6.win.standalone.zip" -outfile "C:\Users\andy.dwyer\Desktop\Memory_Analysis\volatility_2.6_win64_standalone.zip"
```
   - Extract the zip file content in the Memory Analysis folder
```
Expand-Archive "C:\Users\andy.dwyer\Desktop\Memory_Analysis/volatility_2.6_win64_standalone.zip" "C:\Users\andy.dwyer\Desktop\Memory_Analysis\volatility_2.6_win64_standalone"
```
   - Next move the .exe file to the Memory Analysis folder for FG consistency.
```
mv "C:\Users\andy.dwyer\Desktop\Memory_Analysis\volatility_2.6_win64_standalone\volatility_2.6_win64_standalone.exe" "C:\Users\andy.dwyer\Desktop\Memory_Analysis\volatility_2.6_win64_standalone.exe"
```

**4. Extract Volatility to the Memory Analysis Folder**

   - `Expand-Archive 'C:\Users\Public\Desktop\Memory\vol_standalone.zip' "$HOME\Desktop\Memory_Analysis" -Force`

       - **volatility_2.6_win64_standalone.exe** is the executable

   - Open a command prompt or PowerShell terminal and cd to the directory where the executable was unzipped.

   - Move the executable one directory up to make life easier
```
cd 'C:\Users\andy.dwyer\Desktop\Memory_Analysis\volatility_2.6_win64_standalone\'

move-item 'C:\Users\andy.dwyer\Desktop\Memory_Analysis\volatility_2.6_win64_standalone\volatility_2.6_win64_standalone.exe' ..

cd ..
```
**5. Extract Memdump to Memory Analysis Folder**
```
Expand-Archive 'C:\Users\Public\Desktop\memdump.zip' "$HOME\Desktop\Memory_Analysis" -Force
```
Demonstrations below show help info, basic Volatility command syntax, and covers a few plugins of the Volatility tool for performing memory forensics.
	
It is common to see red error messages during the runs of the Volatility command in PowerShell. The commands ran should work in most cases.
	
Analysis can be made easier by redirecting output of plugin commands to a text file and parsed further using the advance search function native to Notepad++ which include features such as searching by Regular expression, find all in current or all documents, as well as the results pane at the bottom.
	
Open vol_cheatsheet.pdf to use as a guide/reference when hunting for specific memory artifacts.

**List all modules available to Volatility**
```
PS C:\Users\andy.dwyer\Desktop\Memory_Analysis> .\volatility_2.6_win64_standalone.exe -h 
```
-	`-h` or `--help` will list options and supported plugin commands for Volatility

**Basic Volatility command syntax**
```
PS C:\Users\andy.dwyer\Desktop\Memory_Analysis> .\volatility_2.6_win64_standalone.exe -f <FILENAME> --profile=<PROFILE> <PLUGIN> 
```
-	At a minimum, the **Volatility executable** followed by a **filename** (`-f`), **profile**(`--profile=`), and plugin should be used when working with a memory image/dump.

**Plugin: Imageinfo (always use first)**
```
PS C:\Users\andy.dwyer\Desktop\Memory_Analysis> .\volatility_2.6_win64_standalone.exe -f ".\cridex.vmem" imageinfo 
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86) 
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (C:\Users\andy.dwyer\Desktop\Memory_Analysis\cridex.vmem)
                      PAE type : PAE
                           DTB : 0x2fe000L
                          KDBG : 0x80545ae0L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2012-07-22 02:45:08 UTC+0000
     Image local date and time : 2012-07-21 22:45:08 -0400
```
-	`imageinfo` plugin used to determine profile to use for **cridex.vmem**.
-	From the **Suggested Profile(s)** : line we will reference **WinXPSP2x86** as our profile going forward.

The `imageinfo` plugin is an essential first step for performing proper memory analysis with other Volatility plugins.

**Volatility syntax to list available plugins for a given profile**
```
PS C:\Users\andy.dwyer\Desktop\Memory_Analysis> .\volatility_2.6_win64_standalone.exe -f ".\cridex.vmem" --profile=WinXPSP2x86 -h 
```
-	`help` (-h) syntax to list plugins available for the profile `WinXPSP2x86` (--profile=WinXPSP2x86)
	
While PowerShell is case insensitive, Volatility is not. Ensure <PROFILE> is typed as seen from previous imageinfo output

# Volatility Plugins

## pslist plugin

**Plugin: pslist**
```
PS C:\Users\andy.dwyer\Desktop\Memory_Analysis> .\volatility_2.6_win64_standalone.exe -f ".\cridex.vmem" --profile=WinXPSP2x86 pslist 
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x823c89c8 System                    4      0     53      240 ------      0
0x822f1020 smss.exe                368      4      3       19 ------      0 2012-07-22 02:42:31 UTC+0000
0x822a0598 csrss.exe               584    368      9      326      0      0 2012-07-22 02:42:32 UTC+0000
0x82298700 winlogon.exe            608    368     23      519      0      0 2012-07-22 02:42:32 UTC+0000
0x81e2ab28 services.exe            652    608     16      243      0      0 2012-07-22 02:42:32 UTC+0000
0x81e2a3b8 lsass.exe               664    608     24      330      0      0 2012-07-22 02:42:3g2 UTC+0000
0x82311360 svchost.exe             824    652     20      194      0      0 2012-07-22 02:42:33 UTC+0000
0x81e29ab8 svchost.exe             908    652      9      226      0      0 2012-07-22 02:42:33 UTC+0000
0x823001d0 svchost.exe            1004    652     64     1118      0      0 2012-07-22 02:42:33 UTC+0000
0x821dfda0 svchost.exe            1056    652      5       60      0      0 2012-07-22 02:42:33 UTC+0000
0x82295650 svchost.exe            1220    652     15      197      0      0 2012-07-22 02:42:35 UTC+0000
0x821dea70 explorer.exe           1484   1464     17      415      0      0 2012-07-22 02:42:36 UTC+0000
0x81eb17b8 spoolsv.exe            1512    652     14      113      0      0 2012-07-22 02:42:36 UTC+0000
0x81e7bda0 reader_sl.exe          1640   1484      5       39      0      0 2012-07-22 02:42:36 UTC+0000 
0x820e8da0 alg.exe                 788    652      7      104      0      0 2012-07-22 02:43:01 UTC+0000
0x821fcda0 wuauclt.exe            1136   1004      8      173      0      0 2012-07-22 02:43:46 UTC+0000
0x8205bda0 wuauclt.exe            1588   1004      5      132      0      0 2012-07-22 02:44:01 UTC+0000
```
-	`pslist` plugin provides a listing of current running processes.
-	Instructor will reference `reader_sl.exe` line for Q&A with students below.

**Description**:

   - The `pslist` plugin provides a listing of currently running processes. It makes use of virtual memory addressing and offsets. This should always be the first process listing plugin used from Volatility.

   - In simple terms the `pslist` plugin will print all running processes by following the PROCESS lists.

Q&A:

   - Q: Looking at the output of the previous command, does anything appear out of the ordinary? What correlation can you make with `reader_sl.exe` and `explorer.exe`?

   - A: `explorer.exe` is the parent of reader_sl.exe

## psscan plugin

**Plugin: psscan**
```
PS C:\Users\andy.dwyer\Desktop\Memory_Analysis> .\volatility_2.6_win64_standalone.exe -f ".\cridex.vmem" --profile=WinXPSP2x86 psscan 
Offset(P)          Name                PID   PPID PDB        Time created                   Time exited
------------------ ---------------- ------ ------ ---------- ------------------------------ ------------------------------
0x0000000002029ab8 svchost.exe         908    652 0x079400e0 2012-07-22 02:42:33 UTC+0000
0x000000000202a3b8 lsass.exe           664    608 0x079400a0 2012-07-22 02:42:32 UTC+0000
0x000000000202ab28 services.exe        652    608 0x07940080 2012-07-22 02:42:32 UTC+0000
0x000000000207bda0 reader_sl.exe      1640   1484 0x079401e0 2012-07-22 02:42:36 UTC+0000
0x00000000020b17b8 spoolsv.exe        1512    652 0x079401c0 2012-07-22 02:42:36 UTC+0000
0x000000000225bda0 wuauclt.exe        1588   1004 0x07940200 2012-07-22 02:44:01 UTC+0000
0x00000000022e8da0 alg.exe             788    652 0x07940140 2012-07-22 02:43:01 UTC+0000
0x00000000023dea70 explorer.exe       1484   1464 0x079401a0 2012-07-22 02:42:36 UTC+0000
0x00000000023dfda0 svchost.exe        1056    652 0x07940120 2012-07-22 02:42:33 UTC+0000
0x00000000023fcda0 wuauclt.exe        1136   1004 0x07940180 2012-07-22 02:43:46 UTC+0000
0x0000000002495650 svchost.exe        1220    652 0x07940160 2012-07-22 02:42:35 UTC+0000
0x0000000002498700 winlogon.exe        608    368 0x07940060 2012-07-22 02:42:32 UTC+0000
0x00000000024a0598 csrss.exe           584    368 0x07940040 2012-07-22 02:42:32 UTC+0000
0x00000000024f1020 smss.exe            368      4 0x07940020 2012-07-22 02:42:31 UTC+0000
0x00000000025001d0 svchost.exe        1004    652 0x07940100 2012-07-22 02:42:33 UTC+0000
0x0000000002511360 svchost.exe         824    652 0x079400c0 2012-07-22 02:42:33 UTC+0000
0x00000000025c89c8 System                4      0 0x002fe000
```
-	`psscan` plugin uses physical memory addresses and scans memory images for _EPPROCESS pool allocations.

**Description**:

   - The psscan plugin uses physical memory addressing and scans memory images for _EPROCESS pool allocations, in contrast to the pslist plugin that uses virtual memory addressing and scans for EPROCESS lists. The benefit of using this plugin is that sometimes it succeeds in listing processes that cannot be found using other process listing plugins (i.e, `pslist` and `pstree`)

   - This can find processes that **previously terminated (inactive)** and processes that have been **hidden or unlinked by a rootkit**

## pstree plugin

**Plugin: pstree**
```
PS C:\Users\andy.dwyer\Desktop\Memory_Analysis> .\volatility_2.6_win64_standalone.exe -f ".\cridex.vmem" --profile=WinXPSP2x86 pstree 
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0x823c89c8:System                                      4      0     53    240 1970-01-01 00:00:00 UTC+0000
. 0x822f1020:smss.exe                                 368      4      3     19 2012-07-22 02:42:31 UTC+0000
.. 0x82298700:winlogon.exe                            608    368     23    519 2012-07-22 02:42:32 UTC+0000
... 0x81e2ab28:services.exe                           652    608     16    243 2012-07-22 02:42:32 UTC+0000
.... 0x821dfda0:svchost.exe                          1056    652      5     60 2012-07-22 02:42:33 UTC+0000
.... 0x81eb17b8:spoolsv.exe                          1512    652     14    113 2012-07-22 02:42:36 UTC+0000
.... 0x81e29ab8:svchost.exe                           908    652      9    226 2012-07-22 02:42:33 UTC+0000
.... 0x823001d0:svchost.exe                          1004    652     64   1118 2012-07-22 02:42:33 UTC+0000
..... 0x8205bda0:wuauclt.exe                         1588   1004      5    132 2012-07-22 02:44:01 UTC+0000
..... 0x821fcda0:wuauclt.exe                         1136   1004      8    173 2012-07-22 02:43:46 UTC+0000
.... 0x82311360:svchost.exe                           824    652     20    194 2012-07-22 02:42:33 UTC+0000
.... 0x820e8da0:alg.exe                               788    652      7    104 2012-07-22 02:43:01 UTC+0000
.... 0x82295650:svchost.exe                          1220    652     15    197 2012-07-22 02:42:35 UTC+0000
... 0x81e2a3b8:lsass.exe                              664    608     24    330 2012-07-22 02:42:32 UTC+0000
.. 0x822a0598:csrss.exe                               584    368      9    326 2012-07-22 02:42:32 UTC+0000
 0x821dea70:explorer.exe                             1484   1464     17    415 2012-07-22 02:42:36 UTC+0000
. 0x81e7bda0:reader_sl.exe                           1640   1484      5     39 2012-07-22 02:42:36 UTC+0000 
```
-	`pstree` plugin takes output of pslist and presents it in a child-parent relationship.
-	`reader_sl.exe` and its Pid `1640` will referenced during upcoming procdump plugin demo.

**Description**:

   - This plugin takes the output of pslist and actually present them in child-parent relationship. Very useful plugin when the process listing is huge within the memory to see any suspicious relationship between child-parent.

   - To view the process listing in tree form, use the pstree command. This enumerates processes using the same technique as pslist.

   - We are interested in the reader_sl.exe executable. The Reader_sl.exe process is part of Adobe Acrobat SpeedLauncher of Adobe Systems

       - We will dump the executable `reader_sl.exe` (Pid: `1640`) for further investation.

4.4 procdump plugin

**Plugin: procdump**
```
PS C:\Users\andy.dwyer\Desktop\Memory_Analysis> Set-MpPreference -ExclusionPath 'C:\Users\andy.dwyer\Desktop\Memory_Analysis\' 

PS C:\Users\andy.dwyer\Desktop\Memory_Analysis> .\volatility_2.6_win64_standalone.exe -f ".\cridex.vmem" --profile=WinXPSP2x86 procdump -p 1640 -D . 
Process(V) ImageBase  Name                 Result
---------- ---------- -------------------- ------
0x81e7bda0 0x00400000 reader_sl.exe        OK: executable.1640.exe 

PS C:\Users\andy.dwyer\Desktop\Memory_Analysis> get-filehash .\executable.1640.exe 
Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          5B136147911B041F0126CE82DFD24C4E2C79553B65D3240ECEA2DCAB4452DCB5       C:\Users\andy.dwyer\Desktop\Memory_Analysis\executable.1640.exe
```

-   This will prevent Defender from quarantining the potential malware sample.
-	`procdump` plugin used to dump a process’s executable.
-	`executable.1640.exe` is executable now located in the current directory
-	get-filehash provides SHA256 hash of `executable.1640.exe` for copy and paste into [VirusTotal](https://www.virustotal.com/gui/home/search)

**Description**:

   - This plugin is used to dump a process’s executable for further analysis with tools like strings.exe from sysinternals or notepad++ regex functional search.

   - VirusTotal is used for Internet security, and as a file and URL analyzer. See ["How it Works"](https://support.virustotal.com/hc/en-us/articles/115002126889-How-it-works)

**Ask students**:

   - **Q**: Is it a good practice to submit executable to VirusTotal? Why or Why not?

   - **A**: No, submitting the file itself to VirusTotal can alert hackers of an ongoing investigation. Only submit file hashes to VirusTotal

**File Analysis (using filehash) with VirusTotal**

   - Copy filehash

   - Go to [VirusTotal](https://www.virustotal.com/gui/)

   - Click on Search

   - Paste filehash

## memdump plugin

**Plugin: memdump**
```
PS C:\Users\andy.dwyer\Desktop\Memory_Analysis> .\volatility_2.6_win64_standalone.exe -f ".\cridex.vmem" --profile=WinXPSP2x86 memdump -p 1640 -D . 
************************************************************************
Writing reader_sl.exe [1640] to 1640.dmp 

PS C:\Users\andy.dwyer\Desktop\Memory_Analysis> net use * \\live.sysinternals.com\tools 
Drive Z: is now connected to \\live.sysinternals.com\tools. 

The command completed successfully.

PS C:\Users\andy.dwyer\Desktop\Memory_Analysis> Z: 

PS Z:\> .\strings.exe -accepteula "C:\Users\andy.dwyer\Desktop\Memory_Analysis\1640.dmp" > "C:\Users\andy.dwyer\Desktop\Memory_Analysis\1640.txt" 
```
-	`memdump` used to extract all memory resident pages in process `1640` to an individual file.
-	`1640.dmp` is the memdump file created for previous command ran.
-	`net use` command to mount sysinternals tools
-	`Y` drive letter is used sysinternals tool. This may differ for each individual.
-	Switch to drive leter `Y:` containing our Sysinternals tools
-	Run `strings.exe` on memdump file `1640.dmp` and sends output to `1640.txt`

**Description**:

   - We can use memdump to extract all memory resident pages in a process (see memmap for details) into an individual file.

   - We will utilize the sysinternals tool "strings" to read the .dmp file.

**Notepad++ GUI**

   - Copy contents of the text file (1640.txt) to Notepad++ GUI

   - Click on Search → Find

   - Check Regular expression radial

   - Search for IP addresses using a one of the following basic regex syntax:
```
^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}$
^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$
```
   - Click Find All in Current Document and look Find result

**Plugin: connections**
```
PS C:\Users\andy.dwyer\Desktop\Memory_Analysis> .\volatility_2.6_win64_standalone.exe -f ".\cridex.vmem" --profile=WinXPSP2x86 connections 
Offset(V)  Local Address             Remote Address            Pid
---------- ------------------------- ------------------------- ---
0x81e87620 172.16.112.128:1038       41.168.5.140:8080         1484 
```
-	connections used to look for IP addresses and ultimately view TCP connections active at time of memory acquisition.
-	Reference line for Ask the students below.

**Description**:

   - Used to look for IP Addresses and ultimately view TCP connections that were active at the time of the memory acquisition, use the connections command

   - The connections plugin can be used to find evidence of both recently terminated and ongoing communications. It therefore makes sense to use this plugin as it may reveal additional network-based information. Moreover, this plugin supports both physical and virtual memory addresses.

**Ask the students**:

   - Q: What are the connections or IP Addresses? What can you infer?

   - A: A connection was made to IP 41.168.5.140:8080

## `connscan` plugin

**Plugin: connscan**
```
PS C:\Users\andy.dwyer\Desktop\Memory_Analysis> .\volatility_2.6_win64_standalone.exe -f ".\cridex.vmem" --profile=WinXPSP2x86 connscan 
Offset(P)  Local Address             Remote Address            Pid
---------- ------------------------- ------------------------- ---
0x02087620 172.16.112.128:1038       41.168.5.140:8080         1484
0x023a8008 172.16.112.128:1037       125.19.103.198:8080       1484 
```
-	`connscan` used to verify existence of ongoing network connections and scans mem images for current or recently terminated connections.

**Description**:

   - The first network-based Volatility plugin that should be used is connscan. It is used to verify the existence of ongoing network connections and scans a memory image for current or recently terminated connections. This plugin makes uses of physical memory addressing.

   - This can find artifacts from previous connections that have since been terminated, in addition to the active ones

**Ask the students**:

   - Q: What are these connections or IP Addresses? What can you infer?

   - A: Another IP (125.19.103.198) appears in this list meaning the second connection was closed.

# Volatility Methodology and Beyond

The SANS Institute recommends the following commands when using Volatility.

   - **Identify Rogue Processes**: Compare the output of `pslist` and `psscan`. While neither command presents results in a tree format, processes in memory follow a parent-child hierarchy, where each process has a Process ID (PID) and a Parent Process ID (PPID) linking it to the process that created it. Alternatively, the `pstree` plugin provides a structured tree view of process hierarchies, making it easier to spot anomalies in process relationships.

       - **Process validity** - look for things that are off (misspellings, high PIDs, multiples that shouldn’t be, etc.)

   - **DLLs and Handles**: `dlllist`, `dlldump`

   - **Network Artifacts**: `connections`

   - **Hunt for Code Injection**: `malfind`

   - **Check for rootkit**: `psscan`, `devicetree`

   - **Dump suspicious processes and drivers**: `dlldump`, `procdump`, `memdump`, `filescan`, `svcscan`, `driverirp`

## Registry Analysis

It is possible to read the registry from the box but a bit more involved. The list below shows plugins and options one may use within Volatility to achieve this.

   - `hivelist` - Shows addresses of hives and filesystem locations

   - `printkey`

       - use `-o` with the virtual offset to show subkeys

       - use `-K` with the location of the registry key you want on the filesystem (note double quotes with this method) "path\to\key"

   - `hivedump` - use `-o` with virtual offset to recursively list all subkeys

   - `hashdump` - may or may not work, depending

   - `dumpregistry` - Go nuclear. Dumps the whole registry to disk (requires `--dump-dir`)

Try other plugins to investigate other artifacts mentioned in earlier lectures. Run `help` in Volatility to see what plugins you have available for use.

# Resources

   - [About Volatility](https://www.volatilityfoundation.org/about)

   - [Install Python Version of Volatility on Windows](https://dfironthemountain.wordpress.com/2018/10/29/installing-volatility-on-windows/)

   - [Volatility 2.6 Standalone Executables](https://www.volatilityfoundation.org/26)

   - [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)

   - [Intro to Memory Forensics](https://www.youtube.com/watch?v=1PAGcPJFwbE&t=319s)

   - [Windows Memory Analysis](https://www.youtube.com/watch?v=gHbejxlPbRQ)

   - [Memory Layout Reading](https://manybutfinite.com/post/anatomy-of-a-program-in-memory/)

   - [GitHub Wiki on Volatility Installation](https://github.com/volatilityfoundation/volatility/wiki/Installation)

   - [What is a driver](https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/what-is-a-driver-)

