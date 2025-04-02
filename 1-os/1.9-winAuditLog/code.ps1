Get-LocalUser | Select name,sid

$a = Get-WinEvent -logname Security | Where-Object Id -eq '4624' | Select-Object -first 5

([xml]$a[3].ToXml()).Event.EventData.Data

# Check the powershell history for help on flags

# What Sysinternals tool will allow you to read the SQLite3 database containing the web history of chrome?
# strings.exe

# What is the registry location of recent docs for the current user?
# HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

# BAM settings are stored in different registry locations based on the version of Windows 10. What version of Windows 10 is workstation2 running? The answer is the 4 digit Windows 10 release (version) number.
hostname                                                                        
# Workstation2

Get-ComputerInfo | Select-Object windowsversion                                 
# WindowsVersion
# --------------
# 1803

# -----------------------------------------------
# Got two notifications 
# (Windows Browser Artifacts 2 Flag (Broken) https://www.exploit-db.com)
# (Windows BAM 2 (Broken)) C:\Windows\Temp\bad_intentions.exe
# -----------------------------------------------

# Figure out the last access time of the hosts file.
# Flag format: mm/dd/yyyy
Get-ChildItem C:\Windows\System32\drivers\etc\hosts | Select-Object LastAccessTime

# What is the literal path of the prefetch directory?
# C:\Windows\Prefetch

# In the Recycle Bin, there is a file that contains the actual contents of the recycled file. What are the first two characters of this filename?
Get-Childitem 'C:\$RECYCLE.BIN' -Recurse -Verbose -Force | select FullName
# couldn't figure these out, skipping for now

# What are the first 8 characters of the Globally Unique Identifier (GUID) used to list applications found in the UserAssist registry key (Windows 7 and later)?
# The UserAssist registry key tracks the GUI-based programs that were ran by a particular user.
# The GUID represents a particular file extension.
#    - CEBFF5CD-ACE2-4F4F-9178-9926F41749EA A list of applications, files, links, and other objects that have been accessed
#    - F4E57C4B-2036-45F0-A9AB-443BCFE33D9F Lists the Shortcut Links used to start programs

# What cipher method are UserAssist files encoded in?
# ROT13

# What main Windows log would show invalid login attempts?
# Filed User Account Login = 4625 (Informational, Security)

# What main Windows log will show whether Windows updates were applied recently?
# System

# When reading logs, you may notice ... at the end of the line where the message is truncated. What format-table switch/argument will display the entire output?
# -wrap

# There is a file that was recently opened that may contain PII.
# Get the flag from the contents of the file.
# Hint: We're not interested in numbers.
Get-ChildItem -Path C:\ -Recurse -File | Sort-Object LastWriteTime -Descending | Select-Object -First 10 FullName, LastWriteTime

# FullName                                                                        LastWriteTime
# -------------                                                                   -------------
# C:\Windows\Prefetch\SEARCHFILTERHOST.EXE-AA7A1FDD.pf                               4/1/2025 6:35:57 PM  
# C:\Windows\Prefetch\SEARCHPROTOCOLHOST.EXE-AFAD3EF9.pf                             4/1/2025 6:35:57 PM  
# C:\Windows\Prefetch\HOSTNAME.EXE-A62916AE.pf                                       4/1/2025 6:35:54 PM  
# C:\Windows\System32\Tasks\Microsoft\Windows\Windows Error Reporting\QueueReporting 4/1/2025 6:25:00 PM  
# C:\Windows\Prefetch\SVCHOST.EXE-8884F218.pf                                        4/1/2025 6:23:51 PM  
# C:\Windows\Prefetch\SVCHOST.EXE-375FA80F.pf                                        4/1/2025 6:23:51 PM  
# C:\Windows\Prefetch\RUNTIMEBROKER.EXE-5C74CC5C.pf                                  4/1/2025 6:15:04 PM  
# C:\Windows\Prefetch\POWERSHELL.EXE-59FC8F3D.pf                                     4/1/2025 6:02:06 PM  
# C:\Windows\Prefetch\CMD.EXE-89305D47.pf                                            4/1/2025 6:01:55 PM  
# C:\Windows\Prefetch\SSH-SHELLHOST.EXE-B3C3A07C.pf                                  4/1/2025 6:01:55 PM

# Enter the name of the questionable file in the prefetch folder.



