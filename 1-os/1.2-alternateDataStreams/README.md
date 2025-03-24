# Alternate Data Streams

   - ADS was first introduced to NTFS in Windows NT 3.1 and was Microsoft’s attempt at implementing filesystem forks in order to maintain compatibility with other filesystems like Apple’s HFS+ and Novell’s NWFS and NSS.

   - In NTFS – files consists of attributes, security settings, mainstreams and alternate streams. By default, only the mainstream is visible.

   - ADS has been used to store metadata, like file attributes, icons, image thumbnails.

   - Great way to hide data using NTFS.

   - Can be scanned by antivirus (Windows Defender Smartscreen is ADS aware).

   - Does not change the MD5 hash of the file.

   - Deleted once copied to a fat32.

   - Cannot be disabled.

   - `[filename.extension]:[alternate_stream_name]:$DATA`

# Alternate Data Streams in Command Prompt and PowerShell

The demonstrations below are the basics of creating and viewing alternate data streams on a file and directory. The ADS demo will need a elevated command prompt (cmd.exe) and also an elevated PowerShell or PowerShell ISE window. You should understand that just because something isn’t viewable by normal means, doesn’t mean something isn’t hidden. It thus becomes important to understand the commands used to enumerate, recognize indicators, and list contents for ADS.

Perform steps below in an elevated CMD shell.
1. Creating a regular data stream on a file
```
C:\windows\system32>echo Always try your best > reminder.txt 

C:\windows\system32>dir reminder.txt 
 Directory of C:\windows\system32
 02/27/2021 07:13 PM                 25 reminder.txt
                1 File(s)            25 bytes
                0 Dir(s) 20,060,768,688 bytes free

C:\windows\system32>type reminder.txt 
Always try your best
```
-	echo content Always do your best into new file called reminder.txt.
-	dir, for files, displays the file name extension and size in bytes.
-	type displays contents of a text file, showing Always do your best.

2. Creating an Alternate Data Stream on a file
```
C:\windows\system32>echo social security numbers > reminder.txt:secret.info 

C:\windows\system32>dir reminder.txt 
 Directory of C:\windows\system32
 02/27/2021 07:13 PM                  23 reminder.txt
                 1 File(s)            23 bytes
                 0 Dir(s) 20,060,712,960 bytes free

C:\windows\system32>type reminder.txt 
Always try your best
```
-	echo content social security numbers into the ADS :secret.info of reminder.txt.
-	dir shows no visible change to reminder.txt even after previous added ADS content.
-	type shows no visible change to content of reminder.txt even after previous added ADS content.

3. Viewing an Alternate Data Stream on a file.
```
PS C:\windows\system32>Get-Item reminder.txt -Stream * 
PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\windows\system32\reminder.txt::$DATA
PSParentPath : Microsoft.PowerShell.Core\FileSystem::C:\windows\system32
PSChildName : reminder.txt::$DATA
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\windows\system32\reminder.txt 
Stream        : :$DATA 
Length        : 44

PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\windows\system32\reminder.txt:secret.info
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\windows\system32
PSChildName  : reminder.txt:secret.info
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\windows\system32\reminder.txt
Stream        : secret.info 
Length        : 25

PS C:\windows\system32>Get-Content reminder.txt -Stream secret.info 
social security numbers
```
-	Get-Item with the -Stream option allows us to see all streams for *reminder.txt.
-	FileName property provides the full path info for reminder.txt.
-	Stream property lists $DATA which is the main stream and commonly expected on most files. $DATA is the actual content.
-	Stream property lists secret.info which is an ADS to be investigated since it is outside the norm.
-	Get-Content with option and value -Stream secret.info gets us our ADS content, social security numbers.
-	The last command can be further improved to list only the FileName and Stream properties.
```
Get-Item reminder.txt -Stream * | select FileName,Stream
```

