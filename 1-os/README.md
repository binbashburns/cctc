# Range 
Details about the range itself are below

## Range Map
![range-photo](../0-src/Range_Diagram.PNG)

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

