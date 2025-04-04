# Get all properties for a given user
Get-AdUser -Identity 'First.Last' -Properties *

# Get all properties for all users, and then filter based on output:
Get-AdUser -Filter * -Properties * | Select-Object -Property yadayada

# Enable the guest account
Enable-ADAccount -Identity guest

# Change it's password
Set-AdAccountPassword -Identity guest -NewPassword (ConvertTo-SecureString -AsPlaintext -String "PassWord12345!!" -Force)

# Add the user to domain admins:
Add-ADGroupMember -Identity "Domain Admins" -Members guest

# Get all groups and members of those groups
Get-ADGroup -filter * | Get-ADGroupMember -Recursive

#What is the domain portion of the following SID:
# S-1-5-21-1004336348-1177238915-682003330-1000
# From Microsoft Learn: 
# S-1-5-21-1004336348-1177238915-682003330-512
#   The SID for Contoso\Domain Admins has the following components:
#       A revision level (1)
#       An identifier authority (5, NT Authority)
#       A domain identifier (21-1004336348-1177238915-682003330, Contoso)
#       An RID (512, Domain Admins)
# Therefore, the solution is: 21-1004336348-1177238915-682003330

# What PowerShell command will list all users and their default properties?
# The flag is the full command with arguments.
Get-AdUser -Filter *

# What PowerShell command will allow you to search Active Directory accounts for expired accounts without having to create a filter?
# The flag is only the command, no arguments/switches.
Search-ADAccount

# Find the expired accounts that aren't disabled. List the last names in Alphabetical Order, separated with a comma, and no space between.
# Flag format: name,nam
Search-ADAccount -AccountExpired
# Krause,Page

# Find the unprofessional email addresses. List the email's domain.
Get-AdUser -Filter * -Properties EmailAddress | Where-Object {$_.EmailAddress -notlike "@mail.mi*"} | Select-Object -Property Name,EmailAddress
# ashleymadison.com

# The flag is the unprofessionally-named file located somewhere on the Warrior Share.
# From the Admin-Station, Connect to the Warrior Share:
# net use * "\\file-server\warrior share"
net use * "\\file-server\warrior share"
Get-ChildItem -Path 'Z:\' -Recursive
# Z:\Brigade HQ \CMD GRP\lulz.pdf

# The flag is the name of the file, where in the file contents, someone is requesting modified access rights.
# Guessing it is 14287.pdf

# The flag is the name of the user who is requesting modified access rights.
Copy-Item -Path 'Z:\Brigade HQ\S-6\14287.pdf' -Destination C:\Users\andy.dwyer\Desktop
# Open PDF in a PDF Viewer
# PDF doesn't give a name outside of an initial (K), but it gives a phone number, which is "336-6754"
Get-AdUser -Filter * -Properties TelephoneNumber | Where-Object {$_.TelephoneNumber -like "*6754"} | Select-Object -Property Name,TelephoneNumber
# Karen.Nance

# Find the accounts that contain unprofessional information in the description.
Get-AdUser -Filter * -Properties Name,Description | Select-Object -Property Name,Description
# Brandywine,Jimenez

# Find the following three accounts:
#   two accounts with passwords that never expire NOT andy.dwyer
#   one account that has its password stored using reversible encryption
# List the last names in Alphabetical Order, comma-separated, no spaces. Do not list built-in accounts.
Search-ADAccount -UsersOnly -PasswordNeverExpires | Select-Object Name,Enabled
# Eddie.Sanchez and Xavier.Ibarra
Get-AdUser -Filter * -Properties AllowReversiblePasswordEncryption | Where-Object {$_.AllowReversiblePasswordEncryption -eq "True"} | Select-Object -Property Name,AllowReversiblePasswordEncryption
# Alice.Brandywine
# Putting it all together: Brandywine,Ibarra,Sanchez

# Find the short name of the domain in which this server is a part of.
(Get-AdDomain -Identity "DC=army,DC=warriors").NetBIOSName
# ARMY

# What is the RID of the krbtgt account.
Get-AdUser -Filter * -Properties Name,SID | Where-Object -Property Name -eq krbtgt | Select-Object -Property Name,SID
# Name   SID
# ----   ---
# krbtgt S-1-5-21-427089730-1199744433-1189759946-502
# The RID is the last group of numbers, so, 502

