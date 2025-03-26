# Situational Awareness

After first obtaining access to a system an operator must gather as much information about their environment as possible, this is referred to as situational awareness. pwd is just one command of many on Linux which can provide us some insight.

Other commands to help gain situational awareness:

   - `hostname` or `uname -a` displays the name of the host you are currently on.

   - `whoami` shows the user you are currently logged in as (useful after gaining access through service exploitation).

   - `w` or `who` shows who else is logged in.

   - `ip addr` or `ifconfig` displays network interfaces and configured IP addresses.

   - `ip neigh` or `arp` displays MAC addresses of devices observed on the network.

   - `ip route` or `route` shows where packets will be routed for a particular destination address.

   - `ss` or `netstat` will show network connections, with the appropriate flags will show listening ports

   - `nft list tables` or `iptables -L` to view firewall rules.

   - `sudo -l` displays commands the user may run with elevated permissions.

# Variables and Command substitution

Variables are a string of characters with an assigned value. They are used when automating tasks to reduce the amount of time needed to do something. Variables as a concept are easy to explain, but their application is dependent on that task that needs to be done.

## Assigning a Single Value to a Variable
```
student:~$ echo $a 
                   
student:~$ a="100" 
student:~$ echo $a 
100 
```
-	echo the value of the variable a. Notice that it has no value.
-	Nothing is returned.
-	Setting the value of a equals to 100.
-	echo the value of a.
-	Notice that the new value is 100.

Variables can also be assigned the output of a command using a technique called Command substitution. Command substitution is done with `$(command)` instead of the traditional `$`.

**Command Substitution in Bash**
```
student:~$ directories=$(ls /) 
student:~$ echo $directories 
bin   dev  home        initrd.img.old  lib64       media  opt   root  sbin  srv  tmp  var      vmlinuz.old
boot  etc  initrd.img  lib             lost+found  mnt    proc  run   snap  sys  usr  vmlinuz
```
-	Assign the variable directories to the output of the ls / command. Note the $().
-	Execute the echo command the contents of the variable directories.

# Automation and Logic

The primary benefit of terminals is the automation of repetitive tasks and processing logical statements. These statements and loops execute automatically using pre-programmed conditions that control how and even if they execute. They are invaluable to understand and their usefulness is limited to ones imagination and patience.

## For Loops

**For Loops** go by many names such as **Counting Loops** and **Interactive Loops**, but they all do the same thing - execute a command or commands multiple times with a changing variable as an argument. A complete for loop will have the following:

   - a **collection of objects** assigned to a variable

   - a variable that represents the value in the collection correctly being worked on

   - a command or commands that will execute with each value in the collection of variables

```
student:~$ objects=$(ls -d /etc/*) 
student:~$ echo $objects 
/etc/NetworkManager /etc/PackageKit /etc/UPower /etc/X11 /etc/acpi /etc/adduser.conf /etc/alternatives /etc/anacrontab /etc/apg.conf /etc/apm /etc/apparmor /etc/apparmor.d /etc/apport /etc/apt /etc/at.deny /etc/bash.bashrc /etc/bash_completion /etc/bash_completion.d /etc/bindresvport.blacklist /etc/binfmt.d /etc/byobu /etc/ca-certificates /etc/

_truncated_
```

### Making a For Loop to iterate on Objects in the collection of Objects
```
student:~$ for item in $objects; do echo $item; done 
/etc/NetworkManager
/etc/PackageKit
/etc/UPower
/etc/X11
/etc/acpi
/etc/adduser.conf
/etc/alternatives
/etc/anacrontab
/etc/apg.conf
/etc/apm
_truncated_
```
-	For each item in located in the objects variable, echo the value of item as the loop executes.
-	The `$item` variable is will contain each entry in $objects delimited by a space as the loop executes.

## If Statements

If statements are logical expressions that compare objects against various tests to see if they evaluate as true or false. They are understood in a sentence form like this:

   - If this comparison is **true**, then do this

       - or

   - Else If this comparison is **true**, then do this

       - or

   - If nothing is **true**, do this

### Making an If Statement to evaluate a series of objects Copy each line one at a time
```
student:~$ for object in $objects; \ 
do if [ -d $object ]; then echo "$object is a directory"; \ 
else echo "$object is file" ; \ 
fi ; \ 
done 

/etc/X11 is a directory
/etc/acpi is a directory
/etc/adduser.conf is a file
/etc/alternatives is a directory
/etc/anacrontab is a file
/etc/apg.conf is a file
/etc/apm is a directory
/etc/apparmor is a directory

student:~$ for object in $objects; do if [ -d $object ]; then echo "$object is a directory"; else echo "$object is a file" ; fi ; done 
```
-	The beginning of the for loop like in section 2.1.
-	if $object is a directory AND it exists, then run echo "$object is a directory".
-    else echo "$object is a file".
-	ends the if statements.
-	ends the for loop started in 1.
-	One liner version of the if statement.

### One Line For Loop and If Statement for the student’s notes
```
for object in $objects; do if [ -d $object ]; then echo "$object is a directory"; else echo "$object is a file" ; fi ; done
```
[If Statements TLDP](https://tldp.org/LDP/Bash-Beginners-Guide/html/sect_07_01.html)

# While Loops

While statements execute a command or series of commands **while** a condition is true. Unlike for loops which will eventually run out of objects, While Loops will run forever if their condition never evaluates as false. While loops are great for making things run for a specific amount of time instead of a exact amount of iterations. They are understood in sentence form as follows:

   - While this **condition** is true, do this thing or series of things, then re-evaluate the condition to see if it is false. Repeat until condition is false.

### Making an Basic While Loop
```
while [ 1 -eq 1 ]; do echo "To Infinity and Beyond!"; done 
```
-	While 1 equals 1, run the command echo ""To Infinity and Beyond!".
-	Yes, this script will run forever.

### Practical While Loop Example
```
curtime=$(date +"%s") 
echo $curtime

exittime=$(expr $curtime + 3) 
echo $exittime

while [ $exittime -ge $curtime ]; do echo "To Infinity and Beyond?" ; curtime=$(date +"%s") ; done 
To Infinity and Beyond?
To Infinity and Beyond?
To Infinity and Beyond?
To Infinity and Beyond?
_Truncated_ #It goes for three seconds
```
-	Use command substitution to set the value of curtime equal to the current time in Epoch time. "%s" = in seconds
-	Use command substitution to set the value of exittime equal to 3 seconds in the future Epoch Time.
-	While exittime is greater than curtime, do echo "To Infinity and Beyond?", then update the curtime variable and check if exittime is still greater or equal to curtime.

[While Loops TLDP](https://tldp.org/LDP/abs/html/loops1.html)

# Linux Filesystems

A file system is how a computer stores, categorizes, and retrieves data from physical media devices for use in various applications on the system.

There are multiple types of file systems, but they all follow a common layout described below:

   - Physical Media contains

       - A Partition that is a formatted section of memory, which contains

           - A File System mounted on a drive, which contains

               - A Hierarchical Format of Objects and their supporting Data and Metadata

File systems are a broad topic that range from understand hexadecimal layouts of hard drives to Forensics Techniques to reassemble deleted files. However, the important take away for this course is the understanding of **what is located where and what a user can do with it on a Linux Filesystem**

## Linux Filesystem Hierarchy

Every *Nix system from Ubuntu to Debian has a defined file system layout which is known as the Linux FSH (File System Hierarchy). It is a standard which defines the directory structure on all Linux distributions. What does that mean? Well, by default it defines:

   - The root directory of the file system `/`

       - Everything starts from this directory. Think of it as the doorway to the Linux Filesystem

   - Essential user commands in `/bin`

       - Contains commands like `ls` and `echo` which every user can use.

   - User Directories in `/home`

       - Contains directories for every non-root user on the system (with a home directory and login shell)

   - Host specific system configurations in `/etc`

       - Stands for **everything configurable**

       - Contains network configurations, system services(daemons), firewall configurations, etc.

   - Variable data files in `/var`

       - Contains all of the system logs by default

[Linux Filesystem Hierarchy Standard Wiki](https://en.wikipedia.org/wiki/Filesystem_Hierarchy_Standard)

[Linux Filesystem Hierarchy Standard Detailed](https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html)

## Files and Folders

In a file system, there are two types of objects - files and folders. Folders are a container for files, whilst files are containers for data. Everything without exception falls into one of those two categories.

**Showing / directories**
```
student@linux-opstation-kspt:~$ cd / 
student@linux-opstation-kspt:/$ 
student@linux-opstation-kspt:/$ ls -l $PWD/* 
drwxr-xr-x   2 root root  4096 Feb  4  2020 /bin
drwxr-xr-x   3 root root  4096 Feb  4  2020 /boot
drwxr-xr-x  19 root root  3840 Jan 23 12:29 /dev
drwxr-xr-x 117 root root  4096 Feb 12 16:49 /etc
drwxr-xr-x   4 root root  4096 Jan 23 12:25 /home
```
-	execute the command cd into the root directory of /.
-	The directory changed to /.
-	Execute ls in long list format with absolute path.

**Showing files in /bin**
```
student@linux-opstation-kspt:/$ cd /bin 

student@linux-opstation-kspt:/bin$ ls -ld $PWD/* 
-rwxr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
-rwxr-xr-x 1 root root  716464 Mar 12  2018 /bin/btrfs

student@linux-opstation-kspt:/bin$ ls -l 
-rwxr-xr-x 1 root root 1113504 Jun  6  2019 bash
-rwxr-xr-x 1 root root  716464 Mar 12  2018 btrfs
-rwxr-xr-x 1 root root  375952 Mar 12  2018 btrfs-debug-tree

	Change directory to /bin.
	Execute ls in long list format with absolute paths.
	Execute ls in long list format with relative paths.
```

Remember that there are only two types of objects in Linux - files and folders. Folders can’t be read, but files can. Granted, not every file is human readable. In most computers today, files have subtypes defined by their file signature typically located in the first few bytes of a file. The file signature defines how the operating system will attempt to use the file.

**Reading a "file" in /bin**
```
student@linux-opstation-kspt:/bin$ cat ls | head -n 1 
ELF>PX@▒@8      @@@▒888▒ _truncated_ 

student@linux-opstation-kspt:/bin$ xxd ls | head -n 2
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............ 
00000010: 0300 3e00 0100 0000 5058 0000 0000 0000  ..>.....PX......
```
-	Execute cat on ls, then send its standard output to the head command and trim output to display a single row.
-	Aside from the first few characters, that isn’t readable.
-	Execute xxd on ls, then send its standard output to the head command and trim output to display to the first two rows.
-	Look at that file signature! This file signature of 7f45 4c46 stands for Linux Executable Linked file format unique to Linux.

[File Signature Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)

## Linux Users

Users in Linux systems are defined by an ascending numerical value called a UID. The uid value uniquely identifies a user and is contained in the `/etc/passwd` file along with an associated username. Every user on a Linux system and has an associated value in `/etc/passwd`.

**Identify what Username you are whoami**
```
student@linux-opstation-kspt:/bin$ whoami 
student 
```
-	Execute the whoami command.
-	The answer to who I am.

**Identify what your uid value is with id**
```
student@linux-opstation-kspt:/bin$ id 
uid=1001(student) gid=1001(student) groups=1001(student),27(sudo) 
```
-	Execute the id command.
-	All of my associated ids?

**Looking at who I am in the /etc/passwd file with cat**
```
student@linux-opstation-kspt:/bin$ cat /etc/passwd | grep student 
student:x:1001:1001::/home/student:/bin/bash 
 (1)   (2) (3) (4) (5)   (6)          (7)
```
-	cmd line: Execute cat /etc/passwd and pipe it to grep to filter on student.
-	cmd output: Student entry in the /etc/passwd file.

**Sections of output lines**
-	Username
-	Password. An x character indicates that an encrypted password is stored in /etc/shadow file.
-	UID Value
-	GUID Value
-	User ID Info (GECOS). The comment field
-	Home Directory.
-   Command/Shell /bin/bash

## Linux Groups

Groups in Linux define a collection of Users and are defined by an ascending **GID** value. The **gid** value uniquely identifies a group and is contained in the `/etc/group` and its associated group name.

**Looking at who I am in the /etc/group file with cat**
```
student@linux-opstation-kspt:/bin$ cat /etc/group | grep student 
sudo:x:27:ubuntu,student 
student:x:1001: 
```
-	Execute cat /etc/group and pipe it to grep to filter on student.
-	Shows the sudo group, its gid value, its two members student and ubuntu.
-	Shows the student group, its gid value, and no additional members.

## Permissions

Access to objects in Linux by is controlled via strict file permissions metadata. It is formatted as:

   - `U` The object’s User/Owner

   - `G` The object’s owning Group

   - `O` Any subject that is not the owning user or group, AKA: "Others"

Each `U.G.O` permission group has three corresponding permissions of Read, Write, and Execute. Any combination of permissions can be applied to any permissions group. These permissions also have numeric representations of 4, 2, and 1. Permissions when represented by letters, as in `rwx`, are referred to as Relative, and permissions when represented by numbers, as in `421` are referred to as *Octal*.

It’s also important to understand that file permissions **do not overrule directory permissions**. If a user does not have read rights to a directory, it also cannot read any of its files **even if the file’s permissions allow it**

### Linux Permissions broken out 
|Perm | Relative | Octal | On a File | On a Directory|
|---|---|---|---|---|
|read | r | 4 | Read the contents of the file | List the contents of the directory|
|write | w | 2 | Write content into a file | Create/delete in the directory|
|exe | x | 1 | Run the file as an executable | Move into the directory|

**Showing Linux Permissions with ls -lisa**
```
student@linux-opstation-kspt:/bin$ ls -lisa /bin/dd 
student@linux-opstation-kspt:/bin$ 130341 76 -rwx r-x r-x 1 root root 76000 Jan 18  2018 /bin/dd
                                             (2)  (3) (4)   (5)   (6)
```
-	Showing permissions.
-	The Owner has Read, Write, and Execute permissions.
-	The Group has Read and Execute permissions.
-	Anyone who is not the User/Owner or belonging to the Group has Read and Execute permissions.
-	The file’s Owner.
-	The files' Group.

**File and Folder Permissions Demo**
```
student@linux-opstation-kspt:/home/student$ sudo su
root@linux-opstation-kspt:/home/student$  mkdir testdir
root@linux-opstation-kspt:/home/student$  chmod 750 testdir
root@linux-opstation-kspt:/home/student$  echo "Can you read me?" > testdir/file
root@linux-opstation-kspt:/home/student$  ls -lisa testdir/
1020551 4 drwxr-x---  2 root   root   4096 Feb 17 19:00 .
1016881 4 drwxr-xr-x 24 student student 4096 Feb 17 18:59 ..
1022450 4 -rw-r--r--  1 root   root     16 Feb 17 19:00 file

root@linux-opstation-kspt:/home/student$  exit
student@linux-opstation-kspt:/home/student$ cat testdir/file
cat: testdir/file: Permission denied
```
-	Change to the root user.
-	make a directory named testdir.
-	change the permissions on the directory to 750 or RWX,R-X,---.
-	Echo some text into a file in the created directory.
-	Show the permissions of the Directory and the file. . represents the directories permissions.
-	Exit root.
-	Try to cat the file as student and get Permission denied.

### Special Permissions : Sticky Bit

If a user has write access to a directory, they can delete any file from it. That may cause problems though in some directories like `/var/tmp`. To address this Linux has what is known as the **sticky bit**. The **sticky bit** removes the ability to delete files unless the user attempting is the **owner** of the file.

### Special Permissions : SUID and SGID

When an executable is ran in Linux, it runs with the permissions of the user who started it. However, SUID and SGID changes that to force the executable to run as the owning user or group. These permissions are represented as `s` in the User or Group field of `ls- l`.

**SUID and SGID Demo**
```
student@linux-opstation-kspt:~$ ls -l /bin/ping 
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /bin/ping 
```
-	Execute ls -l on /bin/ping.
-	Notice the s in the users field? What permissions does this executable effectively have?

[TLDP File Security](https://tldp.org/LDP/intro-linux/html/sect_03_04.html)

[Linux file permissions explained](https://www.redhat.com/en/blog/linux-file-permissions-explained)

# String Manipulation

In Linux all output is some kind of text, regardless of whether it was meant to be read by humans or not. You could scroll and use your finger to find data, or you can use one of pattern matching or text manipulation tools to make life easier.

## Grep

`Grep` is a program that searches data given to it from standard input for patterns of strings specified with regular expressions. `Grep` is invaluable in Linux because most of the time it is to only way to quickly filter output to find exactly what is needed.

**Use grep to filter standard output from another command**
```
student@linux-opstation-kspt:~$ ls -Rlisa /etc | grep password 
 1137 4 -rw-r--r--   1 root root 1440 Jan 31  2020 common-password
 1156 4 -rw-r--r--   1 root root 1160 Oct  9  2018 gdm-password
ls: cannot open directory '/etc/polkit-1/localauthority': Permission denied 
ls: cannot open directory '/etc/ssl/private': Permission denied
ls: cannot open directory '/etc/sudoers.d': Permission denied
```
-	Execute `ls -Rlisa` then send its standard out to grep to filter for the string password.

**Use grep to search through a directory for text**
```
student@linux-opstation-kspt:~$ grep -R 'network' /etc/ 
```
-	Execute `grep -R 'network' /etc/` then send it’s standard out to grep to filter for the string network.
-	The -R is recursive.

## Awk

`awk` is yet another important string manipulation tool. Unlike grep which searches for strings of text, awk allows you to reformat or select sections of text based on delimiters on the fly. Awk is commonly used to create tabular data sets from command output in Bash. However, it is a very flexible tool and its functionality does not end there.

**Reformat output from a command to create a comma delimited file with awk**
```
student@linux-opstation-kspt:~$ ls -l /etc 
drwxr-xr-x  7 root root       4096 Feb  4  2020 NetworkManager
drwxr-xr-x  2 root root       4096 Feb  4  2020 PackageKit
drwxr-xr-x  2 root root       4096 Feb  4  2020 UPower
_truncated_

student@linux-opstation-kspt:~$ ls -l /etc | awk -F " " '{print$3","$4","$9}' > files.csv 
student@linux-opstation-kspt:~$ cat files.csv
root,root,NetworkManager
root,root,PackageKit
root,root,UPower
_truncated_
```
-	The output from `ls -l` is verbose, maybe all of that information isn’t needed?
-	Lets send the output from `ls -l` into `awk`, then set the delimiter to blank space, then tell it to print fields $3,$4,$9, finally send them to a csv file.

**Crate a variable of all the news articles on https://dailymail.co.uk**
```
student@linux-opstation-kspt:~$ articles=$(curl -L https://www.dailymail.co.uk/ushome/index.html --output - | grep itemprop | grep href | awk -F "\"" '{print$4}'|  awk -F "/" '{print$4}')

student@linux-opstation-kspt:~$ for article in $articles; do echo $article; done
Rush-Limbaugh-dies-aged-70-lung-cancer-battle.html
Facebook-BANS-Australians-sharing-news-war-publishers.html
Congress-holds-hearing-reparations-slavery-time-BLM-protests-rocked-nation.html
Kendall-Jenner-accused-cultural-appropriation-launching-tequila-brand.html
MGM-Resorts-resume-24-7-operations-Mandalay-Bay-Park-MGM-Mirage-resorts-Las-Vegas.html
_truncated_
```
-	Perform a http GET request and filter all the HTML to get to the specific articles by grepping on itemprop, then grep on href, next use awk to cut output into fields separated by \ characters and select column 4, finally cut output into fields separated by / characters and select column 4.
-	Read the variable articles with a for loop.

## Sed

Sed is yet another string manipulation tool, but it edits text instead of filtering or formatting it like the other two. Sed is special because it edits text as it is sent to standard output. It is known as a stream editor. Text edited from sed can also be saved assuming the user executing it has the right permissions.

**Use sed to change standard out from the cat**
```
student@linux-opstation-kspt:~$ cat /etc/passwd | grep root 
root:x:0:0:root:/root:/bin/bash

student@linux-opstation-kspt:~$ cat /etc/passwd | grep root | sed s/root/bacon/g 
bacon:x:0:0:bacon:/bacon:/bin/bash
```
-	Execute cat on /etc/passwd then filter the output with grep to filter for root.
-	Using sed to change standard any standard input that matches root to bacon, then send the modified output to the screen.

**Using sed to clean up the output from the Dailymail Variable in section 4.2**
```
student@linux-opstation-kspt:~$ for article in $articles; do echo $article; done 
Rush-Limbaugh-dies-aged-70-lung-cancer-battle.html
Facebook-BANS-Australians-sharing-news-war-publishers.html
Congress-holds-hearing-reparations-slavery-time-BLM-protests-rocked-nation.html

for article in $articles; do echo $article |sed -e s/\.html//g -e s/\-/" "/g ; done  
Rush Limbaugh dies aged 70 lung cancer battle
Facebook BANS Australians sharing news war publishers
Police 7 shot near transit station north Philadelphia
```
-	The original output described in 4.2. It is messy and could be cleaned up a bit.
-	Using sed to replace standard input that matches .html with nothing.
-	Using sed to replace standard input from sed that matches the - (dash) character with a space.

## Regular Expressions

Regular expressions, or `regex`, are a pattern matching language developed in the 1980s with the first use of the Unix operating system. `Regex` filters on patterns strings that may match multiple permutations. Most internet search engines, online shopping, and really any place there is a search button uses them too.

**Showing how regular expressions can match on multiple permutations of strings**
```
student@linux-opstation-kspt:~$ echo -e "Handel\nHändel\nHaendel" > regexfile   
student@linux-opstation-kspt:~$ grep -P "H(ä|ae?)ndel" regexfile    
Handel
Händel
Haendel
```
-	Create a file with 3 similar names in it and save it as regexfile in the current directory.
-	Use `grep` with `-P` to specify **Perl regular expressions** and look for :
-	H,ä or a, e is `optional`, `ndel`.

[Handel Example Reference](https://en.wikipedia.org/wiki/Regular_expression#Patterns)

**Showing how regular expressions can match on multiple permutations of strings in files that are too large to search manually**
```
student@linux-opstation-kspt:~$ cat results.txt 
111-715-255643
(9279815)92-3599127
466-33836614-273
_truncated_

student@linux-opstation-kspt:~$ grep -P '\b\d{3}-\d{2}-\d{4}\b' results.txt
629-75-1985
386-67-7872
478-71-4964

student@linux-opstation-kspt:~$ grep -P '\(\d{3}\)\d{3}-\d{4}\b' results.txt
(267)874-4532
(446)146-8923
(548)985-5415
(199)363-3617
```
-	Attempting to cat the a large file isn’t very helpful.
-	Execute grep to search for the following pattern : nnn-nn-nnnn.
-	Execute grep to search for the following pattern : (nnn)nnn-nnnn.

## Linux Resources
   - [Command Cheat Sheet](https://cheat.sh/)
   - [Reference guide containing syntax and examples for the most prevalent computing commands](https://ss64.com/)

## Regex Resources

   - [Rexegg](https://rexegg.com/regex-quickstart.html)

   - [Regexone](https://regexone.com/)

   - [Regexr](https://regexr.com/)

   - [Regex Crosswords](https://regexcrossword.com/)

