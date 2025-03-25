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

