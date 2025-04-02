# What is Logging?

Logging is "**a record of performance, events, or day-to-day activities**". A log is a collection of data that defines the **time** an **event** occurred on a computer. However, a log without context is useless. The value of a log comes from the questions it will answer.

Logs are raw, unprocessed **data** that has no meaning. A question must be asked of the data for it to be valuable. Once data is asked a question - it becomes **information**. Usefulness of said information is dependent on the question being answered. Too much information is just as bad as useless data. Ask focused questions of the data to generate the best information.

## Figure 1. Data to Information Transformation

![data-to-information](../../0-src/linlog1.png)

In a security context, the value of a log comes from its ability to answer two questions, depending on Defensive or Offensive roles:

   - **Offense**

       - How can someone use this data to detect, investigate, and halt my presence within a system?

       - How can I blend in with standard system activity?

   - **Defense**:

       - How can I use this data to determine actions attempted or taken on a host?

       - What artifacts or IOCs(Indicators of Compromise) did the adversary leave behind?


# Linux Logging Daemons

In most Linux systems, logging is controlled by `syslog` or `journald`. **Syslog** is a Standard System Logging Protocol defined by **RFC 5424**, used across a variety of systems, and even on some enterprise Windows hosts. Journald, on the other hand, is unique to systemd distributions of Linux.

Both services store their logs in **/var/log**…​ however, there is a massive difference in the data each program generates.

# Syslog Daemon

Syslog stores its logs as human-readable text documents within `/var/log`. It is configured using files in `/etc/rsyslog/`.

Rsyslog one of many implementations of the Syslog Standard. It is typically included in **free** distributions of Linux because it is free. It supports configuration options, but the most important topic is understanding **what and where** it logs.

### Table 1. Syslog logging configuration standard 
|Selectors|Action|
|---|---|
|`facility`.`severity`|`/path/to/log/location`|

   - `Facility` is the source, or **event**, that generated the log

   - `Severity` is how urgent an event is from 0 (Emergency) to 7 (Debug)

   - `path/to/log/location` is where the log is stored and/or any action taken on the event before storage (like sending it to a remote server)

Syslog is the underlying standard but has multiple implementations like **rsyslog** and **syslog-ng**. They do the same tasks, but from version specific nuances.

### Table 2. Syslog Message Facilities RFC 5424 

| Numerical Code | Facility |
|---|---|
|0 | kernel messages  |
|1 | user-level messages|
|2 | mail system|
|3 | system daemons|
|4 | security/authorization messages|
|5 | messages made by syslogd|
|6 | line printer subsystem|
|7 | network news subsystem|
	
This is not every Facility Code. See the RFC for a listing of every code. 

### Table 3. Syslog Message Severities RFC 5424 
|Numerical Code | Severity|
|---|---|
|0|Emergency|
|1|Alert|
|2|Critical|
|3 | Error|
|4 | Warning|
|5 | Notice|
|6 | Informational|
|7 | Debug|

**Sample Syslog Configuration**
```
cat /etc/rsyslog.d/50-default.conf

root@sup09:/etc/rsyslog.d# cat /etc/rsyslog.d/50-default.conf | head -n 15
#  Default rules for rsyslog.
#
#			For more information see rsyslog.conf(5) and /etc/rsyslog.conf

#
# First some standard log files.  Log by facility.
#
auth,authpriv.*			-/var/log/auth.log 
*.*;auth,authpriv.none		-/var/log/syslog 
#cron.*				-/var/log/cron.log
#daemon.*			-/var/log/daemon.log 
kern.critical		        -/var/log/kern.log 
#lpr.*				-/var/log/lpr.log
mail.*				-/var/log/mail.log
#user.*				-/var/log/user.log
```
-	Logs messages from **standard** and **privileged** user authentication facilities to `/var/log/auth.log`
-	Everything **except** authentication logs is logged to `/var/log/syslog`
-	This line is commented out and **nothing will be done with it**
-	Logs **kernel** facility logs with a severities of Emergency, Alert, and Critical to `/var/log/kern.log`.

Severity statements in selectors are hierarchical. Syslog uses greater than or equal to and less than to select when determining what severies are logged.

**Example**:

   - `mail.info` matches all messages produced by the kernel with severity of #equal to and greater than (greater severity) 6/Informational (severity 0 - 6).

   - `mail.!info` matches all messages produced by the kernel with severity of #less than and not including (lesser severity) 6/Informational (severity 7).

[rsyslog.conf — Linux manual page](https://man7.org/linux/man-pages/man5/rsyslog.conf.5.html)

`severity` does not refer to the numerical code. It refers to the severity nouns in hierarchical format. Emergency is the highest severity and Debug is the lowest.

The level describes the severity of the message, and is a keyword from the following ordered list (higher to lower): emerg, crit, alert, err, warning, notice, info and debug. These keywords correspond to similar "LOG_" values specified to the syslog(3) library routine 

[Syslog conf file walkthrough](https://www.thegeekdiary.com/centos-redhat-beginners-guide-to-log-file-administration/)

[Syslogd man page](https://linux.die.net/man/8/syslogd)

[FREEBSD syslog.conf man page](https://www.freebsd.org/cgi/man.cgi?query=syslog.conf&sektion=5&n=1)

## Filtering Syslog Log Files

Since Syslog log files are plain text documents they are easily filtered using simple command line tools like cat, vi , and grep.

**Filtering Syslog Output With Grep**
```
cat /var/log/syslog | grep timesyncd 

Oct  2 17:24:25 sup09 systemd-timesyncd[3526]: Timed out waiting for reply from 91.189.94.4:123 (ntp.ubuntu.com).
Oct  2 17:58:46 sup09 systemd-timesyncd[3526]: Timed out waiting for reply from 91.189.91.157:123 (ntp.ubuntu.com).
Oct  2 17:58:56 sup09 systemd-timesyncd[3526]: Timed out waiting for reply from 91.189.89.198:123 (ntp.ubuntu.com).
Oct  2 17:59:06 sup09 systemd-timesyncd[3526]: Timed out waiting for reply from 91.189.89.199:123 (ntp.ubuntu.com).
```

-	Grep for the string **timesyncd** in `/var/log/syslog`

Don’t forget that grep also supports Regular Expressions to find patterns of strings within a file!

**Filtering Syslog Output With Grep**
```
cat /var/log/syslog | grep -R "\w*\.\w*\.\w*" 

Oct  2 18:06:47 sup09 systemd[1]: Starting User Manager for UID 0...
Oct  2 18:33:27 sup09 systemd-timesyncd[3526]: Timed out waiting for reply from 91.189.91.157:123 (ntp.ubuntu.com).
Oct  2 18:33:37 sup09 systemd-timesyncd[3526]: Timed out waiting for reply from 91.189.89.198:123 (ntp.ubuntu.com).
```
-	Using **grep** to match on the patterns that loosely resemble an IP address or domain names within var/log/syslog

## Log Rotations

The concept of **Log Rotations** limit the content in logs based off defined spans of time for ease of use and administration. If log rotation is not implemented, logs will grow infinitely. Since they are text files, it makes them very hard to read.

A daily cron job runs the `logrotate` binary controls log rotations. The cron job runs `logrotate` with the path to its configuration file `/etc/logrotate.conf` as an argument. /etc/logrotate.conf defines how often logs are rotated.

**Show Log Rotations**
```
root@linux-opstation-kspt:~# cat /etc/logrotate.conf

# see "man logrotate" for details
# rotate log files weekly
weekly 
```
-	Log rotation occurs weekly

Your system might not have rotated files yet. Force rotations with sudo /usr/sbin/logrotate /etc/logrotate.conf

**Showing Rotated logs**
```
root@linux-opstation-kspt:~# ls -l /var/log
total 684
-rw-r--r--  1 root      root               333 Feb  8 00:33 alternatives.log
-rw-r--r--  1 root      root              3010 Jan 25 20:55 alternatives.log.1
drwxr-xr-x  2 root      root              4096 Feb 12 16:49 apt
-rw-r-----  1 syslog    adm              54651 Feb 26 20:17 auth.log 
-rw-r-----  1 syslog    adm              43270 Feb 20 23:17 auth.log.1 
-rw-r-----  1 syslog    adm               5069 Feb 14 23:17 auth.log.2.gz 
```
-	Current version of auth.log
-	auth.log from 1 week ago
-	auth.log from 2 weeks ago in a zipped file.

`vim` and `zcat` will read zip files without extracting them.

## Essential Syslog Types/Locations

### Authentication

Any logs having to do with logins and authentication attempts. 
  - `/var/log/auth.log` - Authentication related events 
  - `/var/run/utmp` - Users currently logged in .. Not in human readable format. Must use `last` command
  - `/var/log/wtmp` - History file for utmp .. Not in human readable format. Must use `last` command
  - `/var/log/btmp` - Failed login attempts

### Application

Any logs having to do with programs. 
  - Apache - Webserver (dir) 
  - apt - Package Manager (dir) 
  - /var/log/mysql.log

### System

   - `/var/log/messages` - Legacy Catch all

   - `/var/log/syslog` - Ubuntu/Debian Catch all

   - `dmesg` = Device Messenger (queires /proc/kmsg)

       - Kernel Ring Buffer - Never fills

       - First logs generated by the system

### Logging at a Glance

   - Location: All logs are in `/var`, most are in `/var/log`

   - Config File: `/etc/rsyslog.conf`

   - Service: `/usr/sbin/rsyslogd`

# Journald Logs

Journald or `systemd-journald.service` is the logging daemon for `systemd` init Linux systems. It logs everything in regards to `*.units` from unit startup status to logs generated by each individual unit. Journald stores its logs in binary form. `journalctl` is the open command that reads them.

`journalctl` in its base form shows all the logs currently saved by journald. Warning, journald is verbose so it saves a lot of logs.

**Basic Journal ctf usage**
```
root@linux-opstation-kspt:~# journalctl -e 

Feb 26 21:08:45 linux-opstation-kspt systemd-timesyncd[592]: Timed out waiting for reply from 91.189.91.157:123
Feb 26 21:08:55 linux-opstation-kspt systemd-timesyncd[592]: Timed out waiting for reply from 91.189.94.4:123 (
Feb 26 21:09:05 linux-opstation-kspt systemd-timesyncd[592]: Timed out waiting for reply from 91.189.89.199:123
Feb 26 21:09:16 linux-opstation-kspt systemd-timesyncd[592]: Timed out waiting for reply from 91.189.89.198:123
```
-	Tell journalctl to show the last logs its received with `-e`.
	
If -e is not used, prepare to scroll for quite some time.

## Journald features

`Journalctl` is a powerful tool. It supports a plethora of advanced features which make it more convenient then regular text based logs. A sample of the features' are below.

**Filtering logs by Boot**
```
root@linux-opstation-kspt:~# journalctl --list-boots 
-1 7124cba1d13a4933a0784ad063870cc6 Sat 2021-01-23 12:24:35 UTC—Sat 2021-01-23 12:29:32 UTC
 0 b3076f6774b841e08c19236bf327f529 Sat 2021-01-23 12:29:51 UTC—Fri 2021-02-26 20:34:26 UTC

root@linux-opstation-kspt:~# journalctl -b b3076f6774b841e08c19236bf327f529 
-- Logs begin at Sat 2021-01-23 12:24:35 UTC, end at Fri 2021-02-26 21:04:48 UTC. --
Jan 23 12:29:51 linux-opstation-kspt kernel: Linux version 4.15.0-76-generic (buildd@lcy01-amd64-029) (gcc vers
Jan 23 12:29:51 linux-opstation-kspt kernel: Command line: BOOT_IMAGE=/boot/vmlinuz-4.15.0-76-generic root=L
```
-	Show boot ids which separate logs based on when the machine was restarted
-	Tell `journalctl` to only show logs relating to that boot id.

**Filtering Logs by a specific unit**
```
root@linux-opstation-kspt:~# journalctl -u ssh.service 
Jan 27 13:16:21 linux-opstation-kspt sshd[7558]: Accepted password for holman from 10.250.0.6 port 62390 ssh2
Jan 27 13:16:21 linux-opstation-kspt sshd[7558]: pam_unix(sshd:session): session opened for user holman by (uid
Jan 29 13:23:51 linux-opstation-kspt sshd[10277]: Accepted password for holman from 10.250.0.6 port 52863 ssh2
```
-	Show only `ssh.service` logs in journalctl

**Filtering Logs since a specific time period**
```
root@linux-opstation-kspt:~# journalctl -u ssh.service --since "2 days ago" 
-- Logs begin at Sat 2021-01-23 12:24:35 UTC, end at Fri 2021-02-26 21:09:16 UTC. --
Feb 25 13:44:48 linux-opstation-kspt sshd[29991]: Accepted password for holman from 10.250.0.20 port 59042 ssh2
Feb 25 13:44:48 linux-opstation-kspt sshd[29991]: pam_unix(sshd:session): session opened for user holman by (ui
Feb 25 16:09:56 linux-opstation-kspt sshd[32230]: Accepted password for holman from 10.250.0.20 port 59830 ssh2
Feb 25 16:09:56 linux-opstation-kspt sshd[32230]: pam_unix(sshd:session): session opened for user holman by (ui
Feb 25 16:39:15 linux-opstation-kspt sshd[1396]: Accepted password for holman from 10.250.0.20 port 60070 ssh2
```
-	Only show logs pertaining to `ssh.service` from up to 2 days ago in journalctl

# Log Formats

Logs are formatted in a variety of ways. Some formats are designed to read without external tools, whilst others require text parsing tools or are unreadable without special programs. In general, logs are presented in one the following formats: Simple Text Documents, Markup Languages, and JavaScript Object Notation (JSON).

## Simple Text Documents

   - Readable without specific tools and typically work well with ctrl-f searches or `grep`

### Syslog Message Format
**Example - Syslog Message Format Log**
```
Apr 6 00:00:09 linux-opstation-7qhp systemd-timesyncd[745]: Timed out waiting for reply from 91.189.91.157:123 (ntp.ubuntu.com). 
Apr 6 00:00:10 linux-opstation-7qhp CRON[10943]: (root) CMD ( cd / && run-parts --report /etc/cron.hourly)
Apr 6 00:00:11 linux-opstation-7qhp CRON[10948]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))
Apr 6 00:00:12 linux-opstation-7qhp systemd-timesyncd[745]: Timed out waiting for reply from 91.189.89.198:123 (ntp.ubuntu.com).
Apr 6 00:00:13 linux-opstation-7qhp systemd-timesyncd[745]: Timed out waiting for reply from 91.189.91.157:123 (ntp.ubuntu.com).
Apr 6 00:00:14 linux-opstation-7qhp systemd-timesyncd[745]: Timed out waiting for reply from 91.189.94.4:123 (ntp.ubuntu.com).
```
-	Each entry is broken into a single line.
-	Makes the file easy to parse with `grep`, `findstr`, and ctrl-f.
-	This cannot be fed into a machine for bulk processing as it lacks serialization.

## Markup Languages

   - Human readable, but designed to be parsed using special programs.

   - Uses a schema like `HTML` so it has tags and attributes like a webpage. Also, it is serialized.

### XML Example
Example - XML
```
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<Events><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4672</EventID><Version>0</Version><Level>0</Level><Task>12548</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2021-04-16T10:21:57.759800100Z'/><EventRecordID>1478494</EventRecordID><Correlation/><Execution ProcessID='776' ThreadID='12292'/><Channel>Security</Channel><Computer>BrickPuter-PC</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>SYSTEM</Data><Data Name='SubjectDomainName'>NT AUTHORITY</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='PrivilegeList'>SeAssignPrimaryTokenPrivilege
			SeTcbPrivilege
			SeSecurityPrivilege
			SeTakeOwnershipPrivilege
			SeLoadDriverPrivilege
			SeBackupPrivilege
			SeRestorePrivilege
			SeDebugPrivilege
			SeAuditPrivilege
			SeSystemEnvironmentPrivilege
			SeImpersonatePrivilege</Data></EventData><RenderingInfo Culture='en-US'><Message>Special privileges assigned to new logon.

Subject:
	Security ID:		S-1-5-18
	Account Name:		SYSTEM
	Account Domain:		NT AUTHORITY
	Logon ID:		0x3e7

Privileges:		SeAssignPrimaryTokenPrivilege
			SeTcbPrivilege
			SeSecurityPrivilege
			SeTakeOwnershipPrivilege
			SeLoadDriverPrivilege
			SeBackupPrivilege
			SeRestorePrivilege
			SeDebugPrivilege
			SeAuditPrivilege
			SeSystemEnvironmentPrivilege
			SeImpersonatePrivilege</Message><Level>Information</Level><Task>Special Logon</Task><Opcode>Info</Opcode><Channel>Security</Channel><Provider>Microsoft Windows security auditing.</Provider><Keywords><Keyword>Audit Success</Keyword></Keywords></RenderingInfo></Event></Events>
```
-	Difficult to read, but it isn’t impossible. Try copying and pasting this into a XML formatter online at [Freeformatter.com](https://www.freeformatter.com/xml-formatter.html#ad-output)
-	Parsing this is hard without a specialized querying tool called Xpath. Try it out at this website: [Xpather.com](http://xpather.com/).
-	Here is a Xpath tutorial: [Click meeee](https://www.w3schools.com/xml/xpath_syntax.asp)

![xpath](../../0-src/ancestor_descendant.jpeg)

   - Xpath Syntax: `xpath -q -e '//element/@attribute' file.xml`

Here's an example using the `output.xml` file in the same folder as this README.

Query is read as:
```
//*[@state='up']/../address/@addr | //*[@state='up']/../ports/port/@portid
```
![xpather](../../0-src/xpath.png)

### Resources

   - [Execute Xpath One Liners From Shell](https://stackoverflow.com/questions/15461737/how-to-execute-xpath-one-liners-from-shell)

## JavaScript Object Notation (JSON)

   - Serialized data interchange format designed to be parsed by machines.

   - It is human readable, however it is nigh to read without pretty printing it first.

### JSON Example
**Example - JSON output from a Zeek conn.log**
```
{"ts":1615383120.600619,"uid":"CLdOLa12ikO7IbVX0d","id.orig_h":"10.50.24.73","id.orig_p":19831,"id.resp_h":"192.168.65.20","id.resp_p":110,"proto":"tcp","duration":0.000010013580322265625,"orig_bytes":0,"resp_bytes":0,"conn_state":"REJ","missed_bytes":0,"history":"Sr","orig_pkts":1,"orig_ip_bytes":60,"resp_pkts":1,"resp_ip_bytes":40}
```
-	Kind of difficult to parse because its length. Try pretty printing it at the following link: [pretty print link](https://jsonformatter.org/json-pretty-print)
-	Like XML, JSON needs can be queried using special programs. To query JSON use jq or JSON Query.
-	Here is a [JSON Query Tutorial](https://docs.jsonata.org/simple)
-	Here is a [Online JSON Query tool](https://jqplay.org/)
-	Here is a [jq Syntax Overview](https://www.linode.com/docs/guides/using-jq-to-process-json-on-the-command-line/)
-	Here is a [jq Cheat sheet](https://cheat.sh/jq)

Here is an example using the file in this directory:
```
jq '.|select(."id.orig_p" == 443)|".id.orig_h"' output.xml
```

### Resources

   - [Shapeshed - Parse JSON with JQ](https://shapeshed.com/jq-json/)

   - [Using jq to Parse JSON](https://www.baeldung.com/linux/jq-command-json)

   - [Json Manipulation](https://webgeodatavore.com/jq-json-manipulation-command-line-with-geojson.html)