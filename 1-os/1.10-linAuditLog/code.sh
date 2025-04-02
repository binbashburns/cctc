# File: /home/garviel/output.xml
# Identify the only XML element name referenced in the output below
# <scaninfo type="syn" protocol="tcp" numservices="200" services="1-200"/>
# Flag: The element with start and end tags

scp garviel@terra:/home/garviel/output.xml . # copy file locally to observe structure
# above step wasn't really necessary. The question was really looking for this answer: <scaninfo/>

# Identify one of the XML attributes in the output below
# <scaninfo type="syn" protocol="tcp" numservices="200" services="1-200"/>
# Flag format: value="pair"
# answer: protocol="tcp"

# What RFC is Syslog?
# RFC 5424

# What is the numerical code assigned to the facility dealing with authorization?
# 4

# How many severity codes are defined in the standard that defines syslog?
# 8

# What severity is assigned to system instability messages?
# 0

# (Using 50-cctc.conf) In the legacy rules section of the file, what facility is logged to 0.log?

# From File:
#Legacy rules. Why do we even have these?
# 0.* -/var/log/0.log
# 4.4 -/var/log/4min.log
# 4.!4 -/var/log/4sig.log
# 2,9,12.=5 /var/log/not.log
# 0 is the answer, and looking at the FG, 0 is for kernel messages. Answer is "kernel"

# In the legacy rules section of the file, how many severities are logged to 0.log?
# observing the above, the syntax is 0.*, which means all kernel severitys defined in syslog standard (8) is the answer.

# In the legacy rules section of the file, how many severities are logged to 4min.log?
# List the severities from highest severity (lowest numerical listed) to lowest severity (highest numerical listed) using their severity name.
# Flag format: name,name,name
# The .conf file has "4.4" for this. I want to confirm what is listed in /var/log.
# 4 is the auth log.
ls -l
# -rw-r-----   1 syslog        adm               73371 Apr  2 10:39 auth.log
# -rw-r-----   1 syslog        adm              154581 Mar 29 23:39 auth.log.1
# -rw-r-----   1 syslog        adm                7648 Mar 22 23:39 auth.log.2.gz
# -rw-r-----   1 syslog        adm                7138 Mar 15 23:39 auth.log.3.gz
# -rw-r-----   1 syslog        adm                8143 Mar  8 23:39 auth.log.4.gz
# it is logging everything from 0 to 4, based on that output. So that's 5 different severity groups. Referencing RFC 5424, that is:
# emergency,alert,critical,error,warning

# In the legacy rules section of the file, how many severities are logged to 4sig.log?
# List the severities from highest severity (lowest numerical listed) to lowest severity (highest numerical listed), using their severity name.
# Flag format: name,name,name
# using the referenced file, the syntax if 4.!4, which means everything from 4 and up, which is 5, 6 and 7, or:
# notice,informational,debug

# What is being logged in not.log?
# Provide the facilities from lowest facility to highest facility numerically, and the severity being logged. (List only the first word for each.)
# Flag format: facility,facility,facility,severity
# 2,9,12.=5, or: mail,clock,ntp,notice

# What facilities and what severities are being sent to a remote server over a reliable connection using port 514?
# Provide the facility names, number of severities, and the correct destination IP address.
# Flag format: F,F,#,IP
# using the provided example, two at symbols (@@) mean TCP so:
# auth,authpriv.* @@10.30.0.1:514 OR : auth,authpriv,8,10.30.0.1

# What messages are being sent to 10.84.0.1?
# Provide the facility number, the number (amount) of severity codes, and Layer 4 connection type as the answer.
# From referenced file: kern.!=info
# OR: 0,7,udp (0 for kernel, 7 because it's everything BUT info, and UDP for one @ symbol)

