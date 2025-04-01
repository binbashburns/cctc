# List processes
ps -aux
ps -faux # more verbose
ps -elf # long format

# Realtime processes
top

# Don't use top, use htop
htop

# [kthreadd] process will always be PID 2
# sbin init will always have a PID of 1

# fork and exec calls
fork
exec

# kill things
kill -9 #<PID>
pkill -9 #<process name>

# kill sigterm numbers can be viewed with 
kill -l

systemctl status sshd

#cron stuff
# /var/spool/cron or /etc/crontab
sudo ls -l /var/spool/cron/crontabs

# remember this for the minas tirith box
sudo ls -la  /var/spool/cron/crontabs/

# check out crontab.guru

# lsof
sudo lsof -c sshd
sudo lsof -c cron
# pay attention to file descriptors using man lsof
# cron    1309 root    0r   CHR    1,3      0t0  1028 /dev/null
# cron    1309 root    1w   CHR    1,3      0t0  1028 /dev/null
# cron    1309 root    2w   CHR    1,3      0t0  1028 /dev/null
# cron    1309 root    3u   REG   0,19        5 12353 /run/crond.pid

sudo -la l /proc/ #<proc number>
