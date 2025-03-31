################################################

# Solve the following equation:
# 0x31A - 0x21B
# Enter the flag in Hexadecimal form.

echo $((0x31A))
# 794

echo $((0x21B))
# 539

# 794 - 539 = 255

echo "obase=16; 255"|bc
# 0xFF

################################################

# Each hex pair contains a value of 8 bits when used to represent memory. The range from 0x00000000 to 0x00000010 in hexadecimal represents addresses in memory or positions in data. This range includes the starting address (0x00000000) and ends at the address (0x00000010).

# How many bytes could the range 0x00000000 - 0x00000010 contain?

# Each memory address hold one byte. We count from 0x00000000 to 0x0000000F, which is 16 bytes. If you include the 0x00000010, inclusive, that is 17 bytes.

################################################

# What are the maximum and minimum value a single Hexadecimal digit can contain?

# Enter the values in Linux Hexadecimal Numerical Constant form.

# Flag format: min-max

# Research Hex to Decimal: https://www.aqua-calc.com/convert/number/hexadecimal-to-decimal

# 0-15 (0x0 - 0xF)

################################################

# Solve the following equation:
# 0x31A + 0x43
# Enter the flag in Hexadecimal form.

echo $((0x31A))
# 794

echo $((0x43))
# 67

# 794 + 67 = 861

echo "obase=16; 861"|bc
# 0x35D

################################################

# sudo cat /dev/sda | xxd -l 32 -c 0x10 -g 1
# sudo: unable to resolve host minas-tirith.novalocal: Connection timed out
# 00000000: eb 63 90 8e d0 31 e4 8e d8 8e c0 be 00 7c bf 00  .c...1.......|..
# 00000010: 06 b9 00 01 f3 a5 be ee 07 b0 08 ea 20 06 00 00  ............ ...

echo $((0xeb)) # 235    (0x00000001)
echo $((0x63)) # 99     (0x00000002)
echo $((0x90)) # 144    (0x00000003)
echo $((0x8e)) # 142    (0x00000004)
echo $((0xd0)) # 208    (0x00000005)
echo $((0x31)) # 49     (0x00000006)
echo $((0xe4)) # 228    (0x00000007)
echo $((0x8e)) # 142    (0x00000008)
echo $((0xd8)) # 216    (0x00000009)
echo $((0x8e)) # 142    (0x0000000A)
echo $((0xc0)) # 192    (0x0000000B)
echo $((0xbe)) # 190    (0x0000000C)
echo $((0x00)) # 0      (0x0000000D)
echo $((0x7c)) # 124    (0x0000000E)
echo $((0xbf)) # 191    (0x0000000F)

# 235,99,144,142,208,49,228,142
# ë,c,,,Ð,1,ä,

################################################

# Identify the file that init is symbolically-linked to, on the SystemD init machine.
# Flag format: /absolute/path

ls -l /sbin/init

################################################

# What is the default target on the SystemD machine and where is it actually located?

# Flag format: name.target,/absolute/path

systemctl get-default
# graphical.target

find / -type f -name "graphical.target" 2>/dev/null
# /lib/systemd/system/graphical.target

################################################

# What unit does the graphical.target want to start, based solely on its configuration file?

# HINT: Targets deal with which init system? Which machine should you be looking for this flag, on?

cat /lib/systemd/system/graphical.target

# Wants=display-manager.service

################################################

# What dependency to graphical.target will stop it from executing if it fails to start, based solely on its static configuration file?

cat /lib/systemd/system/graphical.target

# Requires=multi-user.target

################################################

# How many wants does SystemD recognize for only the default.target

# HINT: Use the systemctl command with some arguments to make life easier. Do not include sub-dependencies

systemctl list-dependencies default.target
# default.target
# ● ├─accounts-daemon.service
# ● ├─apport.service
# ● ├─display-manager.service
# ● ├─grub-common.service
# ● ├─systemd-update-utmp-runlevel.service
# ● ├─ureadahead.service
# ● ├─vestrisecreta.service
# ● └─multi-user.target
# ●   ├─apache2.service
# ●   ├─apache3.service
# ●   ├─apport.service
# ●   ├─atd.service
# ●   ├─binfmt-support.service
# ●   ├─console-setup.service
# ●   ├─cron.service
# ●   ├─dbus.service
# ●   ├─ebtables.service

# 7 (plus multi-user.target)

################################################

# What is the full path to the binary used for standard message logging?

# HINT: Standard message logging is standardized across UNIX systems.

which rsyslogd
# /usr/sbin/rsyslogd

################################################

# Identify the Linux Kernel being loaded by the Grub, by examining its configuration.

# Enter the command used by the Grub, and the full path to the Kernel, as the flag.

# Flag Format: command,kernel location

find / -type f -name "*grub*" 2>/dev/null

# ...
# /boot/grub/grub.cfg
# ...

cat /boot/grub/grub.cfg | grep linux

# ...
# linux   /boot/vmlinuz-4.9.0-16-amd64
#

# linux,linux   /boot/vmlinuz-4.9.0-16-amd64

################################################



################################################