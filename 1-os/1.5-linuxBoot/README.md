# Linux Boot Process

The boot process is a sequence of events that bring a computer from an off state to full functional. At each stage different programs run to fulfill specific tasks. A skilled adversary can change each stage of the process to further their goals. Understanding all the configuration options at every stage can mean the difference between a completely locked down system, and one with default security vulnerabilities at all levels.

![linux-boot-process](../../0-src/linboot1.png)

# BIOS and UEFI

BIOS and UEFI are firmware that ensure critical hardware like SATA devices (Hard Drives), Display Adapters, and SDRAM(Synchronous dynamic random-access memory) are functional then, locates the MBR(Master Boot Record) or GPT(GUID Partition Tables).

Firmware is software coded non-volatile memory devices such as: . ROM (Read only memory) . EPROM (Electronically Programmable Read only memory) . EEPROM (Electronically Erasable Programmable read only memory) . Flash memory

## Differences between BIOS and UEFI Firmware

BIOS and UEFI do the same thing, but minor differences make UEFI more popular than BIOS in the current day. Without getting into low level specifics some of the benefits of UEFI:

   - UEFI Boots much faster than BIOS systems, especially for Windows machines.

   - UEFI Firmware is usually loaded into flash memory or EEPROM, making it easier to update and patch.

   - UEFI offers SECURED BOOT mode which only allows verified drivers to load.

   - UEFI offers drive support of up to 9 zettabytes', while BIOS only works with 2 terabytes.

# 1st Stage Bootloaders

1st Stage Bootloaders are the Master Boot Records(MBR) and the GUID Partition Tables (GPT) because they are the first part of loading an operating system. They locate and finish loading the 2nd stage bootloader known as GRUB

## Master Boot Record (MBR)

The Master Boot Record contains information on partitions locations on the hard drive. Partitions contain the 2nd stage bootloader known as the GRUB(Grand Unified Bootloader).
	Boot Sector and MBR are the same thing. The MBR is a Boot Sector.

Once the BIOS loads the bootstrap in the MBR. The bootstrap is the initial section of code that contains a bootloader known as GRUB broken into two stages. The first stage is GRUB stage 1, which loads Grub Stage 2 from the selected active partition. Grub Stage 2 is not located in the MBR, but further in the hard drive.

### Master Boot Record Layout

The first 512 bytes of a hard drive contains the Master Boot Record. It contains the following information:

   - Bootstrap Code

   - Partition entry 1

   - Partition entry 2

   - Partition entry 3

   - Partition entry 4

   - Boot signature


**Locate the hard drive and partition in Linux**
```
student@linux-opstation-kspt:~$ lsblk 

NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
loop0    7:0    0 31.1M  1 loop /snap/snapd/10707
loop1    7:1    0 55.4M  1 loop /snap/core18/1944
loop2    7:2    0 44.7M  1 loop /snap/openstackclients/38
loop3    7:3    0 55.5M  1 loop /snap/core18/1988
loop4    7:4    0 31.1M  1 loop /snap/snapd/11036
sr0     11:0    1  514K  0 rom  /media/student/config-2
vda    252:0    0  128G  0 disk 
└─vda1 252:1    0  128G  0 part / 
```
-	List block devices currently in use by Linux
-	Shows disk vda virtual disk A
-	Shows virtual disk A partition 1 is mounted as the / or root drive in Linux


**Examining the contents of the MBR with xxd**
```
student@linux-opstation-kspt:~$ sudo xxd -l 512 -g 1 /dev/vda 

00000000: eb 63 90 00 00 00 00 00 00 00 00 00 00 00 00 00  .c.............. 
00000010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
_truncated_
000001b0: cd 10 ac 3c 00 75 f4 c3 fa b7 12 e6 00 00 80 00  ...<.u.......... 
000001c0: 21 02 83 0f 2e 40 00 08 00 00 df f7 ff 0f 00 00  !....@.......... 
000001d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 aa  ..............U.
```
-	Execute xxd to hexdump 512 bytes in separated by 1 byte from /dev/vda to the screen
-	The start of the hard drive shown by the code eb 63. File signature for an MBR.
-	The first partition of the hard drive in 0x01be shown as 80
-	The second partition entry is blank!

[MBR Layout Forensics Reference](http://www.invoke-ir.com/2015/05/ontheforensictrail-part2.html)

[Wikipedia Entry on MBR Disk Layouts](https://en.wikipedia.org/wiki/Master_boot_record#Disk_partitioning)

**Making a copy of the MBR with dd — Run this on Ops Station**
```
student@linux-opstation-kspt:~$ dd if=/dev/vda of=MBRcopy bs=512 count=1 
dd: failed to open '/dev/vda': Permission denied 
student@linux-opstation-kspt:~$ sudo !! 
1+0 records in
1+0 records out
512 bytes copied, 0.00026952 s, 1.9 MB/s
student@linux-opstation-kspt:~$ file MBRcopy 
MBRcopy: DOS/MBR boot sector
```
-	Execute dd which copies 512 bytes once from /dev/vda to a file in my current directory called MBR
-	Notice, dd failed to run
-	!! represents the previous command. Run it with sudo permissions.
-	Execute file to read the file signature from the MBR file

# Hexidecimal

Understanding the format of a hexadecimal address, or hex, is essential to many Cyber Security fields. Luckily they are easy to understand, it is only a new way of counting! We have all learned to count to 10 in decimal notation, Hexadecimal notation requires us to count by 16 instead.

**Decimal to Hexadecimal Notation Chart**

|Decimal|Hexadecimal|
|---|---|
|0 | 0x0|
|1 | 0x1|
|2 | 0x2|
|3 | 0x3|
|4 | 0x4|
|5 | 0x5|
|6 | 0x6|
|7 | 0x7|
|8 | 0x8|
|9 | 0x9|
|10|  0xA|
|11|  0xB|
|12|  0xC|
|13|  0xD|
|14|  0xE|
|15|  0xF|
|16|  0x10|
|17|  0x11|

Since its understood that hex numbers are 0-F with a value of 0-15 understanding a hex dump is easy! Hex dumps are the raw form of a file dumped to a screen or file for us to browse. They begin from the start of the file or hex 0x00 (same thing as 0). From there, they break into 16 byte lines. Each byte represents the contents of a single hexadecimal address.

   - 10101100 (8 bits or 1 byte in Binary)

   - AC (The above converted into hex form as 1 byte)

   - AC 3C (Two 1 byte hex numbers)

**Sample Hex Dump**
```
00000000: cd 10 ac 3c 00 75 f4 c3 fa b7 12 e6 00 00 80 00 
00000010: 21 02 83 0f 2e 40 00 08 00 00 df f7 ff 0f 00 00 
```
-	16 Bytes from hex address 0x00 - 0x0F (Decimal 0 - 15)
-	16 Bytes from hex address 0x10 - 0x1F (Decimal 16 - 31)

In the example above: the hex position of 0x00 contains cd and 0x02 contains ac

## GUID Partition Tables (GPT)

Much like UEFI is a newer version of BIOS, GPT(Guid Partition Tables) is a new version of MBR. Once again they do the exact same thing. Yet, GPT has quite a few advantages compared to an MBR.

   - GPT Only works with UEFI Firmware

   - GPT has many boot sectors stored around the disk as redundancy so an issue in one will not deadline the entire machine

   - GPT supports 128(and more depending on Operating System) separate physical partitions, while MBR supports only 4

   - GPT Supports partitions up to 9 zettabytes. Which is ridiculous.

[Understanding GPT Partition Tables](https://www.linux.com/training-tutorials/using-new-guid-partition-table-linux-goodbye-ancient-mbr/)

# 2nd Stage Bootloader (GRUB)

The MBR in **Grub Stage 1** loads the 2nd stage bootloader, named Grub Stage 2 or GRUB. GRUB Stage 2 rests inside the selected active partition mounted in /boot or in a completely separate partition.

## GRUB

**GRUB**(Grand Unified Bootloader) has one purpose - to load the **Linux Kernel** a user choses from a location in the hard drive. The GRUB has two stages which load it from two separate locations.
On BIOS Systems using MBR

   - Stage 1 : `boot.img` located in the first 440 bytes of the MBR loads…​

   - Stage 1.5 : `core.img` located in the MBR between the bootstrap and first partition. It loads…​

   - Stage 2 : `/boot/grub/i386-pc/normal.mod` which loads the grub menu and then reads

       - `/boot/grub/grub.cfg` Which displays a list of Linux kernels available to load on the system

	MBR is a legacy standard. Most machines don’t use it any more. Yet, it is still used every now and then in fringe situations.

### On UEFI Systems using GPT

    Stage 1 : grubx64.efi Located on an EFI partition or in /boot loads…​

    Stage 2 : /boot/grub/x86_64-efi/normal.mod

        /boot/grub/grub.cfg Which displays a list of Linux kernels available to load on the system

[GRUB 2 Chain Loading Process Resource 1](https://en.wikipedia.org/wiki/GNU_GRUB#Version_2_(GRUB_2))

[GRUB Deep Dive at GNU.org](https://www.gnu.org/software/grub/manual/grub/grub.html#Images)

**Looking at Grub configuration in Linux to find the Kernel**
```
student@linux-opstation-kspt:/$ cat /boot/grub/grub.cfg 
_truncated_
set linux_gfx_mode=auto
export linux_gfx_mode
menuentry 'Ubuntu' --class ubuntu --class gnu-linux --class gnu --class os $menuentry_id_option 'gnulinux-simple-LABEL=cloudimg-rootfs' {
        recordfail
        load_video
        gfxmode $linux_gfx_mode
        insmod gzio
        if [ x$grub_platform = xxen ]; then insmod xzio; insmod lzopio; fi
        insmod part_msdos
        insmod ext2
        if [ x$feature_platform_search_hint = xy ]; then
          search --no-floppy --fs-uuid --set=root  6c0fba3b-b236-4b3a-b999-db7359c5d220
        else
          search --no-floppy --fs-uuid --set=root 6c0fba3b-b236-4b3a-b999-db7359c5d220
        fi
        linux   /boot/vmlinuz-4.15.0-76-generic root=LABEL=cloudimg-rootfs ro  console=tty1 console=ttyS0 
        initrd  /boot/initrd.img-4.15.0-76-generic
_truncated_
```
-	Concatenate the contents of /boot/grub/grub.cfg to the screen.
-	The kernel is loaded with the command linux. The file /boot/vmlinuz-4.15.0-76-generic contains the Linux Kernel.

# Linux Kernel

The Kernel is the **heart of a Operating System**. It has complete control on everything within it such as memory management, device management, Input/output Device request control, and managing process scheduling with the Central processing unit.

The Linux Kernel originated from the Unix kernel and is unique from Windows in that it is :
1. A Monolithic Kernel

   - System calls all functionality to the user such as CPU scheduling, memory management, and file management. A `systemcall` is a way in which a program requests services from the kernel. **Everything that occurs on the system occurs through a systemcall**

**Showing System calls in Linux**
```
student@linux-opstation-kspt:/$ ltrace -S cat /etc/passwd 
_truncated_
open("/etc/passwd", 0, 037777402000 <unfinished ...>  
SYS_openat(0xffffff9c, 0x7ffcbb66d68c, 0, 0)       = 3
<... open resumed> )                               = 3
__fxstat(1, 3, 0x7ffcbb66be40 <unfinished ...>
SYS_fstat(3, 0x7ffcbb66be40)                       = 0
<... __fxstat resumed> )                           = 0
posix_fadvise(3, 0, 0, 2 <unfinished ...>
SYS_fadvise64(3, 0, 0, 2)                          = 0
<... posix_fadvise resumed> )                      = 0
malloc(135167 <unfinished ...>
SYS_mmap(0, 0x22000, 3, 34)                        = 0x7f0b09df0000
<... malloc resumed> )                             = 0x7f0b09df0010
read(3 <unfinished ...>
SYS_read(3, "root:x:0:0:root:/root:/bin/bash\n"..., 131072) = 1875
<... read resumed> , "root:x:0:0:root:/root:/bin/bash\n"..., 131072) = 1875 
write(1, "root:x:0:0:root:/root:/bin/bash\n"..., 1875 <unfinished ...> 
```
-	Execute `ltrace` to track the systemcalls occurring when running cat /etc/passwd.
-	open systemcall on /etc/passwd returns a file descriptor of 3.
-	`read` systemcall on file descriptor of 3 returns the amount of bytes in the file.
-	`write` systemcall to write all the 1875 bytes from /etc/passwd to stdout.

[Linux System Calls](https://man7.org/linux/man-pages/man2/syscalls.2.html)

2. Modular

    Modules are extensions to base functionality of the Linux Operating System. This modularity allows for modifications baseline system functionality without rebuilding the kernel and failures will not stop the machine from starting.

**Modules in Linux**
```
student@linux-opstation-kspt:/$ ltrace -S lsmod  

Module                  Size  Used by
aesni_intel           188416  0
aes_x86_64             20480  1 aesni_intel 
crypto_simd            16384  1 aesni_intel
glue_helper            16384  1 aesni_intel
cryptd                 24576  3 crypto_simd,ghash_clmulni_intel,aesni_intel
psmouse               151552  0
ip_tables              28672  0
virtio_blk             20480  2 
virtio_net             49152  0
virtio_rng             16384  0
virtio_gpu             53248  3
```
-	Execute `lsmod` to list modules in Linux
-	Module required to use AES Encryption
-	Modules for Virtual Input / Output Devices used in Openstack instances.

# Init

The kernel, once loaded, is hard coded to reach out and execute `/sbin/init`. This starts the process of bringing the system to a desired level of functionality using Initialization Daemons. There are two main initialization daemons now : **Systemd** and **SysV**.

[Stack Overflow article on how the kernel knows to load /sbin/init](https://serverfault.com/questions/372007/linux-kernel-and-the-init-process)

[See Line 798 for hard coded /sbin/init](https://elixir.bootlin.com/linux/v2.6.24/source/init/main.c)

A term used in **Init** is a **Run Level**. A Run Level defines the state of a machine after it has completed booting and is prompting for a user login. Run levels numbered from zero(0) to six(6) have special meaning, but they are not rigid in definition.

**Run Level meanings** 
|Run Level|Meaning|Description|
|---|---|---|
|0 | Halt | Shutdown the system|
|1 | Single User | Allow a single user to login session with No network functionality. Used to troubleshoot.|
|2 | Multi-user mode | Allow multiple user to login sessions with No network functionality.|
|3 | Multi-user mode with networking | Allow multiple user to login sessions with complete networking functionality|
|4 | Not used/user-definable | Nothing, can be set to anything|
|5 | Multi-user mode with networking and GUI Desktop | Allow multiple user to login sessions with complete networking functionality and a graphical desktop instead of a Bash terminal|
|6 | Reboot | Restart the system|

## SysV

SysV initialization is a legacy system initialization method, but it is still used today in many older systems Linux systems or Unix machines like Oracle’s Solaris. It starts with the kernel executing the first process on the machine, or the **Initialization daemon**. In SysV machines it is the `/etc/init `program. Then, `init` reads `/etc/inittab` to start creating processes in groups called **Run Levels**. The processes that each **Run Level** starts are defined in `/etc/rc*.d`

### SysV Init Daemon

The program `/etc/init` is the first process to start in SysV Linux machines. The kernel spawns `/sbin/init`. Its role is to initialize the system to a target run level specified in /etc/inittab.

The file `/etc/inittab` is a text file that contains **Run Level** entries as variables read by `/etc/init`. Entries numbered 0-6 specify a directory with scripts to start at the specified **Run Level**. By default the system will try to start the **initdefault** run level. If that fails to start, the machine will display an error, then execute the scripts in the 0(halt) run level.

[Oracle Documentation on the Inittab File](https://docs.oracle.com/cd/E19683-01/817-3814/6mjcp0qgh/index.html)

**Sample of /etc/initab on a SysV machine**
```
cat /etc/inittab

is:5:initdefault: 

l0:0:wait:/etc/rc0.d
l1:1:wait:/etc/rc1.d
l2:2:wait:/etc/rc2.d
l3:3:wait:/etc/rc3.d
l4:4:wait:/etc/rc4.d 
l5:5:wait:/etc/rc5.d
l6:6:wait:/etc/rc6.d
```
-	The run level 5 is the default run level in /etc/inittab
-	Another non-default run level is in /etc/rc4.d

### Run Levels

**Run Levels** in SysV are a series of scripts that start or kill background processes on Linux at specific run levels. The scripts have a specific naming scheme that determine how the `init` process interacts with them.

   - The first letter `K` or `S` means `Kill` or `Start` the process that that script handles

   - The two digit number that follows `K` or `S` dictates the order the scripts execute

Another name for background processes (or services) in Linux is a **daemon**. Daemons run in the background and maintain user mode functionality such as DHCP or enabling SSH.

**Sample contents of a /etc/rc#.d directory**
```
student@linux-opstation-kspt:/etc/rc3.d$ ls -l /etc/rc3.d/ 

lrwxrwxrwx 1 root root 15 Jan 31  2020 S01acpid -> ../init.d/acpid 
lrwxrwxrwx 1 root root 17 Feb  4  2020 S01anacron -> ../init.d/anacron
lrwxrwxrwx 1 root root 16 Jan 31  2020 S01apport -> ../init.d/apport
lrwxrwxrwx 1 root root 13 Jan 31  2020 S01atd -> ../init.d/atd
lrwxrwxrwx 1 root root 26 Jan 31  2020 S01console-setup.sh -> ../init.d/console-setup.sh
lrwxrwxrwx 1 root root 14 Jan 31  2020 S01cron -> ../init.d/cron
lrwxrwxrwx 1 root root 14 Jan 31  2020 S01dbus -> ../init.d/dbus
lrwxrwxrwx 1 root root 14 Feb  4  2020 S01gdm3 -> ../init.d/gdm3

student@linux-opstation-kspt:/etc/rc3.d$ ls -l /etc/rc1.d/ 

lrwxrwxrwx 1 root root 20 Feb  4  2020 K01alsa-utils -> ../init.d/alsa-utils
lrwxrwxrwx 1 root root 13 Jan 31  2020 K01atd -> ../init.d/atd
lrwxrwxrwx 1 root root 20 Jan 31  2020 K01cryptdisks -> ../init.d/cryptdisks
lrwxrwxrwx 1 root root 26 Jan 31  2020 K01cryptdisks-early -> ../init.d/cryptdisks-early
lrwxrwxrwx 1 root root 18 Jan 31  2020 K01ebtables -> ../init.d/ebtables
lrwxrwxrwx 1 root root 14 Feb  4  2020 K01gdm3 -> ../init.d/gdm3 
```
-	List the contents of the `/etc/rc3.d/` directory
-	S01acpid is *symbolically linked to `../init.d/acpid`
-	List the contents of the `/etc/rc1.d/` directory
-	Notice how the **S** is a **K** now? What run level is this?

**Looking at an bash script in /etc/init.d/gdm3**
```
#! /bin/sh 
### BEGIN INIT INFO

_truncated_

PATH=/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/sbin/gdm3 
PIDFILE=/var/run/gdm3.pid

test -x $DAEMON || exit 0
```
-	the `#!/bin/bash` shows that this is a bash script.
-	`/usr/sbin/gdm3` is the program run for this daemon.

The last thing to start is the login program. `init` spawns a login to each of the Linux virtual consoles. The `getty` command specified in the `inittab` displays this login. When given a login name, `getty` invokes `/bin/login`, which prompts the user for a password, authentication to the system takes place, and brings a terminal back.

## Systemd

Systemd is the modern initialization method. It starts with the kernel spawning `/sbin/init` which is symbolically linked to `/lib/systemd/system`. `systemd` interacts with flat configuration files called **units**. There are many types, but the **target** and service **units** determine system initialization.

### Systemd Init target.units

The kernel spawns `/usr/lib/systemd/system` as the first process on the system. It then executes configurations starting at mounting the local file system to bringing the system to a desired state specified in the default **target** unit. Targets in systemd are like runlevels in SysV. The name of the default target is `default.target` and located in `/lib/systemd/system`.

**Translating between Run Levels and Systemd Targets** 
|Run Level | Meaning | Systemd Target|
|---|---|---|
|0 | Halt | poweroff.target|
|1 | Single User | rescue.target|
|2 | Multi-user mode | multi-user.target|
|3 | Multi-user mode with networking | multi-user.target|
|4 | Not used/user-definable | multi-user.target|
|5 | Multi-user mode with networking and GUI Desktop | graphical.target|
|6 | Reboot | reboot.target|

[Systemd Target Unit to Runlevel Translate Source](https://www.computernetworkingnotes.com/linux-tutorials/systemd-target-units-explained.html)

**Showing the default target unit**
```
student@linux-opstation-kspt:/$ ls -lisa /lib/systemd/system/default.target

lrwxrwxrwx 1 root root 16 May  3 11:30 default.target -> graphical.target 
```
-	Symbolically linked default.target to graphical.target unit.
-	The system will, by default, try to run the system to the specifics set by graphical.target.

### Target units

Systemd **target** units are a set of `value=data` pairs to create processes in a set order on the system. But, they are simple to understand at a functional level by understanding the `value=data` fields within each.

**Examining the Contents of the graphical.target**
```
cat /lib/systemd/system/default.target | tail -n 8

Description=Graphical Interface
Documentation=man:systemd.special(7)
Requires=multi-user.target
Wants=display-manager.service 
Conflicts=rescue.service rescue.target
After=multi-user.target rescue.service rescue.target display-manager.service 
AllowIsolate=yes
```
-	`wants=display-manager.service` attempts to start other units. If they fail to start, the calling target unit **will still execute**.
-	`requires=multi-server.target` attempts to start other units. If they fail to start, the calling target unit **will fail to execute**.

Yet, **wants** and **requires** statements can also come from other locations on the file system. Target units search for dependencies in **eleven** other locations around the file system.

Target.unit want and requires dependencies search locations

   - `/etc/systemd/system/*`

   - `/lib/systemd/system/*`

   - `/run/systemd/generator/*`

   - More found in [System Unit Man Page](https://www.man7.org/linux/man-pages/man5/systemd.unit.5.html)

**Showing more wants and requires to graphical.target — Run on Ops Station**
```
student@linux-opstation-kspt:/$ ls -l /etc/systemd/system/ | grep graphical
drwxr-xr-x 2 root root 4096 Feb  4  2020 graphical.target.wants 

student@linux-opstation-kspt:/$ ls -l /etc/systemd/system/graphical.target.wants/
total 0
lrwxrwxrwx 1 root root 43 Jan 31  2020 accounts-daemon.service -> /lib/systemd/system/accounts-daemon.service  
lrwxrwxrwx 1 root root 35 Feb  4  2020 udisks2.service -> /lib/systemd/system/udisks2.service 

student@linux-opstation-kspt:/$ ls -l /lib/systemd/system | grep graphical
lrwxrwxrwx 1 root root   16 Nov 15  2019 default.target -> graphical.target
-rw-r--r-- 1 root root  598 Jan 28  2018 graphical.target
drwxr-xr-x 2 root root 4096 Jan 31  2020 graphical.target.wants 
lrwxrwxrwx 1 root root   16 Nov 15  2019 runlevel5.target -> graphical.target

student@linux-opstation-kspt:/$ ls -l /lib/systemd/system/graphical.target.wants/
total 0
lrwxrwxrwx 1 root root 39 Nov 15  2019 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service 
```
-	A **graphical.target** wants directory in `/etc/systemd/system/`
-	**graphical.target** also target wants **udisks2.service** and **accounts-daemon.service**
-	Yet another **graphical.target** wants directory in `/lib/systemd/system/`
-	**graphical.target** also wants **systemd-update-utmp-runlevel.service**

Breaking it down into steps brings the following conclusion:

   - This means that the `default.target` is actually `graphical.target`

   - The `graphical.target` unit wants to start:

       - `display-manager.service`

       - `udisks2.service`

       - `accounts-daemon.service`

       - `systemd-update-utmp-runlevel.service`

   - But, the `graphical.target` requires the `multi-user.targe`t to execute.

[Understanding systemd.units](https://www.man7.org/linux/man-pages/man5/systemd.unit.5.html)

### Service units

**Service** units create processes when called by **target** units. They, much like **target units**, have `value=data` pairs that determine what the unit does.

**Examining the Contents of the display-manager.service**
```
cat /etc/systemd/system/display-manager.service | tail -n 13

[Service]
ExecStartPre=/usr/share/gdm/generate-config
ExecStart=/usr/sbin/gdm3 
KillMode=mixed
Restart=always 
RestartSec=1s
IgnoreSIGPIPE=no
BusName=org.gnome.DisplayManager
StandardOutput=syslog
StandardError=inherit
EnvironmentFile=-/etc/default/locale
ExecReload=/usr/share/gdm/generate-config
ExecReload=/bin/kill -SIGHUP $MAINPID
```
-	`ExecStart=/usr/sbin/gdm3` causes the systemd process to execute the command specified along with any arguments.
-	`Restart=always` tells systemd to attempt to restart the command in **ExecStart**.

[Understanding systemd service units](https://www.man7.org/linux/man-pages/man5/systemd.service.5.html)

### Systemd putting it all together

Systemd is a complex initialization method with interweaving dependencies, hundreds of files across the system, and unique file types. It is possible to query each file and use the `find` command to locate dependencies, but there is a much easier way. The `systemctl` command comes with every systemd machine to query and manage details relating to its dependencies.

By default, `systemctl` shows every unit file currently visible by systemd. However, it takes arguments to:

**1. List unit dependencies in a tree form**
```
systemctl list-dependencies graphical.target

graphical.target
● ├─accounts-daemon.service
● ├─apport.service
● ├─gdm.service 
● ├─grub-common.service
● ├─qemu-guest-agent.service
● ├─systemd-update-utmp-runlevel.service
● ├─udisks2.service 
● ├─ureadahead.service
● └─multi-user.target 
●   ├─anacron.service
```
-	Wants statements to **graphical.target**
-	Requires statements to **graphical.target**
​
**2. Show wants to individual units.**
```
systemctl show -p Wants graphical.target

Wants=ureadahead.service qemu-guest-agent.service gdm.service systemd-update-utmp-runlevel.service grub-common.service accounts-daemon.service udisks2.service apport.service 
```
-	That is a lot more wants statements than found in the 2 directories we searched in 6.2.2.

**3. List every individual unit file.**
```
systemctl list-unit-files

UNIT FILE                                  STATE
spice-vdagent.service                      enabled
spice-vdagentd.service                     enabled
ssh.service                                enabled 
ssh@.service                               static
sshd.service                               enabled
stop-bootlogd-single.service               masked

_truncated_
339 unit files listed. 
```
-	A unit file for **ssh.service**
-	Total number of unit files seen by **systemd**
​
**4. Concatenate the contents of a unit file to the screen.**
```
systemctl cat graphical.target

# /lib/systemd/system/graphical.target
#  SPDX-License-Identifier: LGPL-2.1+
#
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

[Unit]
Description=Graphical Interface
Documentation=man:systemd.special(7)
Requires=multi-user.target
Wants=display-manager.service
Conflicts=rescue.service rescue.target
After=multi-user.target rescue.service rescue.target display-manager.service
AllowIsolate=yes
```

**7. Post Boot**

Actions in the post boot stage encompass user shell environment customization with scripts and text files read by other programs. Each file is read at specific point when users log in. Each locate presented in the post boot process is easily changeable unlike earlier stages of the boot process. Adversaries can take advantage of this flexibility to run any script they want. Be mindful of that when evaluating a Linux system.

## The /etc/environment file

The `/etc/environment` file sets **Global Variables**. **Global Variables** are accessible by every user or process on the system. It is read once when the machine completes Init. Any changes to the file require a system restart for them to apply.

In the example below, `/etc/environment` is setting the **PATH** variable. This variable is the search path for executables from the command line. It allows a user to type `ls` instead of `/bin/ls` when they want to use it.

The /etc/environment file is part of [PAM(Pluggable Authentication Modules) 6.6.1](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/4/html/reference_guide/ch-pam) used to authenticate users in Linux. That is why it isn’t a bash script like everything else.

**Looking at /etc/environment**
```
cat /etc/environment

PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games" 
```
-	The path variable contains all default locations to executables in Linux delimited by :.
	
Executables not located in the path can not be executed by typing in the name of the executable, unless it is located in the same directory. Instead, the absolute or relative path to the executable must be given.

[Ubuntu Help: Persistent environment variables](https://help.ubuntu.com/community/EnvironmentVariables)

## The /etc/profile file

`/etc/profile` is a script that executes whenever a user logs into an **interactive** shell on Linux. its functionality depends entirely on the version of Linux being used. Ubuntu Linux uses it to set the BASH shell prompt by executing `/etc/bash.bashrc` and execute any script named `*.sh` in `/etc/profile.d`.

Unlike `/etc/environment` it executes **every time a user logs in interactively**; therefore, when the file is modified logging out then in again will apply the changes.

[Interactive Logins](https://tldp.org/LDP/abs/html/intandnonint.html) accept user input from a tty or commandline. Non-Interactive logins, such as the ones used by services or ssh remote commands, will not execute `/etc/profile`

**Examining /etc/profile**
```
student@linux-opstation-kspt:~$ cat /etc/profile

# /etc/profile: system-wide .profile file for the Bourne shell (sh(1))
# and Bourne compatible shells (bash(1), ksh(1), ash(1), ...).

if [ "${PS1-}" ]; then
  if [ "${BASH-}" ] && [ "$BASH" != "/bin/sh" ]; then 
    # The file bash.bashrc already sets the default PS1.
    # PS1='\h:\w\$ '
    if [ -f /etc/bash.bashrc ]; then 
      . /etc/bash.bashrc  
    fi
_truncated_
if [ -d /etc/profile.d ]; then
  for i in /etc/profile.d/*.sh; do
    if [ -r $i ]; then
      . $i 
    fi
  done
  unset i
fi
```
-	If the variable $BASH is set and does not equal /bin/sh then execute
-	if the /etc/bash.bashrc exists, execute it.
-	/etc/bash.bashrc creates the bash prompt student@linux-opstation-kspt:~$
-	If the directory /etc/profile.d exists, execute any script named *.sh in that directory.

## The .bash_profile and .bashrc files

Unique to BASH(Bourne Again Shell) are `.bash_profile` and `.bashrc`. They execute on a per user basis for interactive logins only. Both files are located every user’s `/home` directory. They are user specific configurations and freely editable by the owning user or root.

`.bash_profile` is a bash script that executes when a user invokes an interactive login shell on the system. Interactive login shells only occur when prompted for a password while logging in like when using ssh or telnet to access a system. `.bash_profile` is also called `.profile` on many systems as well.

`.bashrc` on the other hand, executes when interactive non-login shell is invoked. Non-Login interactive shells occur when not prompted for credentials.

**Demonstrate the difference between interactive login shells and Non-Login interactive shells**
```
student@linux-opstation-kspt:~$ cd $HOME
student@linux-opstation-kspt:~$ echo "echo 'Im in `~/.profile`'" >> .profile 
student@linux-opstation-kspt:~$ echo "echo 'Im in ~/.bashrc'" >> .bashrc 

student@linux-opstation-kspt:~$ bash
student@linux-opstation-kspt:~$ Im in ~/.bashrc
student@linux-opstation-kspt:~$ exit 
student@linux-opstation-kspt:~$ exit 

#Log back into same Linux machine
Last login: Fri Feb 26 12:55:13 2021 from 10.250.0.20
Im in ~/.bashrc
Im in /etc/profile 
student@linux-opstation-kspt:~$
```
-	Echo a phrase into .profile and .bashrc
-	Create a **Non-Login interactive shell** by spawning a new bash session
-	Exit the new session AND logout of the machine
-	Logins create an **interactive login shell**; therefore,

[Understanding .bash_profile and .profile](https://www.baeldung.com/linux/bashrc-vs-bash-profile-vs-profile)

[TLDP 1.2.2.2. Bash startup files](https://tldp.org/LDP/Bash-Beginners-Guide/html/Bash-Beginners-Guide.html)
