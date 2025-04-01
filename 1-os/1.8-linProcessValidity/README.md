# Process Listing

A **process** is one of the most important fundamental concepts of the Linux Operating System. A process refers to a program in execution; it is a running instance of a program. It is made up of the program instruction, data read from files and other programs or input from a system user.

Each Linux system has numerous processes running. You may be familiar, or will become familiar, with most of these processes if you regularly use commands like "ps" or "top" to display them.

## ps command

The `ps` command is a native Unix/Linux utility for viewing information concerning a selection of running processes on a system: it reads this information from the virtual files in /proc filesystem

**Output of ps command**
```
student@linux-opstation-grkv:~$ ps 
  PID TTY          TIME CMD
 7198 pts/1    00:00:00 bash 
 7213 pts/1    00:00:00 ps
```
-	`ps` (report a snapshot of the current processes) command
-	the output provides information about the currently running processes, including their process identification numbers (PID).


## top command

The `top` command is used to show the Linux processes. It provides a dynamic real-time view of the running system. Usually, this command shows the summary information of the system and the list of processes or threads which are currently managed by the Linux Kernel. Additional columns, like `ppid`, can be added by pressing `f` in the main window. A hierarchical view of the process tree can be displayed by pressing `shift + v`.

**Output of top command**
```
student@linux-opstation-grkv:~$ top 

top - 15:30:43 up 2 days, 13:04,  3 users,  load average: 0.00, 0.00, 0.00
Tasks: 205 total,   1 running, 167 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.3 us,  0.7 sy,  0.0 ni, 99.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
KiB Mem :  4039312 total,  2133660 free,  1070632 used,   835020 buff/cache
KiB Swap:        0 total,        0 free,        0 used.  2642820 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S %CPU %MEM     TIME+ COMMAND 
 1572 gdm       20   0  802524  50388  37608 S  0.3  1.2   0:53.50 gsd-color
 7239 student   20   0   44540   4028   3392 R  0.3  0.1   0:00.16 top
    1 root      20   0  159928   9144   6728 S  0.0  0.2   0:08.14 systemd
-- Truncated
```
-	`top` command provides a dynamic real-time view of a running system
-	the output displays the summary information for the system and a dynamic list of processes currently managed by the Linux kernel

## htop command

Similar to `top`, `htop` is a utility used to display various information about Linux processes dynamically, but in a more human friendly way. Also like `top` it can be configured to show an operator exactly the set of information needed for the task at hand. At the bottom of the `htop` window there is a bar with some available actions, namely F5 to present the process listing in a hierarchicall tree view, and `F2` to add or remove columns such as `ppid`.

# Startup Processes

The startup process follows the boot process and brings the Linux computer to an operational state in which it is usable for productive work. It is highly important that a demarcation is established in virtual memory to prevent programs running in user space to directly interact with the kernel.

Executing the `ps` command with the `-elf` argument will do a full format listing of all running processes on the system in long format

**Output of ps -elf command**
```
student@linux-opstation-grkv:~$ ps -elf | head 
F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY          TIME CMD         
4 S root         1     0  0  80   0 - 39982 -      Feb25 ?        00:00:08 /sbin/init  
1 S root         2     0  0  80   0 -     0 -      Feb25 ?        00:00:00 [kthreadd]  

--Truncated
```
-	`ps -elf` command will do a full format listing of all processes. Snapshot above shows the two primary processes after startup
	shows the fields
```
F:      Field Table
S:      Current status of the process
UID:    The effective user ID of the process's owner
PID:    Process ID
PPID:   The parent process's ID
C:      The processor utilization for scheduling. This field is not displayed when the -c option is used
PRI:    The kernel thread's scheduling priority. Higher numbers mean higher priority
NI:     The process's nice number, which contributes to its scheduling priority. Making a process "nicer" means lowering its priority
ADDR:   The address of the proc structure
SZ:     The virtual address size of the process
WCHAN:  The address of an event or lock for which the process is sleeping
STIME:  The starting time of the process (in hours, minutes, and seconds)
TTY:    The terminal from which the process (or its parent) was started. A question mark indicates there is no controlling terminal
TIME:   The total amount of CPU time used by the process since it began
CMD:    The command that generated the process
```
-	`init (/sbin/init)` has a process ID of 1; and its parent, the Kernel has a PID of 0. The kernel starts `/sbin/init` which is the parent/grandparent of all user mode processes.
-	Modern Linux kernels/distros also have `[kthreadd]` which is a kernel thread daemon which is second after init so it will have a PID of 2 and will also have no parent.

**Key Points**

   - All kernel processes are fork()ed from `[kthreadd]` and all user processes are fork()ed from `/sbin/init` or direct ancestor.

   - Kernel processes are typically used to manage hardware, are directly handled by the kernel, have their own memory space, and have a high priority.

   - They can be identified by the name enclosed in square brackets `[ ]` (using the `ps -f` option). `kthreadd` -spawned processes will have a PPID of 2.

   - **Q**: What are the primary parent processes of all running processes on the system?

       - **A**: There are two primary processes after startup:

           - For user-space processes `/sbin/init` **( PID = 1 )**

           - For kernel-space processes `[kthreadd]` **( PID = 2 )**

**Operational Value**

   - The Linux OS is at it’s core the sum of all running processes.

   - Understanding the difference between User and Kernel mode processes, as well as the Parent/Child relationship of processes, is fundamental to understanding how a Linux machine works.

# Concepts of Virtual Memory

Virtual memory is divided into kernel space and user space

## Kernel Space

Kernel space is that area of virtual memory where kernel processes will run. This division is required for memory access protections. Code running in kernel mode has **unrestricted access** to the processor and main memory. This is a powerful but dangerous privilege that allows a kernel process to easily crash the entire system. The kernel is the core of the operating system. It normally has full access to all memory and machine hardware (and everything else on the machine). To keep the machine as stable as possible, you normally want only the most trusted, well-tested code to run in kernel mode/kernel space.

Executing code in kernel space will give it unrestricted access to any of the memory address space and to any underlying hardware. Kernel space is reserved for the highest of trusted functions within a system. Kernel mode is generally reserved for the lowest-level (ring 0), most trusted functions of the operating system. Due to the amount of access the kernel have, any instability within the kernel’s executing code can result in complete system failure.

Kernel space can be accessed by user processes only through the use of system calls.

## User Space

   - **User mode**, in comparison, restricts access to a (usually quite small) **subset of memory** and safe CPU operations. User space refers to the parts of main memory that the user processes can access. If a process makes a mistake and crashes, the consequences are limited and can be cleaned up by the kernel. This means that if your web browser crashes, it won’t take down the whole system. Think of it as a form of sand-boxing — it restricts user programs so they can’t mess with memory (and other resources) owned by other programs or by the OS kernel. This limits (but usually doesn’t entirely eliminate) their ability to do bad things like crashing the machine. Because of the restricted access, malfunctions within user mode are limited only to the system space they are operating within.

## OS Protection

In Computer Science, the ordered protection domains are referred to as Protection Rings. These mechanisms help in improving fault tolerance and provide Computer Security. Operating Systems provide different levels to access resources. Rings are hierarchically arranged from most privileged to least privileged.

![OS_Protection_Ring](../../0-src/OS_Protection_Ring.png)

Use of Protection Rings provides logical space for the levels of permissions and execution. Two important uses of Protection Rings are:

   - Improving Fault Tolerance

   - Provide Computer Security

There are basically 4 levels ranging from 0 which is the most privileged to 3 which is least privileged. Most Operating Systems use level 0 as the kernel or executive and use level 3 for application programs.

   - Rings 1-2 cannot run privileged instructions but this is the only real limit; otherwise they are as privileged as ring 0. The intent by Intel in having rings 1 and 2 is for the OS to put device drivers at that level, so they are privileged, but somewhat separated from the rest of the kernel code.

**Operational Value**

   - The goal in most, if not all, exploitative exercises is to be able to manipulate kernel mode processes and memory.

   - In doing so, an adversary can gain complete control over the OS and obfuscate their methodology.

# Process Ownership, Effective User ID (EUID), Real User ID (RUID), User ID (UID)

The Linux kernel supports the traditional concept of a Unix user. A user is an entity that can run processes and own files. A user is also associated with a username.

## Process Ownership

A Linux process is nothing but running instance of a program. For example, when you start Firefox to browse Internet, you can create a new process. In Linux, each process is given a unique number called as a process identification (PID). Linux kernel makes sure that each process gets a unique PID. `/sbin/init` or `/lib/systemd/systemd` on modern Linux distros always has a PID of 1 because it is eternally the first process on the Linux based system.

   - **A user is an entity that can run processes and own files**. Users exist primarily to support permissions and boundaries. Every user-space process has a user owner, and processes are said to run as the owner. A user may terminate or modify the behavior of its own processes (within certain limits), but it cannot interfere with other users’ processes. In addition, users may own files and choose whether they share them with other users.

   - Users of the system may be:

       - Human Users = people who log into the system; or

       - System Users = used to start non-interactive background services such as databases

   - From the perspective of the operating system, there is no distinction between human users and system users and all the information is stored in the same file. However, there is a range of user IDs reserved for human users and another range for system users. To view this range, execute the following command and point out that the system UID’s range from 100 - 999 and the user range is 1000 - 60000.

**Show range of User IDs for system and human users**
```
  student@linux-opstation-grkv:~$ grep UID /etc/login.defs                  

	UID_MIN:                1000        
	UID_MAX:                60000       
	#SYS_UID_MIN:           100         
	#SYS_UID_MAX:           999         
```
-	grep for UID from the shadow password suite configuration file `login.defs`
-	minimum userid assigned to a regular user
-	maximum userid assigned to a regular user
-	minimum userid assigned to a system user
-	maximum userid assigned to a system user

## Effective User ID (EUID)

Effective user ID (EUID) defines the access rights for a process. In layman’s term it describes the user whose file access permissions are used by the process.

## Real User ID (RUID)

The real user ID is who you really are (the one who owns the process). It also defines the user that can interact with the running process—most significantly, which user can kill and send signals to a process.

   - Users can only modify / interact with files /processes that they own or that have been shared with them.

-	The distinction between a real and an effective user id is made because you may have the need to temporarily take another user’s identity (most of the time, that would be root, but it could be any user).

-	EUID and RUID are mostly always the same. They can be different when special permissions (like SUID bits) are set on files.

**Viewing special permissions on passwd executables**
```
student@linux-opstation-grkv:~$ ls -l /usr/bin/passwd         
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /usr/bin/passwd
   ^          ^
  <2>        
```
-	command list permissions of the passwd executables
-	depicts that the SUID bit is set on the executable
-	shows that the SUID bit is set by the user root

In the example above; the SUID bit is set on the passwd executable so that when a normal user (non-root user) attempts to change their password, the executable is run with effective permissions of root. In this instance the real user is the non-root user and effective user is root.

**Operational Value**

   - The "context" that a program runs in is something that is very important to keep track of. For Example:

       - The `/usr/bin/passwd` command runs with an EUID of root no matter who runs it.

           - `ls -l /usr/bin/passwd`

       - This is done, because when a user updates their password, the `/etc/shadow` file is overwritten, which can only be done by root.

       - However, the `passwd` command tracks the RUID ensuring that a normal user can’t change another user’s password

# System Calls

## Starting a new process

![Spawning](../../0-src/linproc1.png)

-	original process
-	original process asking the kernel to create another process must perform a fork() system call
-	original process after fork() system call
-	identical copy of original process after fork() system call
-	identical copy of original process performs exec(ls) system call
-	kernel replaces identical copy of original process with that of the new process

   - **Q**: What exactly is a system call?

       - **A**: A system call is an interaction between a process and the kernel, a programmatic way in which a computer program requests a service from the kernel of the operating system it is executed on. For example, the acts of opening, reading, and writing files all involve system calls.

## Fork() and Exec() System calls

Two system calls, **fork** and **exec**, are important to understanding how processes startup:

   - **fork** - creates a new process by duplicating the calling process. The new process is referred to as the child process. The calling process is referred to as the parent process.

       - The fork “processes” can be explained as the recreation of a process from system space and duplicated into user space in an attempt restrict user access to system processes/space.

   - **exec** - When a process calls exec, the kernel starts program, replacing the current process.

Some popular system calls are `open, read, write, close, wait, exec, fork and kill`.

### Table 1. Common System Calls 	

| |Windows|Unix|
|---|---|---|
|Process Control|CreateProcess()|fork()|
| |ExitProcess()|exit()|
| |WaitForSingleObject()|wait()|
|File Manipulation|CreateFile()|open()|
| |ReadFile()|read()|
| |WriteFile()|write()|
| |CloseHandle()|close()|
|Device Manipulation|SetConsoleMode()|ioctl()|
| |ReadConsole()|read()|
| |WriteConsole()|write()|
|Information Maintenance|GetCurrentProcessID()|getpid()|
| |SetTimer()|alarm()|
| |Sleep()|sleep()|
|Communication|CreatePipe()|pipe()|
| |CreateFileMapping()|shmget()|
| |MapViewOfFile()|mmap()|
|Protection|SetFileSecurity()|chmod()|
| |InitializeSecurityDescriptor()|umask()|
| |SetSecurityDescriptorGroup()|chown()|

**Operational Value**

   - An existing executables weakness is that system call instructions are easily identifiable, which makes them potentially vulnerable to scanning attacks. You can make system call instructions harder to identify by disguising them as other, less conspicuous, instructions (e.g., load, store, or div instructions).
   - It’s beyond the scope of this course to get into all the types of system calls.
   - Still, it’s important to understand what they are, and a lot of information can be gleaned from monitoring specific ones.

## Linux - Signals

Signals are software interrupts sent to a program to indicate that an important event has occurred. The events can vary from user requests to illegal memory access errors. Some signals, such as the interrupt signal, indicate that a user has asked the program to do something that is not in the usual flow of control.

Every signal has a default action associated with it. The default action for a signal is the action that a script or program performs when it receives a signal.

Some of the possible default actions are −

Terminate the process.
Ignore the signal.
Dump core. This creates a file called core containing the memory image of the process when it received the signal.
Stop the process.
Continue a stopped process

**Key Points**
`kill -9 <PID>` or `pkill -9 <process name>`
- Stop Process = `SIGSTOP(19)` (pause signal, let’s you continue later, does not kill process)
- End Process = `SIGTERM(15)` (termination signal, the right way, the application can intercept this signal and initiate shutdown tasks such as temp file cleanup)
- Kill Process = `SIGKILL(9)` (kill signal, extreme, only use if SIGTERM doesn’t work, won’t initiate shutdown tasks)

**Table 2. Common Signals in Linux**

|Signal | Name | Description|
|---|---|---|
|SIGHUP | 1 | Hangup (POSIX)|
|SIGINT | 2 | Terminal interrupt (ANSI)|
|SIGQUIT | 3 | Terminal quit (POSIX)|
|SIGILL | 4 | Illegal instruction (ANSI)|
|SIGTRAP | 5 | Trace trap (POSIX)|
|SIGIOT | 6 | IOT Trap (4.2 BSD)|
|SIGBUS | 7 | BUS error (4.2 BSD)|
|SIGFPE | 8 | Floating point exception (ANSI)|
|SIGKILL | 9 | Kill(can’t be caught or ignored) (POSIX)|
|SIGUSR1 | 10 | User defined signal 1 (POSIX)|
|SIGSEGV | 11  |Invalid memory segment access (ANSI)|
|SIGUSR2 | 12 | User defined signal 2 (POSIX)|
|SIGPIPE | 13 | Write on a pipe with no reader, Broken pipe (POSIX)|
|SIGALRM | 14 | Alarm clock (POSIX)|
|SIGTERM | 15 | Termination (ANSI)|
|SIGSTKFLT | 16 | Stack fault|
|SIGCHLD | 17 | Child process has stopped or exited, changed (POSIX)|
|SIGCONTv | 18 | Continue executing, if stopped (POSIX)|
|SIGSTOP | 19 | Stop executing(can’t be caught or ignored) (POSIX)|
|SIGTSTP | 20 | Terminal stop signal (POSIX)|
|SIGTTIN | 21 | Background process trying to read, from TTY (POSIX)|
|SIGTTOU | 22 | Background process trying to write, to TTY (POSIX)|
|SIGURG | 23 | Urgent condition on socket (4.2 BSD)|
|SIGXCPU | 24 | CPU limit exceeded (4.2 BSD)|
|SIGXFSZ  |25 | File size limit exceeded (4.2 BSD)|
|SIGVTALRM | 26 | Virtual alarm clock (4.2 BSD)|
|SIGPROF | 27 | Profiling alarm clock (4.2 BSD)|
|SIGWINCH | 28 | Window size change (4.3 BSD, Sun)|
|SIGIO | 29 | I/O now possible (4.2 BSD)|
|SIGPWR | 30 | Power failure restart (System V)|

**List Supported signals**
```
student@linux-opstation-grkv:~$ kill -l                             
 1) SIGHUP	 2) SIGINT	 3) SIGQUIT	 4) SIGILL	 5) SIGTRAP         
 6) SIGABRT	 7) SIGBUS	 8) SIGFPE	 9) SIGKILL	10) SIGUSR1
11) SIGSEGV	12) SIGUSR2	13) SIGPIPE	14) SIGALRM	15) SIGTERM
16) SIGSTKFLT	17) SIGCHLD	18) SIGCONT	19) SIGSTOP	20) SIGTSTP
21) SIGTTIN	22) SIGTTOU	23) SIGURG	24) SIGXCPU	25) SIGXFSZ
26) SIGVTALRM	27) SIGPROF	28) SIGWINCH	29) SIGIO	30) SIGPWR
31) SIGSYS	34) SIGRTMIN	35) SIGRTMIN+1	36) SIGRTMIN+2	37) SIGRTMIN+3
38) SIGRTMIN+4	39) SIGRTMIN+5	40) SIGRTMIN+6	41) SIGRTMIN+7	42) SIGRTMIN+8
43) SIGRTMIN+9	44) SIGRTMIN+10	45) SIGRTMIN+11	46) SIGRTMIN+12	47) SIGRTMIN+13
48) SIGRTMIN+14	49) SIGRTMIN+15	50) SIGRTMAX-14	51) SIGRTMAX-13	52) SIGRTMAX-12
53) SIGRTMAX-11	54) SIGRTMAX-10	55) SIGRTMAX-9	56) SIGRTMAX-8	57) SIGRTMAX-7
58) SIGRTMAX-6	59) SIGRTMAX-5	60) SIGRTMAX-4	61) SIGRTMAX-3	62) SIGRTMAX-2
63) SIGRTMAX-1	64) SIGRTMAX

student@linux-opstation-grkv:~$ kill -19 <PID of Process>               

student@linux-opstation-grkv:~$ kill -18 <PID of Process>               

student@linux-opstation-grkv:~$ kill -9 <PID of Process>                
```
-	The kill command is used to send a signal to a process. kill -l will list signals supported by your system
-	supported signals are displayed in output
-	`kill -19 <PID of process>` command will send the pause signal to a process
-	`kill -18 <PID of process>` command will send un-pause/continue executing signal to a process
-	`kill -9 <PID of process>` is used in the most extreme cases to abruptly terminate a process

## Demonstration - Process Enumeration
	Add the following scripts to your box for demonstrations, located at: https://git.cybbh.space/os/public-old/tree/master/modules/operating-systems/linux/scripts/6_LinuxProcesses

**Steps to follow when running scripts**

 - create a file for **Each** script with the following command `nano <name>.sh`
 - copy and paste the contents of the script, close and save
 - run the script with the following command: `source <name>.sh`

**using `less` with the `ps -elf` command to page through the long output**
```
student@linux-opstation-grkv:~$ ps -elf | less 
F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY          TIME CMD
4 S root         1     0  0  80   0 - 40015 -      Feb25 ?        00:00:08 /sbin/init        
1 S root         2     0  0  80   0 -     0 -      Feb25 ?        00:00:00 [kthreadd]
1 I root         4     2  0  60 -20 -     0 -      Feb25 ?        00:00:00 [kworker/0:0H]

--Truncated
```
-	shows the command prior to execution
-	shows the output one page view at a time. Can exit out of it by hitting the q key on your keyboard

**display top five lines of the process table**
```
student@linux-opstation-grkv:~$ ps -elf | head -n5   
F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY          TIME CMD
4 S root         1     0  0  80   0 - 56461 ep_pol 18:23 ?        00:00:07 /sbin/init splash     
1 S root         2     0  0  80   0 -     0 kthrea 18:23 ?        00:00:00 [kthreadd]
1 I root         3     2  0  60 -20 -     0 rescue 18:23 ?        00:00:00 [rcu_gp]
1 I root         4     2  0  60 -20 -     0 rescue 18:23 ?        00:00:00 [rcu_par_gp]
```
-	head command will display the top ten listings. When used with -n# will display the number of required listings
-	note the top two PID’s and PPID’s

**Show only kthreadd processes**
```
student@linux-opstation-grkv:~$ ps --ppid 2 -lf | head              
F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY          TIME CMD
1 I root         3     2  0  60 -20 -     0 rescue 18:23 ?        00:00:00 [rcu_gp]         
1 I root         4     2  0  60 -20 -     0 rescue 18:23 ?        00:00:00 [rcu_par_gp]
1 I root         6     2  0  60 -20 -     0 worker 18:23 ?        00:00:00 [kworker/0:0H]
1 I root         8     2  0  60 -20 -     0 rescue 18:23 ?        00:00:00 [mm_percpu_wq]
1 S root         9     2  0  80   0 -     0 smpboo 18:23 ?        00:00:00 [ksoftirqd/0]

--Truncated
```
- `--ppid #` will show only the parent process with the stated id
-	note that `[kthreaded]` processes have a `PPID` of `2` and with enclosed with brackets `[]`

**Show all processes except kthreadd processes**
```
student@linux-opstation-grkv:~$ ps --ppid 2 -Nlf | head                 
F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY          TIME CMD          
4 S root         1     0  0  80   0 - 56461 ep_pol 18:23 ?        00:00:07 /sbin/init splash
1 S root         2     0  0  80   0 -     0 kthrea 18:23 ?        00:00:00 [kthreadd]
4 S root       310     1  0  79  -1 - 25836 ep_pol 18:23 ?        00:00:00 /lib/systemd/systemd-journald
4 S root       336     1  0  80   0 -  8503 ep_pol 18:23 ?        00:00:00 /lib/systemd/systemd-udevd
4 S systemd+   576     1  0  80   0 - 17750 ep_pol 18:23 ?        00:00:00 /lib/systemd/systemd-resolved
4 S systemd+   578     1  0  80   0 - 36527 ep_pol 18:23 ?        00:00:00 /lib/systemd/systemd-timesyncd

--Truncated
```
-	-N is used in connection with --ppid to negate the required ppid
-	output will not contain ppid of 2 i.e {kthreaded] processes

**display process output in Ascii art process tree**
```
student@linux-opstation-grkv:~$ ps -elf --forest | tail             
0 S student   3185  3178  0  80   0 - 219853 poll_s Feb25 tty2    00:00:00  \_ /usr/lib/evolution/evolution-addressbook-factory-subprocess --factory all --bus-name org.gnome.evolution.dataserver.Subprocess.Backend.AddressBookx3178x2 --own-path /org/gnome/evolution/dataserver/Subprocess/Backend/AddressBook/3178/2
0 S student   3243     1  0  80   0 - 175142 poll_s Feb25 tty2    00:00:00 /usr/lib/gnome-terminal/gnome-terminal-server                                                   
0 S student   3251  3243  0  80   0 -  5774 wait   Feb25 pts/2    00:00:00  \_ bash
4 S root      3310  3251  0  80   0 - 15870 -      Feb25 pts/2    00:00:00      \_ su root
4 S root      3311  3310  0  80   0 -  5510 -      Feb25 pts/2    00:00:00          \_ bash
0 S student   4357     1  0  80   0 -  1159 wait   Feb25 tty2     00:00:00 /bin/sh -c /usr/lib/ubuntu-release-upgrader/check-new-release-gtk
0 S student   4358  4357  0  80   0 - 127623 poll_s Feb25 tty2    00:00:00  \_ /usr/bin/python3 /usr/lib/ubuntu-release-upgrader/check-new-release-gtk

--Truncated
```
-	`--forest` will display the output in Ascii tree format. `Tail` command will output the last ten lines
-	output shows a diagrammatic view of the process table

**Key Points**

   - Shows some simple commands and switch options to view Linux processes

   - `ps -elf` Displays processes

       - `-e` Displays every process on the system

       - `-l` Lists processes in a long format

       - `-f` Does a full-format listing

    - `ps --ppid 2 -lf` Displays only `kthreadd` processes (so, only kernel-space processes)

       - Processes spawned from `kthreadd` will always have a **PPID of 2**

   - `ps --ppid 2 -Nlf` Displays anything except kthreadd processes (so, only user-space processes)

       - `-N` **Negates** the selection

   - `ps -elf --forest` Displays processes in an ASCII tree

       - `--forest` ASCII art process tree

**Operational Value**

    Excellent command for process enumeration.

# Foreground and Background Processes

Processes that require a user to start them or to interact with them are called foreground processes.

Processes that are run independently of a user are referred to as background processes.

Programs and commands run as foreground processes by default.

## Orphan Processes

An orphan process is a running process whose parent process has finished or terminated and is adopted by `sbin/init` and will have a PPID of 1.

  - Key Points

       - `disown -a && exit` Close a shell/terminal and force all children to be adopted

### Demonstration - Orphan

Copy code below and paste into any editor of choice. Give a name to the script. In this instance the script will be called `orphan.sh`, make file an executable and run twice in succession.

**Code for orphan demonstration**
```
#!/bin/bash

#Print PID of current shell
echo $$

#Pause  for  NUMBER seconds
sleep 5 &

#List process table and output PID associated with "sleep"
ps -elf | grep -v  grep | grep sleep
```
`#!/bin/bash` on the first line, meaning that the script should always be run with bash

**Simple demonstration to show how orphans are created**
```
student@linux-opstation-grkv:~$ chmod +x orphan.sh          

student@linux-opstation-grkv:~$ ./orphan.sh                 
13409                                                       
0 S student  13410 13409  0  80   0 -  1983 hrtime 23:16 pts/1    00:00:00 sleep 5      

student@linux-opstation-grkv:~$ ./orphan.sh             
13415                                                               
0 S student  13410     1  0  80   0 -  1983 hrtime 23:16 pts/1    00:00:00 sleep 5      
0 S student  13416 13415  0  80   0 -  1983 hrtime 23:16 pts/1    00:00:00 sleep 5
```
-	make `orphan.sh` an executable
-	first run of `orphan.sh`
-	`13409` is the PID of the shell containing the executable
-	PID `13410` is the PID of the sub process created when the file was executed. Its parent PID is `13409`
-	second run of `orphan.sh`
-	new PID of shell containing the code is now `13415`
-	running the code a second time terminates the original process with PID `13409` containing the code. Sub process with PID of `13410` will now become an orphan and will be reclaimed by /sbin/init. Its PPID will now be 1

### Resources

   - [Orphan Exploit Exercise](https://www.voidsecurity.in/2012/09/blog-post.html)

   - [More about Orphan Processes](https://www.geeksforgeeks.org/zombie-and-orphan-processes-in-c/)

## Zombie (Defunct) Processes

A zombie process (or defunct process) is a process that has completed execution but hasn’t been reaped by its parent process. As result it holds a process entry in the form of a PID in the process table. Zombies cannot be killed as they are already dead and do not use resources. However, they do take up PIDs in the process table which is a finite resource. Zombie entries can be removed from the process table by killing its parent process.

### Demonstration - zombies

Copy code below and paste into any editor of choice. Give a name to the script. In this instance the script will be called `zombie.sh`, make file an executable and run once

**Code for zombie demonstration**
```
#!/bin/bash

#Print PID of current shell
echo $$

#Pause  for  NUMBER seconds
sleep 2 &

#Pause signal
kill -19 $(echo $$)
```
`#!/bin/bash` on the first line, meaning that the script should always be run with bash

**Simple demonstration to show how zombies are created**
```
student@linux-opstation-grkv:~$ chmod +x zombie.sh          

student@linux-opstation-grkv:~$ ps -elf | grep -v grep | grep sleep     

student@linux-opstation-grkv:~$ ./zombie.sh         
13981                                   

[1]+  Stopped                 ./zombie.sh

student@linux-opstation-grkv:~$ ps -elf| grep -v grep | grep sleep          
0 Z student  13982 13981  0  80   0 -     0 -      00:17 pts/1    00:00:00 [sleep] <defunct>        

student@linux-opstation-grkv:~$ kill -18 13981                  
[1]+  Done                    ./zombie.sh

student@linux-opstation-grkv:~$ ps -elf| grep -v grep | grep sleep          
```
-	make `zombie.sh` an executable
-	List continents of process table and confirm that there is no zombie on process list
-	execute file `zombie.sh`
-	PID `13981` is the PID of the shell containing the executable
-	After two seconds list contents of the process table containing `sleep` in the command section
-	After the sleep command completes, the process associated with the executable will not be around to reap its return code as it was paused due to the `kill -19` command in the code. The process associated with sleep, with PID of 13982 will now become a zombie as its parent with PID 13981 is paused. Note the z and `<defunct>` in the process list
-	`kill -18` will send the continue\restart signal to PID 13981 which will clear the zombie entry from the process list
	this command will return no output as the zombie entry has been cleared from the process list

### Resources

   - [Example - ZombieLoad Attack](https://zombieloadattack.com/)

   - [Zombie Security Risks](https://www.fugue.co/blog/zombie-cloud-infrastructure-is-a-major-security-risk)

## Daemons

A daemon process is an intentionally orphaned process in order to have a background process.

**Key Points**

   - What is a daemon and how are they created?

       - Program that runs as a background process (Ex. syslogd, sshd, cron)

       - All daemons are Orphans, but all orphans are not Daemons

       - A daemons purpose is to manage/monitor a service: {status, start, restart}

       - `man cron` - to see an example of a daemon that starts during the boot process

**Operational Value**

   - Persistence - Daemons are services that should run for duration of system operation, since init is parent, would require shutdown for parent to die.

   - Malicious processes are sometimes orphaned and named to make it look like a daemon process `ps --ppid 1 -lf`

### Interacting With Linux Services

A service is a program that runs in the background outside the interactive control of system users as they lack an interface. This in order to provide even more security, because some of these services are crucial for the operation of the operating system.

On the other hand, in systems like Unix or Linux, the services are also known as daemons. Sometimes the name of these services or daemons ends with the letter d. For example, sshd is the name of the service that handles SSH.

The commands used to interact with services on a Unix/Linux system differs based on distribution [sysV or systemD]

#### Interacting With Services on a SYSV System

A system that uses the SysV scheme usually comes with the service program used to manage the services while the system is running. You can check on the status of a service, or all services, and start or stop a service, respectively, using the service utility:

**Check status/start/stop/restart a service on sysV**
```
student@linux-opstation-grkv:~$ service <servicename> status/start/stop/restart
```

#### Interacting With Services on a SYSTEMD System

In recent years, Linux distributions have increasingly transitioned from other init systems to systemd. The systemd suite of tools provides a fast and flexible init model for managing an entire machine from boot onwards

The basic object that systemd manages and acts upon is a `“unit”`. Units can be of many types, but the most common type is a `“service”` (indicated by a unit file ending in `.service`). To manage services on a systemd enabled server, our main tool is the `systemctl` command.

**List all unit files that systemd has listed as active**
```
student@linux-opstation-grkv:~$ systemctl list-units
UNIT                                                                                LOAD   ACTIVE SUB       DESCRIPTION
proc-sys-fs-binfmt_misc.automount                                                   loaded active waiting   Arbitrary Executable File Formats F
sys-devices-pci0000:00-0000:00:01.1-ata1-host0-target0:0:0-0:0:0:0-block-sr0.device loaded active plugged   QEMU_DVD-ROM config-2
sys-devices-pci0000:00-0000:00:03.0-virtio1-net-ens3.device                         loaded active plugged   Virtio network device

--Truncated
```

**List all units that systemd has loaded or attempted to load into memory, including those that are not currently active, add the --all switch:**
```
student@linux-opstation-grkv:~$ systemctl list-units --all
  UNIT                                                                                LOAD      ACTIVE   SUB       DESCRIPTION
  proc-sys-fs-binfmt_misc.automount                                                   loaded    active   waiting   Arbitrary Executable File Fo
  dev-cdrom.device                                                                    loaded    active   plugged   QEMU_DVD-ROM config-2
  dev-disk-by\x2did-ata\x2dQEMU_DVD\x2dROM_QM00001.device                             loaded    active   plugged   QEMU_DVD-ROM config-2

--Truncated
```

**Check status of a service**
```
student@linux-opstation-grkv:~$ systemctl status <servicename.service>

student@linux-opstation-grkv:~$ systemctl status <PID of service>
```

**Start/stop/restart a service**
```
student@linux-opstation-grkv:~$ systemctl start/stop/restart <servicename.service>
```

## Job Control

Job control is the ability to stop/suspend the execution of processes (command) and continue/resume their execution as per your requirements.

The jobs command displays the status of jobs started in the current terminal window. Jobs are numbered starting from 1 for each session. The job ID numbers are used by some programs instead of PIDs (for example, by fg and bg commands).

### Demonstration - Job Control

**Jobs**
```
student@linux-opstation-grkv:~$ ping 8.8.8.8 &          
[1] 14130                   
student@linux-opstation-grkv:~$ PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=112 time=8.51 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=112 time=8.40 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=112 time=8.31 ms
fg                              
ping 8.8.8.8
64 bytes from 8.8.8.8: icmp_seq=4 ttl=112 time=8.72 ms
^Z                              
[1]+  Stopped                 ping 8.8.8.8

student@linux-opstation-grkv:~$ jobs            
[1]+  Stopped                 ping 8.8.8.8      

student@linux-opstation-grkv:~$ kill -9 %1      

[1]+  Stopped                 ping 8.8.8.8
```
-   the command is executed as a background process indicated by & at the end
-	value in `[]` denotes job id and `14130` denotes PID
-	`fg` command is entered on the keyboard to bring job to the foreground
-	`ctrl+z` is used to stop the job
-	`jobs` command will list all jobs and their status
-	list that `job id 1` is stopped
-	`job id 1` is abruptly terminated with the `kill -9` command. Use the % when terminating jobs by their respective ids

the bg command can be use to background a job and ctrl+c command can be use to kill an active process

## Cron Jobs

The Unix cron service runs programs repeatedly on a fixed schedule. Most experienced administrators consider cron to be vital to the system because it can perform automatic system maintenance.

The cron daemon checks the directories `/var/spool/cron`, `/etc/cron.d` and the file `/etc/crontab`, once a minute and executes any commands specified that match the time.

   - Two types of cron jobs

       - System cron jobs

           - run as root and rigidly scheduled

           - perform system-wide maintenance tasks (Cleaning out /tmp or rotating logs)

           - controlled by `/etc/crontab`

       - User cron jobs

           - Use 'crontab’ command to create user cron jobs

           - stored in `/var/spool/cron/crontabs/`

One can run any program with cron at whatever time they want the job to execute. The program running through cron is called a `cron job`.

On Unix-like systems, the `crontab` command opens the cron table for editing. The cron table is the list of tasks scheduled to run at regular time intervals on the system.

**Syntax**

   - `crontab -u [user] file` This command will load the crontab data from the specified file

   - `crontab -l -u [user]` This command will display/list user’s crontab contents

   - `crontab -r -u [user]` This Command will remove user’s crontab contents

   - `crontab -e -u [user]` This command will edit user’s crontab contents

Crontab jobs will run with the permissions of the owner of the crontab file

**Contents placement of the crontab file**
```
  ┌───────────── minute (0 - 59)
  │ ┌───────────── hour (0 - 23)
  │ │ ┌───────────── day of the month (1 - 31)
  │ │ │ ┌───────────── month (1 - 12)
  │ │ │ │ ┌───────────── day of the week (0 - 6) (Sunday to Saturday;
  │ │ │ │ │                           7 is also Sunday on some systems)
  │ │ │ │ │
  │ │ │ │ │
  * * * * * <Time/Day to execute    "Command to Execute"

(Mnemonic: Minnie Has Daily Money Worries)
* The syntax of each line expects a cron expression made of five fields, followed
by a shell command to execute.
```

**Cron Examples**
```
* Run backup everyday at 0412
** `12 4 * * *`    /usr/bin/backup

* Send a message to all logged in users, 0000 hours on 1 Jan
** `0 0 1 1 *`     wall "Happy New Year"

Other advanced usage....

* Send a message at minute 15 of each hour to logged in users on Sunday
** `15 * * * 0`    wall "Shouldn't you be in church?"

* Run backup on Wed, and Sat at 0515
** `15 5 * * 3,6`   /usr/bin/backup

* Save open tcp port listing hourly from 9PM to 5AM every day
** `0 0-5,21-23 * * *`    echo $(ss -nltp) >> /home/andy.dwyer/tcplist.context
```

### Resources

   - [Cron Schedule Expression Editor](https://crontab.guru/)

# Processes and Proc Dir

   - The `/proc/` directory — also called the proc file system — contains a hierarchy of special files which represent the current state of the kernel, allowing applications and users to peer into the kernel’s view of the system.

   - Every process accesses files in order to complete its work. These processes keep track of open files using File Descriptors.

## File Descriptors

   - In Unix and Unix-like computer operating systems, a file descriptor ("FD" or less frequently known as "fildes") is a unique identifier (aka handle) for a file or other input/output resource, such as a pipe or network socket.

   - When you open a file, the operating system creates an entry to represent that file and store the information about that opened file.

       - So if there are 100 files opened in your OS then there will be 100 entries in the OS (somewhere in kernel).

       - These entries are represented by integers like `(…​100, 101, 102…​.)`.

           - This entry number is the file descriptor. So it is just an integer number that uniquely represents an opened file in the operating system. If your process opens 10 files then your Process table will have 10 entries for file descriptors.

### Viewing File Descriptors

   - View File Descriptors using the LSOF command.

   - List all open files being used by every process.

       - `sudo lsof | tail -30`
```
--- Trimmed ---
                <2>                         <1>                                                    
COMMAND     PID   TID             USER   FD      TYPE             DEVICE SIZE/OFF       NODE NAME
gdbus     18768 18772          student   12u     unix 0x0000000000000000      0t0    2409093 type=STREAM
gdbus     18768 18772          student   14r      REG              252,1  1327119      18343 /var/lib/dpkg/status (deleted)
gdbus     18768 18772          student   15r      CHR                1,9      0t0         11 /dev/urandom
gdbus     18768 18772          student   16r      CHR                1,8      0t0         10 /dev/random
--- Trimmed ---
```
-	File Descriptors and their permissions
-	PID and PPID
-	Open file being accessed

   - List all open files for a specific process.

       - `sudo lsof -c sshd`
```
sshd    14139 student    2u   CHR                1,3      0t0       6 /dev/null
sshd    14139 student    3u  IPv4            2761262      0t0     TCP linux-opstation-mikh:ssh->192.168.249.87:43044 (ESTABLISHED)
sshd    14139 student    4u  unix 0xffff917eb0205000      0t0 2761302 type=DGRAM
sshd    14139 student    5u  unix 0xffff917ec7a51000      0t0 2761519 type=STREAM
sshd    14139 student    6r  FIFO               0,12      0t0 2761523 pipe
sshd    14139 student    7w  FIFO               0,24      0t0     289 /run/systemd/sessions/6101.ref
sshd    14139 student    8w  FIFO               0,12      0t0 2761523 pipe
sshd    14139 student    9u   CHR                5,2      0t0      87 /dev/ptmx
sshd    14139 student   11u   CHR                5,2      0t0      87 /dev/ptmx
sshd    14139 student   12u   CHR                5,2      0t0      87 /dev/ptmx
```
### Interpreting File Descriptors
```
This information and more available in the lsof man page.

# - The number in front of flag(s) is the file descriptor number used by the process associated with the file
u - File open with Read and Write permission
r - File open with Read permission
w - File open with Write permission
W - File open with Write permission and with Write Lock on entire file
mem - Memory mapped file, usually for share library
```

## - Navigating Proc Directory

   - List all the proc directories.

       - `ls -l /proc/`
```
dr-xr-xr-x  9 root             root                           0 Feb  9  2021 1
dr-xr-xr-x  9 root             root                           0 Feb  9  2021 10
dr-xr-xr-x  9 root             root                           0 Feb  9  2021 100
dr-xr-xr-x  9 root             root                           0 Feb  9  2021 1018
dr-xr-xr-x  9 xrdp             xrdp                           0 Feb  9  2021 1081
dr-xr-xr-x  9 root             root                           0 Feb  9  2021 1085
dr-xr-xr-x  9 root             root                           0 Feb  9  2021 11
dr-xr-xr-x  9 root             root                           0 Feb  9  2021 1104
```
   - Grab the PID of a process.

       - `ps -elf | grep sshd`
```
4 S root      1107     1  0  80   0 - 18077 -      Feb09 ?        00:00:00 /usr/sbin/sshd -D
4 S root     14035  1107  0  80   0 - 26424 -      14:21 ?        00:00:00 sshd: student [priv]
5 S student  14139 14035  0  80   0 - 27031 -      14:22 ?        00:00:00 sshd: student@pts/0
```
   - List contents for that PID directory.

       - `sudo ls -l /proc/14139`
```
total 0
dr-xr-xr-x 2 student student 0 Aug 27 17:14 attr
-rw-r--r-- 1 root    root    0 Aug 27 17:14 autogroup
-r-------- 1 root    root    0 Aug 27 17:14 auxv
-r--r--r-- 1 root    root    0 Aug 27 17:14 cgroup
--w------- 1 root    root    0 Aug 27 17:14 clear_refs
-r--r--r-- 1 root    root    0 Aug 27 17:12 cmdline
-rw-r--r-- 1 root    root    0 Aug 27 17:14 comm
-rw-r--r-- 1 root    root    0 Aug 27 17:14 coredump_filter
-r--r--r-- 1 root    root    0 Aug 27 17:14 cpuset
lrwxrwxrwx 1 root    root    0 Aug 27 14:22 cwd -> /
-r-------- 1 root    root    0 Aug 27 17:14 environ
lrwxrwxrwx 1 root    root    0 Aug 27 14:22 exe -> /usr/sbin/sshd    
```
-	The exe link to actual binary file being executed.

## Resources

   - [lsof examples](https://www.tecmint.com/10-lsof-command-examples-in-linux/)

   - [cheat.sh/lsof](https://cheat.sh/lsof)

   - [View FD without LSOF](https://unix.stackexchange.com/questions/66235/how-to-display-open-file-descriptors-but-not-using-lsof-command)

   - [About Proc Directories](https://www.thegeekstuff.com/2010/11/linux-proc-file-system/)

   - [About File Descriptors](https://www.sciencedirect.com/topics/computer-science/file-descriptor)