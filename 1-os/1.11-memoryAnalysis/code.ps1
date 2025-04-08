# What Volatility plugin will dump a process to an executable file sample?
# procdump

# What Volatility plugin will extract command history by scanning for _COMMAND_HISTORY?
# cmdscan

# What Volatility plugin will show driver objects?
# driverscan

# What plugin do you run to find which memory profile to use with a memory image?
# imageinfo

# What switch/argument will list all plugins for Volatility?
# --help

# In terms of Volatile Data, what locations are the MOST volatile?
# registers,cache
# reference: https://datatracker.ietf.org/doc/html/rfc3227#section-2.1

# What is the 12th plugin listed in the Volatility help menu?
# cd C:\Users\andy.dwyer\Desktop\Memory_Analysis
.\volatility_2.6_win64_standalone.exe --help
# cmdscan

# What profile do you use in conjunction with this memory image?
# Use the following file (memory image) to answer the rest of the Memory Analysis challenges.
# 0zapftis.vmem
.\volatility_2.6_win64_standalone.exe -f .\0zapftis.vmem imageinfo
# WinXPSP2x86

# What command did the attacker type to check the status of the malware?
.\volatility_2.6_win64_standalone.exe -f .\0zapftis.vmem cmdscan
# sc query malware

# What are the last 7 digits of the memory offset for the driver used by the malware?
.\volatility_2.6_win64_standalone.exe -f .\0zapftis.vmem driverscan
# 1a498b8

# The process running under PID 544 seems malicious. What is the md5hash of the executable?
.\volatility_2.6_win64_standalone.exe -f .\0zapftis.vmem procdump -p 544 -D .
# ./executable.544.exe
Get-FileHash .\executable.544.exe -Algorithm md5hash
# 6cee14703054e226e87a963372f767aa

#What remote IP and port did the system connect to?
# Flag format: ip:port
.\volatility_2.6_win64_standalone.exe -f .\cridex.vmem --profile=WinXPSP2x86 connections
# 41.168.5.140:8080