#############################

# Find all files in a given directory that have alternate data streams
Get-ChildItem -Force -Recurse | Get-Item -Stream * | Where-Object {$_.Stream -notlike "*DATA*"}

Get-Content C:\Users\CTF\Documents\nothing_here -Stream hidden

#############################

# Fortune cookies have been left around the system so that you won't find the hidden password

# In C:\Users\CTF:

Get-ChildItem -force -recurse -file | Select-String -Pattern "cookie"

# Documents\fortune cookie.txt:1:only listen to the Fortune Cookie, and disregard all other fortune telling units



#############################

# There are plenty of phish in the C:\Users\CTF, but sometimes they're hidden in plain site

Get-ChildItem -path C:\Users\CTF\Documents -recurse -force
Get-Content -path .\www\200

#############################



#############################