#############################

# Find all files in a given directory that have alternate data streams
Get-ChildItem -Force -Recurse | Get-Item -Stream * | Where-Object {$_.Stream -notlike "*DATA*"}

Get-Content C:\Users\CTF\Documents\nothing_here -Stream hidden

#############################

# Fortune cookies have been left around the system so that you won't find the hidden password

# In C:\Users\CTF:

Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue | Select-String -Pattern "fortune cookie" -ErrorAction SilentlyContinue

# Documents\fortune cookie.txt:1:only listen to the Fortune Cookie, and disregard all other fortune telling units

# Found C:\Windows\PLA\not_anihc\The Fortune Cookie

Get-Item -Stream * 'C:\Windows\PLA\not_anihc\The Fortune Cookie'

# Found an additional stream called "none"

Get-Content 'C:\Windows\PLA\not_anihc\The Fortune Cookie' -Stream none

#############################

# There are plenty of phish in the C:\Users\CTF, but sometimes they're hidden in plain site

Get-ChildItem -path C:\Users\CTF\Documents -Recurse -Force
Get-Content -path .\www\200

#############################



#############################