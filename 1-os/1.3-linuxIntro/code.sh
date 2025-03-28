######################

# Find executable path of cat man page
/usr/share/man/man1/cat.1.gz

######################

# Search man pages for a keyword, using the largest sha hash available, hash "OneWayBestWay" and submit the hash

man -k digest #this reveals the hashing algorithm is sha512sum

echo "OneWayBestWay" | sha512sum -t

######################

# Use file /home/garviel/Encrypted and identify the file type. Once identified, decode it's contents

unzip Encrypted

# This produced two files:
#  cipher, which appeared to be an encrypted file
#  symmetric, which appeared to be a key with the value "AES129Key"

openssl enc -aes128 -d -in cipher -out unciphered.txt -pass file:symmetric

# This gave me a warning, but still generated unciphered.txt

cat unciphered.txt

######################

# Search home directories to find a file with the second-most lines in it. The flag is the number of lines in the file

find /home/ -type f | xargs wc -l | sort -rn

# ...
# 20000 /home/garviel/numbers
# ...

######################

# Find strange comment in users list
cat /etc/passwd

# ...
# garviel:x:1001:1001:Traitor:/home/garviel:/bin/bash
# ...

######################

# Find all members of a given group
getent group lodge

######################

# Find the user with a unique shell
grep -v "/bin/bash$" /etc/passwd | awk -F: '{print $1, $7}'

# nobody  /bin/sh

######################

# Find a directory named Bibliotheca
find / -type d -name "Bibliotheca" 2>/dev/null

######################

# Identify the number of users with valid login shells, who can list the contents of the Bibliotheca directory.

getent passwd | grep -F -f <(grep -E '^/' /etc/shells) | cut -d: -f1 | wc -l

######################

/media/Bibliotheca/Bibliotheca_tribus/Codex_Imperium

/media/Bibliotheca/Bibliotheca_unus/Codex_Astartes

######################

# Execute the file owned by the guardsmen group in /media/Bibliotheca, as the owning user. The flag is the code name provided after a successful access attempt.

# find what files are owned in the directory by the guardsmen group
find /media/Bibliotheca/ -group guardsmen
# media/Bibliotheca/Bibliotheca_quattuor/Tactica_Imperium
# /media/Bibliotheca/Bibliotheca_tribus/Codex_Imperium

# find the permissions on those two files
ls -la /media/Bibliotheca/Bibliotheca_quattuor/Tactica_Imperium
# -rwxrwx--- 1 gaunt guardsmen 865 Feb 28  2022 /media/Bibliotheca/Bibliotheca_quattuor/Tactica_Imperium

ls -la /media/Bibliotheca/Bibliotheca_tribus/Codex_Imperium
# -r--rw-r-- 1 mephiston guardsmen 4047 Feb 28  2022 /media/Bibliotheca/Bibliotheca_tribus/Codex_Imperium

# Check sudo rights to see which one of these I can run:
sudo -l
# Matching Defaults entries for garviel on terra:
#     env_reset, mail_badpass,
#     secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

# User garviel may run the following commands on terra:
#     (ALL) NOPASSWD: /bin/cat /etc/shadow
#     (gaunt) NOPASSWD: /media/Bibliotheca/Bibliotheca_quattuor/Tactica_Imperium
#     (ALL) NOPASSWD: /bin/cat, /bin/ls, /usr/bin/find, /bin/systemctl

# So we want to run Tactica_Imperium as sudo, assuming gaunt's persona:
sudo -u gaunt /media/Bibliotheca/Bibliotheca_quattuor/Tactica_Imperium

# Enter_Access_Code
# Only the owner may access this file:
# Speak thy name: gaunt
# Processing...Access Granted
# Codename: GHOSTS

######################

# REGEX on Valid and Invalid IP addresses
grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' numbers | wc -l # invalid

grep -E '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$' file.txt | wc -l # valid

######################

# File: home/garviel/numbers

# Use awk to print lines:

# >= 420 AND <=1337

# The flag is a SHA512 hash of the output.

awk 'NR>=420 && NR<=1337' numbers | sha512sum -

######################

# Find the warp and read its secrets for the flag.

find /media/Bibliotheca/Bibliotheca_duo/ -type f 2>/dev/null

# ...
# /media/Bibliotheca/Bibliotheca_duo/.warp2/.warp5/warp5/.warp3/warp2/.secrets
# ...

cat /media/Bibliotheca/Bibliotheca_duo/.warp2/.warp5/warp5/.warp3/warp2/.secrets

######################



######################



######################



######################



######################



######################