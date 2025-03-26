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

# Find all members of a given ggroup
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
ls -ld /media/Bibliotheca

# found group name

getent group mephiston

######################

/media/Bibliotheca/Bibliotheca_tribus/Codex_Imperium

/media/Bibliotheca/Bibliotheca_unus/Codex_Astartes

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



######################



######################



######################



######################



######################



######################