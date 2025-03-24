#######################################

# Find Service description:
Get-CimInstance Win32_Service | Select-Object -Property Name,Description | Where-Object -Property Name -eq LegoLand

#######################################

# Count words in a text file:
Get-Content .\words2.txt | Measure-Object -Word

#######################################

# Count files in a directory:
Get-ChildItem | Measure-Object

#######################################

# Find difference between two files:
Compare-Object (Get-Content .\old.txt) (Get-Content .\new.txt)

#######################################

# Alphabetically sort a file by line in descending order, and output the 21st line:

(Get-Content .\file.txt | Sort-Object -Descending)[20]

#######################################

# Count the number of unique lines in a file:
Get-Content .\file.txt | Sort-Object | Get-Unique | Measure-Object -Line

#######################################

# Count number of available methods:
Get-Process | Get-Member | Where-Object -Property MemberType -eq Method | Measure-Object

#######################################

# Get number of folders in a given folder:
Get-ChildItem | Measure-Object

#######################################

# Count the number of times a given string (case-insensitive) is listed in a given file:
Get-Content .\words.txt | Sort-Object | Select-String Pattern "gaab"

#######################################

# Count the number of words, case-insensitive, with either a or z in a word, in the words.txt file

Get-Content .\words.txt | Sort-Object | Select-String -Pattern "a" | Measure-Object | Select-Object -Property Count

Get-Content .\words.txt | Sort-Object | Select-String -Pattern "z" | Measure-Object | Select-Object -Property Count

#######################################

# Count the number of words, case-insensitive, with either a or z in a word, in a given file

(Get-Content .\words.txt | Where-Object {$_ -match "[azAZ]"}) | Measure-Object | Select-Object -ExpandProperty Count

#######################################

# Count the number of lines, case-insensitive, that az appears in a given file

(Get-Content .\words.txt | Where-Object {$_ -match "[aA][zZ]"}) | Measure-Object | Select-Object -ExpandProperty Count

#######################################

# Use a PowerShell loop to unzip the Omega file 1,000 times and read what is inside.

$zipNumber = 1000
$basePath = "C:\Users\student\Documents\Omega1000.zip"
$extractPath = "C:\Users\student\Documents"
$destinationRoot = "C:\Users\student\Documents\dest"

Expand-Archive -Path $basePath - DestinationPath "$extractPath\Omega1000" -Force

$workingDir = "$extractPath\Omega1000"

while ($zipNumber -gt 0){
    $zipNumber--
    $currentZip = "$workingDir\Omega$zipNumber.zip"
    $newFolder = "$destinationRoot\Omega$zipNumber"

    if (Test-Path $currentZip) {
        Expand-Archive -Path $currentZip -DestinationPath $newFolder -Force
        $workingDir = $newFolder

    } else {
        Write-Host "No more zip files found. Looking for flag..."
        break
    }
}

#######################################



#######################################



#######################################



#######################################