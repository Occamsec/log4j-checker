# CVE-2021-44228 - Log4Shell checker 0.2
# Released by OccamSec on 2021.12.13
#
# Finds every .jar file within the filesystem and compares
# each one against known log4j 2.0-2.14.1 sha256 hashes
#
# Hash files available from
# https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes
# 
# This script is meant to be readable and understandable,
# not clever, or elegant
#

Param ($hashfile, $path)
If ($hashfile -eq $null) {
	$hashfile = Read-Host -Prompt "Please enter the path to the hash file"
}
If ($path -eq $null) {
	$path = Read-Host -Prompt "Please enter the path to scan for vulnerable files"
}
If (($hashfile -eq $null) -or ($path -eq $null)) {
	Write-Host "No hashfile or path specified."
} Else {
	# Start a log to save output
	# Start-Transcript -Path "log4shell_hash_check.txt" -Append

	# Let the user know what we're doing
	Write-Host "Checking $($path) for vulnerable jar files based on hashes in $($hashfile)"

	# Create new output files
	New-Item -Name jarfiles.txt -ItemType "file" -Force | Out-Null
	New-Item -Name matchinglog4j.txt -ItemType "file" -Force | Out-Null

	# Find all *.jar files in the specified path
	foreach ($file in Get-ChildItem -Path $path -Filter *.jar -Recurse) {
		# Log the new jar file
		Add-Content -Path jarfiles.txt -Value $file.FullName

		# Get the hash for the file
		$hash = Get-FileHash $file.FullName

		# Search the hash listing to see if we have a match
		If (Select-String -Pattern $hash.Hash -Path $hashfile -Quiet) {

			# Output the hash and the full path for the file
			Write-Host "  >>> MATCH:  $($hash.Hash)  $($hash.Path)"
			Add-Content -Path matchinglog4j.txt -Value "$($hash.Hash)  $($hash.Path)"

		}
	}
	Write-Host "Done"

	# Close the log
	# Stop-Transcript
}
