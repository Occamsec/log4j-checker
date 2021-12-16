# CVE-2021-44228 - Log4Shell JndiLookup finder 0.1
# Released by OccamSec on 2021.12.16
#
# Finds every .jar file within the filesystem, extracts
# information from the ones containing JndiLookup.class
# and calculates a SHA-256 hash for reference.
#
# This script is meant to be readable and understandable,
# not clever, or elegant.
#

Param ($path)

#Add-Type -AssemblyName "System.IO.Compression.ZipFile"
[Reflection.Assembly]::LoadWithPartialName( "System.IO.Compression.FileSystem" ) | Out-Null

If ($path -eq $null) {
	$path = Read-Host -Prompt "Please enter the path to scan for .jar files"
}
If ($path -eq $null) {
	Write-Host "No path specified."
} Else {
	# Start a log to save output
	# Start-Transcript -Path "log4shell_jndilookup.txt" -Append

	# Let the user know what we're doing
	Write-Host "Checking $($path) for jar files"

	# Create new output files
	New-Item -Name jarfiles.txt -ItemType "file" -Force | Out-Null
	New-Item -Name jndilookup_jarfiles.txt -ItemType "file" -Force | Out-Null

	# Find all *.jar files in the specified path
	foreach ($file in Get-ChildItem -Path $path -Filter *.jar -Recurse) {
		# Log the new jar file
		Add-Content -Path jarfiles.txt -Value $file.FullName

		# Get the contents of the file
		$jar = [IO.Compression.ZipFile]::OpenRead($file.FullName)
		$jdniclass = $jar.Entries | Where-Object { $_.FullName -match '.*jndilookup.class$' }
		if ($jdniclass -ne $null) {		
			# Found matching jndi class
			Write-Host "-------------------------------------------`n>>> JndiLookup.class found in: $($file.FullName)"
			Add-Content -Path jndilookup_jarfiles.txt -Value "-------------------------------------------`n>>> JndiLookup.class found in: $($file.FullName)`n"

			# Extract the manifest file to pipe
			$manifest = $jar.Entries | Where-Object { $_.FullName -eq "META-INF/MANIFEST.MF" }
			$stream = $manifest.Open()
			$reader = New-Object IO.StreamReader($stream)
			$data = $reader.ReadToEnd()
		
			# Print Jar info
			Write-Host "PACKAGE INFORMATION:"
			Add-Content -Path jndilookup_jarfiles.txt -Value "PACKAGE INFORMATION:"
			$data | Select-String -Pattern '(?mi)^.*(bundle-symbolicname:|implementation-vendor-id:|specification-title:|bundle-Name:|implementation-title:|automatic-module-name:|implementation-url).*$' -AllMatches |
				ForEach-Object { $_.Matches } | Sort-Object -Property Value | ForEach-Object {
					Write-Host $_.Value
					Add-Content -Path jndilookup_jarfiles.txt -Value $_.Value.Trim()
				}

			# Print version information
			Write-Host "`nVERSION INFORMATION:"
			Add-Content -Path jndilookup_jarfiles.txt -Value "`nVERSION INFORMATION:"
			$data | Select-String -Pattern '(?mi)^.*(log4jreleaseversion:|implementation-version:|bundle-version:|specification-version:).*$' -AllMatches |
				ForEach-Object { $_.Matches } | Sort-Object -Property Value | ForEach-Object {
					Write-Host $_.Value
					Add-Content -Path jndilookup_jarfiles.txt -Value $_.Value.Trim()
				}
		
			# Calculate and print SHA-256 hash
            $hash = Get-FileHash $file.FullName
            Write-Host "`nSHA-256 HASH:`n $($hash.Hash)  $($hash.Path)"
            Add-Content -Path jndilookup_jarfiles.txt -Value "`nSHA-256 HASH:`n$($hash.Hash)  $($hash.Path)"
		}
	}
	Write-Host "`nList of .jar files found under $($path) (if any) saved as ./jarfiles.txt`nDetails about .jar files containing JndiLookup.class (if any) saved as ./jndilookup_jarfiles.txt"

	# Close the log
	# Stop-Transcript
}
