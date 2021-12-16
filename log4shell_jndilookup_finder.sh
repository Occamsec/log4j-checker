#!/bin/bash

# CVE-2021-44228 - Log4Shell JndiLookup finder 0.1
# Released by OccamSec on 2021.12.16
#
# Finds every .jar file within the filesystem, extracts
# relevant information from the ones containing JndiLookup.class
# and calculates a SHA-256 hash for reference.
# 
# This script is meant to be readable and understandable,
# not clever, or elegant.
#

if [[ $# -ne 1 ]]; then
  echo    "Log4Shell JndiLookup finder"
  echo    "----------------------------"
  echo    "This script scans the filesystem for .jar files and extracts relevant"
  echo    "information from .jar files containing the JndiLookup class."
  echo    "NOTE: use 'sudo' if you do not have permissions to access the path you want to scan."
  echo    "Usage: sudo $0 <path>"
  echo    "E.g.: sudo $0 /"
  echo    "      sudo $0 ./"
  echo -e "      sudo $0 /opt/tomcat/"
  exit 2
else

  # Make sure the path to scan exists and is accessible
  if [[ ! -d "${1}" ]]; then
      echo "Cannot find ${1}."
      exit 2
  fi
  
  if [[ ! -r "${1}" ]]; then
      echo "Cannot read ${1}."
      exit 2
  fi

  # Empty output files
  > jarfiles.txt
  > jndilookup_jarfiles.txt

  # Find the jar files and save these to jarfiles.txt
  echo "Please be patient, scanning the file system for .jar files starting at ${1}"
  find "${1}" -name "*.jar" 2>&1 | grep -Eiv "(denied|permitted|no such file|not a directory)" | tee ./jarfiles.txt

  # For each jar file use unzip to list their contents and find the ones containing JndiLookup.class
  IFS=$'\n' # Keep line elements together within the loop by ignoring any separator except '\n'  
  for jarfile in $(cat ./jarfiles.txt); do

    # If the file is readable (we have permission) we process the file
    if [[ ! -r "${jarfile}" ]]; then
        echo -e "Cannot read ${jarfile}."
      else
        # If unzip returns an output we extract the manifest
        if [[ ! -z $(unzip -l "${jarfile}" | grep -i "jndilookup.class") ]]; then
          echo "-------------------------------------------" | tee ./jndilookup_jarfiles.txt
          echo -e ">>> JndiLookup.class found in: ${jarfile}\n" | tee -a ./jndilookup_jarfiles.txt
                    
          # Extract the manifest file to pipe
          MANIFEST=$(unzip -q -p ${jarfile} "META-INF/MANIFEST.MF")

          # Print Jar info
          echo "PACKAGE INFORMATION:" | tee -a ./jndilookup_jarfiles.txt
          echo "${MANIFEST}" | grep -Ei "(bundle-symbolicname:|implementation-vendor-id:|specification-title:|bundle-Name:|implementation-title:|automatic-module-name:|implementation-url)" | sort | tee -a ./jndilookup_jarfiles.txt

          # Print version information
          echo -e "\nVERSION INFORMATION:" | tee -a ./jndilookup_jarfiles.txt
          echo "${MANIFEST}" | grep -Ei "(log4jreleaseversion:|implementation-version:|bundle-version:|specification-version:)" | sort | tee -a ./jndilookup_jarfiles.txt

          # Calculate and print SHA-256 hash
          echo -e "\nSHA-256 HASH:\n $(shasum -a 256 -b "${jarfile}")" | tee -a ./jndilookup_jarfiles.txt
        fi
    fi
  done
  echo -e "\nList of .jar files found under ${1} (if any) saved as ./jarfiles.txt"
  echo "Details about .jar files containing 'JndiLookup.class' (if any) saved as ./jndilookup_jarfiles.txt"

fi
