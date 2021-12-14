#!/bin/bash

# CVE-2021-44228 - Log4Shell checker 0.2
# Released by OccamSec on 2021.12.13
#
# Finds every .jar file within the filesystem and compares
# each one against known log4j 2.0-2.14.1 SHA-256 hashes
#
# Hash files available from
# https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes
# 
# This script is meant to be readable and understandable,
# not clever, or elegant
#

if [[ $# -ne 2 ]]; then
  echo    "Log4shell hash ckecher"
  echo    "----------------------"
  echo    "Scans the filesystem for .jar files and compare them against a list of known SHA-256 hashes."
  echo    "NOTE: use 'sudo' if you do not have permissions to access the path you want to scan."
  echo    "Usage: sudo $0 <path> <sha256file>"
  echo    "E.g.: sudo $0 / sha256sum.txt"
  echo    "      sudo $0 ./ sha256sum.txt"
  echo -e "      sudo $0 /opt/tomcat/ sha256sum.txt\n"
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

  # Make sure the hashfile exists and is accessible
  if [[ ! -f "${2}" ]]; then
      echo "Cannot find ${2}."
      exit 2
  fi
  
  if [[ ! -r "${2}" ]]; then
    echo "Cannot read ${2}."
    exit 2
  fi

  # Empty output files
  > jarfiles.txt
  > matchinglog4j.txt

  # Find the jar files and save these to jarfiles.txt
  echo "Please be patient, scanning the file system for .jar files starting at ${1}"
  find "${1}" -name "*.jar" 2>&1 | grep -Eiv "(denied|permitted|no such file|not a directory)" | tee ./jarfiles.txt

  # For each jar file calculate its SHA-256 hash and compare it against the user-provided SHA-256 hash file
  IFS=$'\n' # Keep line elements together within the loop by ignoring any separator except '\n'  
  for jarfile in $(cat ./jarfiles.txt); do

    # If the file is readable (we have permission) we calculate its SHA-256 hash
    if [[ ! -r "${jarfile}" ]]; then
        echo -en "\033[2K\rCannot read ${jarfile}."
      else
        hash=$(shasum -a 256 -b "${jarfile}" | cut -f 1 -d ' ')        
        echo -en "\033[2K\rChecking hash ${hash}  ${jarfile}"

        # Then we check if the file's hash is present in the user-provided SHA-256 hash file
        match=$(grep ${hash} ${2})
        if [[ ! -z "${match}" ]]; then
          echo -en "\n   >>> MATCH: "
          echo -e "${hash}  ${jarfile}\n" | tee ./matchinglog4j.txt
        fi
    fi
  done
  echo -e "\nJar files found under ${1} (if any) saved as ./jarfiles.txt"
  echo "Matching log4j jars (if any) saved as ./matchinglog4j.txt"

fi
