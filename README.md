# Log4j-Checker
This repository contains scripts that can help identity .jar files which may be vulnerable to CVE-2021-44228 aka Log4Shell.


## Log4Shell Hash Check
This script will find .jar files within the filesystem starting from a specific path, calculate a SHA-256 hash for each .jar file found - regardless of the filename - and compare this value against a user-provided list of SHA-256 hashes. 

Known hash files calculated against official Log4j releases are available from https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes, which is the source for the hash file included within this repository.

NOTE: if the Log4j .jar file in use within your system has been modified because - for instance - it has been compiled from source, because a vendor applied customizations of any type, or because Log4j classes have been included within a larger .jar file, its SHA-256 hash will differ from the corresponding official Log4j release and the script will not be able to flag it.


### Usage:
#### Bash (run with sudo to avoid permission issues):
```
log4shell_hash_check.sh <path> <sha256file>

E.g.: sudo ./log4shell_hash_check.sh / sha256sum.txt
      sudo ./log4shell_hash_check.sh ./ sha256sum.txt
      sudo ./log4shell_hash_check.sh /opt/tomcat/ sha256sum.txt
```

#### PowerShell (run from an administrator shell to avoid permission issues):
```
log4shell_hash_check.ps1 -path <path> -hashfile <sha256file>

E.g.: .\log4shell_hash_check.ps1 -path c:\ -hashfile sha256sum.txt
      .\log4shell_hash_check.ps1 -path .\ -hashfile sha256sum.txt
      .\log4shell_hash_check.ps1 -path c:\opt\tomcat\ -hashfile sha256sum.txt
```

##### Sample output:
```
OccamSec $ ./log4shell_hash_check.sh ./ log4j_2.x_sha256sum.txt
Please be patient, scanning the file system for .jar files starting at ./
.//apache-log4j-2.13.1-bin/log4j-flume-ng-2.13.1.jar
.//apache-log4j-2.13.1-bin/log4j-core-2.13.1.jar
[CUT]
.//apache-log4j-2.13.1-bin/log4j-mongodb2-2.13.1.jar
.//apache-log4j-2.13.1-bin/log4j-to-slf4j-2.13.1-sources.jar
.//apache-log4j-2.13.1-bin/log4j-to-slf4j-2.13.1-javadoc.jar
.//apache-log4j-2.13.1-bin/log4j-appserver-2.13.1-javadoc.jar
.//apache-log4j-2.13.1-bin/log4j-appserver-2.13.1-sources.jar

Checking hash 6f38a25482d82cd118c4255f25b9d78d96821d22bab498cdce9cda7a563ca992  .//apache-log4j-2.13.1-bin/log4j-core-2.13.1.jar
   >>> MATCH: 6f38a25482d82cd118c4255f25b9d78d96821d22bab498cdce9cda7a563ca992  .//apache-log4j-2.13.1-bin/log4j-core-2.13.1.jar

Checking hash eafab7995f042e0386e08fa5e299d63465b63f1e4e5cb754612c68d52b72516d  .//apache-log4j-2.13.1-bin/log4j-appserver-2.13.1-sources.jar

Jar files found under ./ (if any) saved as ./jarfiles.txt
Matching log4j jars (if any) saved as ./matchinglog4j.txt
```

## Log4Shell JndiLookup Finder
This script will find .jar files within the filesystem starting from a specific path and inspect them to check if they contain the JndiLookup class. Should this be the case, the script will extract information from the .jar file manifest which should help determine if the .jar file contains a Log4j release, and if this is vulnerable. Finally, the script will calculate a SHA-256 hash for completeness.

It is up to the the user to decide if this script is to be used as a companion to the "Log4Shell Hash Check" script or as a standalone tool.

### Usage:
#### Bash (run with sudo to avoid permission issues):
```
log4shell_jndilookup_finder.sh <path>

E.g.: sudo ./log4shell_jndilookup_finder.sh /
      sudo ./log4shell_jndilookup_finder.sh ./
      sudo ./log4shell_jndilookup_finder.sh /opt/tomcat/
```

#### PowerShell (run from an administrator shell to avoid permission issues):
```
log4shell_jndilookup_finder.ps1 -path <path>

E.g.: .\log4shell_jndilookup_finder.ps1 -path c:\
      .\log4shell_jndilookup_finder.ps1 -path .\
      .\log4shell_jndilookup_finder.ps1 -path c:\opt\tomcat\
```

##### Sample output:
```
$ ./log4shell_jndilookup_finder.sh ./
Please be patient, scanning the file system for .jar files starting at ./
.//apache-log4j-2.13.1-bin/log4j-flume-ng-2.13.1.jar
.//apache-log4j-2.13.1-bin/log4j-core-2.13.1.jar
[CUT]
.//apache-log4j-2.13.1-bin/log4j-mongodb2-2.13.1.jar
.//apache-log4j-2.13.1-bin/log4j-to-slf4j-2.13.1-sources.jar
.//apache-log4j-2.13.1-bin/log4j-to-slf4j-2.13.1-javadoc.jar
.//apache-log4j-2.13.1-bin/log4j-appserver-2.13.1-javadoc.jar
.//apache-log4j-2.13.1-bin/log4j-appserver-2.13.1-sources.jar
-------------------------------------------
>>> JndiLookup.class found in: .//apache-log4j-2.13.1-bin/apache-log4j-2.13.1-bin/log4j-core-2.13.1.jar

PACKAGE INFORMATION:
Automatic-Module-Name: org.apache.logging.log4j.core
Bundle-Name: Apache Log4j Core
Bundle-SymbolicName: org.apache.logging.log4j.core
Implementation-Title: Apache Log4j Core
Implementation-URL: https://logging.apache.org/log4j/2.x/log4j-core/
Implementation-Vendor-Id: org.apache.logging.log4j
Specification-Title: Apache Log4j Core

VERSION INFORMATION:
Bundle-Version: 2.13.1
Implementation-Version: 2.13.1
Log4jReleaseVersion: 2.13.1
Specification-Version: 2.13.1

SHA-256 hash:
 6f38a25482d82cd118c4255f25b9d78d96821d22bab498cdce9cda7a563ca992 *.//apache-log4j-2.13.1-bin/apache-log4j-2.13.1-bin/log4j-core-2.13.1.jar

List of .jar files found under ./ (if any) saved as ./jarfiles.txt
Details about .jar files containing 'JndiLookup.class' (if any) saved as ./jndilookup_jarfiles.txt
```
