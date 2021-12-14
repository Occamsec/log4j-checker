# Log4Shell checker

This script scans a local filesystem looking for .jar files which may be vulnerable to CVE-2021-44228 aka Log4Shell.

The script will calculate a SHA-256 hash for each .jar file found - regardless of the filename - and compare this value against known SHA-256 hashes calculated against Log4j releases between 2.0 and 2.14.1 included.

Known hash files are available from https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes

NOTE: if the Log4j .jar file in use within your system has been modified, for instance to introduce customizations, its SHA-256 hash will differ from the corresponding official release and the script will not be able to flag it.

## Usage:

### Bash (run with sudo to avoid permission issues):
```
log4shell_hash_check.sh <path> <sha256file>

E.g.: sudo ./log4shell_hash_check.sh / sha256sum.txt
      sudo ./log4shell_hash_check.sh ./ sha256sum.txt
      sudo ./log4shell_hash_check.sh /opt/tomcat/ sha256sum.txt
```

### PowerShell (run from an administrator shell to avoid permission issues):
```
log4shell_hash_check.ps1 -path <path> -hashfile <sha256file>

E.g.: .\log4shell_hash_check.ps1 -path c:\ -hashfile sha256sum.txt
      .\log4shell_hash_check.ps1 -path .\ -hashfile sha256sum.txt
      .\log4shell_hash_check.ps1 -path c:\opt\tomcat\ -hashfile sha256sum.txt
```

### Sample output:

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
