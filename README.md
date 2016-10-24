# sdb-explorer

## Overview
sdb-explorer is a tool that provides the ability to read and write Microsoft Fix-It In-memory patches, also known as SDB files.  

## Windows 10 Support
Note the version of apphelp.dll in Windows 10 does not include the function SeiApplyPatch.  This was the function responsible for patching a and flushing the instruction cache.  It appears that Microsoft has removed support for this undocumented feature.

For more information see:

https://www.blackhat.com/asia-14/archives.html#Erickson

http://www.youtube.com/watch?v=Gx6OgCxPBIQ

Please see my slides from Codeblue 2014: http://sdb.io/erickson-codeblue.pdf
