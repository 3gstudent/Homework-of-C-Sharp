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

---

