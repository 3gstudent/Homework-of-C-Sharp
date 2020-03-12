# Homework-of-C-Sharp
C Sharp codes of my blog.

### Shellcode.cs

Use CreateThread to run shellcode.

### ShellcodeBase64.txt

Base64 of the shellcode(msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f csharp)

### ReadShellcode.cs

It will read ShellcodeBase64.txt and launch the shellcode.

### SafetyKatz.cs

Use to run `sekurlsa::logonpasswords` and `sekurlsa::ekeys` on the minidump file of lsass.exe.

All code from https://github.com/GhostPack/SafetyKatz

I just modified a few lines of code so that it can be compiled by csc.exe.

Eg.

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe SafetyKatz.cs /unsafe`

or

`C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe SafetyKatz.cs /unsafe`

