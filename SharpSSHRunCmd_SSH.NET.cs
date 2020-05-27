
using System;
using System.IO;
using Renci.SshNet;

namespace SharpSSHRunCmd_SSH.NET
{
    class Program
    {
        static void ShowUsage()
        {
            string Usage = @"
SharpSSHRunCmd_SSH.NET
Remote command execution via SSH(Based on SSH.NET).
Support password and privatekeyfile.
Author:3gstudent
Reference:https://github.com/sshnet/SSH.NET
Note:
You need to reference Renci.SshNet.dll.
You can download Renci.SshNet.dll from https://github.com/sshnet/SSH.NET/releases/download/2016.1.0/SSH.NET-2016.1.0-bin.zip
Complie:
      C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe SharpSSHRunCmd_SSH.NET.cs /r:Renci.SshNet.dll

Usage:
      SharpSSHRunCmd_SSH.NET.exe <SSH ServerIP> <SSH ServerPort> <mode> <user> <password> <cmd>
      <mode>:
      - plaintext
      - keyfile
If the <cmd> is shell,you will get an interactive shell.

Eg:
      SharpSSHRunCmd_SSH.NET.exe 192.168.1.1 22 plaintext root toor shell
      SharpSSHRunCmd_SSH.NET.exe 192.168.1.1 22 keyfile root id_rsa ps
";
            Console.WriteLine(Usage);
        }

    static void Main(string[] args)
        {
            if (args.Length != 6)
                ShowUsage();
            else
            {
                try
                {
                    String Host = args[0];
                    String Port = args[1];
                    String Username = args[3];
                    String Password = null;
                    String Keypath = null;
                    String cmd = args[5];
                    if (args[2] == "plaintext")
                    {
                        Password = args[4];
                        var connectionInfo = new PasswordConnectionInfo(Host, Int32.Parse(Port), Username, Password);
                        connectionInfo.Timeout = TimeSpan.FromSeconds(10);
                        var ssh = new SshClient(connectionInfo);
                        ssh.Connect();
                        Console.WriteLine("[+] Valid: " + Username + "  " + Password);
                        if (cmd == "shell")
                            while(true)
                            {
                                Console.Write("\n#");
                                cmd = Console.ReadLine();
                                if(cmd == "exit")
                                {
                                    Console.Write("[*] Exit.");
                                    ssh.Disconnect();
                                    ssh.Dispose();
                                    System.Environment.Exit(0);
                                }
                                var runcmd = ssh.CreateCommand(cmd);
                                var res = runcmd.Execute();
                                Console.Write(res);
                            }
                        else
                        {
                            var runcmd = ssh.CreateCommand(cmd);
                            var res = runcmd.Execute();
                            Console.Write(res);
                            ssh.Disconnect();
                            ssh.Dispose();                        
                        }
                    }
                    else if (args[2] == "keyfile")
                    {
                        Keypath = args[4];
                        FileStream keyFileStream = File.OpenRead(Keypath);
                        byte[] byData = new byte[40];
                        keyFileStream.Read(byData, 0, 40);
                        string keyData = System.Text.Encoding.Default.GetString(byData);
                        if (keyData.Contains("OPENSSH"))
                        {
                            Console.WriteLine("[!] Bad format of key file. You should use puttygen to convert the format.");
                            System.Environment.Exit(0);
                        }

                        keyFileStream.Seek(0, SeekOrigin.Begin);
                        var connectionInfo = new PrivateKeyConnectionInfo(Host, Int32.Parse(Port), Username, new PrivateKeyFile(keyFileStream));
                        connectionInfo.Timeout = TimeSpan.FromSeconds(10);

                        var ssh = new SshClient(connectionInfo);
                        ssh.Connect();
                        Console.WriteLine("[+] Valid: " + Username + "  " + Keypath);
                        if (cmd == "shell")
                            while(true)
                            {
                                Console.Write("\n#");
                                cmd = Console.ReadLine();
                                if(cmd == "exit")
                                {
                                    Console.Write("[*] Exit.");
                                    ssh.Disconnect();
                                    ssh.Dispose();
                                    System.Environment.Exit(0);
                                }
                                var runcmd = ssh.CreateCommand(cmd);
                                var res = runcmd.Execute();
                                Console.Write(res);
                            }
                        else
                        {
                            var runcmd = ssh.CreateCommand(cmd);
                            var res = runcmd.Execute();
                            Console.Write(res);
                            ssh.Disconnect();
                            ssh.Dispose();                        
                        }
                    }
                    else
                    {
                        Console.WriteLine("[!] Wrong parameter");
                        System.Environment.Exit(0);
                    }
                }
                catch (Renci.SshNet.Common.SshException ex)
                {
                    Console.WriteLine("[!] " + ex.Message);
                }
                catch (Exception exception)
                {
                    Console.WriteLine("[!] " + exception.Message);
                }
            }
        }
    }
}
