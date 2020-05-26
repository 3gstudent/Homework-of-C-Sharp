
using System;
using System.IO;
using Renci.SshNet;

namespace SharpSSHCheck_SSH.NET
{
    class Program
    {
        static void ShowUsage()
        {
            string Usage = @"
SharpSSHCheck_SSH.NET
Use to check the valid credential of SSH(Based on SSH.NET).
Support password and privatekeyfile.
Author:3gstudent
Reference:https://github.com/sshnet/SSH.NET
Note:
You need to reference Renci.SshNet.dll.
You can download Renci.SshNet.dll from https://github.com/sshnet/SSH.NET/releases/download/2016.1.0/SSH.NET-2016.1.0-bin.zip
Complie:
      C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe SharpSSHCheck_SSH.NET.cs /r:Renci.SshNet.dll

Usage:
      SharpSSHCheck_SSH.NET.exe <SSH ServerIP> <SSH ServerPort> <mode> <user> <password>
      <mode>:
      - plaintext
      - keyfile
Eg:
      SharpSSHCheck_SSH.NET.exe 192.168.1.1 22 plaintext root toor
      SharpSSHCheck_SSH.NET.exe 192.168.1.1 22 keyfile root id_rsa
";
            Console.WriteLine(Usage);
        }

    static void Main(string[] args)
        {
            if (args.Length != 5)
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
                    if (args[2] == "plaintext")
                    {
                        Password = args[4];
                        var connectionInfo = new PasswordConnectionInfo(Host, Int32.Parse(Port), Username, Password);
                        connectionInfo.Timeout = TimeSpan.FromSeconds(10);
                        var ssh = new SshClient(connectionInfo);
                        ssh.Connect();
                        Console.WriteLine("[+] Valid: " + Username + "  " + Password);
                        ssh.Disconnect();
                        ssh.Dispose();
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
                        ssh.Disconnect();
                        ssh.Dispose();
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
