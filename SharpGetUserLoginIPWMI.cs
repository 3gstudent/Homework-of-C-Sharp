using System;
using System.Management;
namespace SharpGetUserLoginIPWMI
{
    class Program
    {
        static void ShowUsage()
        {
            String Usage = @"
SharpGetUserLoginIPWMI
Use WMI to get the login IP of domain users through the event log.
Support local and remote access
Complie:
      C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe SharpGetUserLoginIPWMI.cs
      or
      C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe SharpGetUserLoginIPWMI.cs
Usage:
      SharpGetUserLoginIPWMI <target> <query>
target:
- localhost
- domain\username:password@server
query:
- all
- TimeGenerated<=20210326

Eg:
      SharpGetUserLoginIPRPC.exe localhost all
      SharpGetUserLoginIPRPC.exe test.com\administrator:password@123@192.168.1.1 ""TimeGenerated<=20210326""

";
            Console.WriteLine(Usage);
        }

        static void Main(String[] args)
        {
            if (args.Length != 2)
            {
                ShowUsage();
                System.Environment.Exit(0);
            }
            try
            {
                String queryPath;
                ManagementScope s;
                if (args[0] == "localhost")
                {
                    Console.WriteLine("[*] Try to query local eventlog");
                    s = new ManagementScope("root\\CIMV2");
                }
                else
                {
                    Console.WriteLine(args[0]);
                    int pos1 = args[0].IndexOf("\\");
                    String domain = args[0].Substring(0, pos1);
                    int pos2 = args[0].IndexOf(":");
                    String username = args[0].Substring(pos1 + 1, pos2 - pos1 - 1);
                    int pos3 = args[0].LastIndexOf("@");
                    String password = args[0].Substring(pos2 + 1, pos3 - pos2 - 1);
                    String server = args[0].Substring(pos3 + 1);
                    Console.WriteLine("[*] Try to query remote eventlog");
                    Console.WriteLine("    Domain   : " + domain);
                    Console.WriteLine("    Username : " + username);
                    Console.WriteLine("    Password : " + password);
                    Console.WriteLine("    Server   : " + server);
                    var opt = new ConnectionOptions(); ;
                    opt.Username = domain + "\\" + username;
                    opt.Password = password;
                    s = new ManagementScope("\\\\" + server + "\\root\\CIMV2", opt);
                }
                if (args[1] == "all")
                    queryPath = "SELECT * FROM Win32_NTLogEvent Where Logfile = 'Security'";
                else
                    queryPath = "SELECT * FROM Win32_NTLogEvent Where Logfile = 'Security' AND " + args[1];
                Console.WriteLine("[*] Try to query: " + queryPath);
                SelectQuery q = new SelectQuery(queryPath);

                ManagementObjectSearcher mos = new ManagementObjectSearcher(s, q);
                int flagTotal = 0;
                int flagExist = 0;
                foreach (ManagementObject o in mos.Get())
                {
                    flagTotal++;
                    String Message = o.GetPropertyValue("Message").ToString();
                    int pos1 = Message.LastIndexOf("Security ID");
                    int pos2 = Message.LastIndexOf("Account Name");
                    int pos3 = Message.LastIndexOf("Account Domain");
                    int pos4 = Message.LastIndexOf("Logon ID");
                    int pos5 = Message.LastIndexOf("Source Network Address");
                    int pos6 = Message.LastIndexOf("Source Port");
                    int length1 = pos2 - pos1 - 16;
                    int length2 = pos4 - pos3 - 20;
                    int length3 = pos3 - pos2 - 17;
                    int length4 = pos6 - pos5 - 27;
                    if (length1 < 0 || length2 < 0 || length3 < 0 || length4 < 0)
                        continue;
                    String targetUserSid = Message.Substring(pos1 + 14, length1);
                    String targetDomainName = Message.Substring(pos3 + 17, length2);
                    String targetUserName = Message.Substring(pos2 + 15, length3);
                    String ipAddress = Message.Substring(pos5 + 24, length4);
                    if (targetUserSid.Length > 9 && ipAddress.Length > 8)
                    {
                        Console.WriteLine("[+] EventRecordID: " + o.GetPropertyValue("RecordNumber"));
                        Console.WriteLine("    TimeCreated  : " + o.GetPropertyValue("TimeGenerated"));
                        Console.WriteLine("    UserSid:       " + targetUserSid);
                        Console.WriteLine("    DomainName:    " + targetDomainName);
                        Console.WriteLine("    UserName:      " + targetUserName);
                        Console.WriteLine("    IpAddress:     " + ipAddress);
                        flagExist++;
                    }
                }
                Console.WriteLine("Total: " + flagTotal + ", Exist: " + flagExist);

            }
            catch (Exception e)
            {
                Console.WriteLine("[!] ERROR: {0}", e);
            }
        }
    }
}