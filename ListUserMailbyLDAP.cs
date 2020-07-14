using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices;

namespace ListUserMailbyLDAP
{
    class Program
    {
        static void ShowUsage()
        {
            string Usage = @"
GetMailbyLDAP
Use to export all users' mail by LDAP.
Modified from https://github.com/Mr-Un1k0d3r/RedTeamCSharpScripts/blob/master/enumerateuser.cs
Complie:
      C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe ListUserMailbyLDAP.cs /r:System.DirectoryServices.dll
      or
      C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe ListUserMailbyLDAP.cs /r:System.DirectoryServices.dll
Usage:
      ListUserMailbyLDAP <LDAP ServerIP> <user> <password>      
Eg:
      ListUserMailbyLDAP.exe 192.168.1.1 test1 password1
";
            Console.WriteLine(Usage);
        }


        static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                ShowUsage(); 
                System.Environment.Exit(0);
            }
            try
            {
                string q = "(&(objectCategory=User))";
                Console.WriteLine("[*] Querying LDAP://{0}", args[0]);
                Console.WriteLine("[*] Querying: {0}", q);
                DirectoryEntry de = new DirectoryEntry("LDAP://" + args[0],args[1],args[2]);
                DirectorySearcher ds = new DirectorySearcher(de);
                ds.Filter = q;
                foreach (SearchResult r in ds.FindAll())
                {           
                    Console.WriteLine("User:" + r.Properties["samaccountname"][0]);
                    if(r.Properties["mail"].Count > 0)
                        Console.WriteLine("Mail:" + r.Properties["mail"][0]);
                    Console.WriteLine("whencreated:" + r.Properties["whencreated"][0]);
                    Console.WriteLine("pwdlastset:" + r.Properties["pwdlastset"][0]);
                    if(r.Properties["accountexpires"][0].ToString()== "9223372036854775807")
                        Console.WriteLine("accountexpires:Never");
                    else
                        Console.WriteLine("accountexpires:" + r.Properties["accountexpires"][0]);                                        
                    Console.WriteLine("lastlogon:" + r.Properties["lastlogon"][0]);
                    Console.WriteLine("---");            
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] ERROR: {0}", e.Message);
            }
        }
    }
}
