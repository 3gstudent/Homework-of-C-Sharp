using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices;

namespace List_passwordneverexpires_user_byLDAP
{
    class Program
    {
        static void ShowUsage()
        {
            string Usage = @"
List_passwordneverexpires_user_byLDAP
Use to export all users with password_never_expires by LDAP.
Complie:
      C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe List_passwordneverexpires_user_byLDAP.cs /r:System.DirectoryServices.dll
      or
      C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe List_passwordneverexpires_user_byLDAP.cs /r:System.DirectoryServices.dll
Usage:
      List_passwordneverexpires_user_byLDAP <LDAP ServerIP> <user> <password>      
Eg:
      List_passwordneverexpires_user_byLDAP.exe 192.168.1.1 test1 password1
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
                //When you are in the domain
                //DirectoryEntry de = new DirectoryEntry("LDAP://" + args[0]);
                DirectorySearcher ds = new DirectorySearcher(de);
                ds.Filter = q;
                Console.WriteLine("[*] Export all users with password_never_expires");
                foreach (SearchResult r in ds.FindAll())
                {           
                    int x = Convert.ToInt32(r.Properties["useraccountcontrol"][0]);
                    if((x & 0x10000) == 0x10000)
                        Console.WriteLine(r.Properties["samaccountname"][0]);            
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] ERROR: {0}", e.Message);
            }
        }
    }
}
