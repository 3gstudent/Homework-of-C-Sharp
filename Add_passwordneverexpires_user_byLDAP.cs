using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices;

namespace Add_passwordneverexpires_user_byLDAP
{
    class Program
    {
        static void ShowUsage()
        {
            string Usage = @"
Add_passwordneverexpires_user_byLDAP
Use to set the selected user with password_never_expires by LDAP.
Complie:
      C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe Add_passwordneverexpires_user_byLDAP.cs /r:System.DirectoryServices.dll
      or
      C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe Add_passwordneverexpires_user_byLDAP.cs /r:System.DirectoryServices.dll
Usage:
      Add_passwordneverexpires_user_byLDAP <LDAP ServerIP> <user> <password> <target user>    
Eg:
      Add_passwordneverexpires_user_byLDAP.exe 192.168.1.1 administrator password1 test1
";
            Console.WriteLine(Usage);
        }

        static void Main(string[] args)
        {
            if (args.Length != 4)
            {
                ShowUsage();
                System.Environment.Exit(0);
            }
            try
            {
                DirectoryEntry entry = new DirectoryEntry("LDAP://" + args[0], args[1], args[2]);
                //When you are in the domain
                //DirectoryEntry de = new DirectoryEntry("LDAP://" + args[0]);

                DirectorySearcher deSearch = new DirectorySearcher(entry);
                deSearch.Filter = "(&(&(objectCategory=person)(objectClass=user))(sAMAccountName=" + args[3] + "))";
                deSearch.SearchScope = SearchScope.Subtree;
                
                SearchResult result = deSearch.FindOne();
                entry = new DirectoryEntry(result.Path, args[1], args[2]);
                //When you are in the domain
                //DirectoryEntry de = new DirectoryEntry("LDAP://" + args[0]);

                Console.WriteLine("[*] Querying: {0}", deSearch.Filter);
                Console.WriteLine("[+] samaccountname: {0}", entry.Properties["samaccountname"][0]);
                int NON_EXPIRE_FLAG = 0x10000;
                int x = (int)entry.Properties["userAccountControl"].Value;
                Console.WriteLine("    userAccountControl: {0}", x);
                Console.WriteLine("[*] Trying to set userAccountControl");
                entry.Properties["userAccountControl"].Value = x | NON_EXPIRE_FLAG;
                entry.CommitChanges();

                result = deSearch.FindOne();
                entry = new DirectoryEntry(result.Path, args[1], args[2]);
                //When you are in the domain
                //DirectoryEntry de = new DirectoryEntry("LDAP://" + args[0]);

                int y = (int)entry.Properties["userAccountControl"].Value;
                Console.WriteLine("[+] samaccountname: {0}", entry.Properties["samaccountname"][0]);
                Console.WriteLine("    userAccountControl(new): {0}", y);
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] ERROR: {0}", e.Message);
            }
        }
    }
}