using System;
using Microsoft.Office.Interop.Outlook;

namespace MAPI_TOOL
{
    class Program
    {
        private static void ListMail(Microsoft.Office.Interop.Outlook.NameSpace ns,String folder,String mode)
        {
            Console.WriteLine("[*] Try to list mail");
            Console.WriteLine("[*] Folder:" + folder);
            Console.WriteLine("[*] Mode:" + mode);
            Console.WriteLine();
            Microsoft.Office.Interop.Outlook.MAPIFolder mapifolder = null;
            if (folder == "Inbox")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderInbox);
            else if(folder == "Drafts")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderDrafts);
            else if (folder == "SentItems")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderSentMail);
            else if (folder == "DeletedItems")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderDeletedItems);
            else if (folder == "Outbox")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderOutbox);
            else if (folder == "JunkEmail")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderJunk);
            else
            {
                Console.WriteLine("[!] The folder is not supported yet.\r\n");
                return;
            }
            Microsoft.Office.Interop.Outlook.Items items = mapifolder.Items;
            Console.WriteLine("[+] Folder size:" + mapifolder.Items.Count + "\r\n");
            if (mode == "all")
                Console.WriteLine("[!] Notice:When the antivirus software is inactive or out-of-date,it will pop up a Outlook security prompt.\r\n");
            foreach (var item in items)
            {
                var mail = item as Microsoft.Office.Interop.Outlook.MailItem;

                if (mail != null)
                {
                    if (mail.UnRead == true)
                        Console.WriteLine("[+] UnRead Mail");
                    else
                        Console.WriteLine("[+] Mail");
                    if (mode == "short")
                    {
                        Console.WriteLine("Subject:" + mail.Subject);
                        Console.WriteLine("ReceivedTime:" + mail.ReceivedTime);
                        if (mail.Attachments.Count > 0)
                        {
                            Console.WriteLine("Attachments:" + mail.Attachments.Count);
                            Microsoft.Office.Interop.Outlook.Attachments attachments = mail.Attachments;
                            foreach (Microsoft.Office.Interop.Outlook.Attachment att in attachments)
                            {
                                Console.WriteLine("    Name:" + att.FileName);
                            }
                        }
                        Console.WriteLine("OutlookVersion:" + mail.OutlookVersion);
                        Console.WriteLine("EntryID:" + mail.EntryID);
                        Console.WriteLine();
                        continue;

                    }
                    else if(mode == "all")
                    {
                        Console.WriteLine("Subject:" + mail.Subject);
                        Console.WriteLine("From:" + mail.SenderName);
                        Console.WriteLine("To:" + mail.To);
                        Console.WriteLine("CC:" + mail.CC);
                        Console.WriteLine("ReceivedTime:" + mail.ReceivedTime);
                        if (mail.Attachments.Count > 0)
                        {
                            Console.WriteLine("Attachments:" + mail.Attachments.Count);
                            Microsoft.Office.Interop.Outlook.Attachments attachments = mail.Attachments;
                            foreach (Microsoft.Office.Interop.Outlook.Attachment att in attachments)
                            {
                                Console.WriteLine("    Name:" + att.FileName);
                            }
                        }
                        Console.WriteLine("Body:\r\n" + mail.Body);
                        Console.WriteLine("OutlookVersion:" + mail.OutlookVersion);
                        Console.WriteLine("EntryID:" + mail.EntryID);
                        Console.WriteLine();
                    }
                }
            }
        }

        private static void ListUnreadMail(Microsoft.Office.Interop.Outlook.NameSpace ns, String folder, String mode)
        {
            Console.WriteLine("[*] Try to list unread mail");
            Console.WriteLine("[*] Folder:" + folder);
            Console.WriteLine("[*] Mode:" + mode);
            Console.WriteLine();
            Microsoft.Office.Interop.Outlook.MAPIFolder mapifolder = null;
            if (folder == "Inbox")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderInbox);
            else if (folder == "Drafts")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderDrafts);
            else if (folder == "SentItems")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderSentMail);
            else if (folder == "DeletedItems")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderDeletedItems);
            else if (folder == "Outbox")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderOutbox);
            else if (folder == "JunkEmail")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderJunk);
            else
            {
                Console.WriteLine("[!] The folder is not supported yet.\r\n");
                return;
            }
            Microsoft.Office.Interop.Outlook.Items items = mapifolder.Items;
            Console.WriteLine("[+] Folder size:" + mapifolder.Items.Count + "\r\n");

            if (mode == "all")
                Console.WriteLine("[!] Notice:When the antivirus software is inactive or out-of-date,it will pop up a Outlook security prompt.\r\n");

            foreach (var item in items)
            {
                var mail = item as Microsoft.Office.Interop.Outlook.MailItem;

                if (mail != null)
                {
                    if (mail.UnRead == false)
                        continue;
                    else
                        Console.WriteLine("[+] UnRead Mail");
                    if (mode == "short")
                    {
                        Console.WriteLine("Subject:" + mail.Subject);
                        Console.WriteLine("ReceivedTime:" + mail.ReceivedTime);
                        if (mail.Attachments.Count > 0)
                        {
                            Console.WriteLine("Attachments:" + mail.Attachments.Count);
                            Microsoft.Office.Interop.Outlook.Attachments attachments = mail.Attachments;
                            foreach (Microsoft.Office.Interop.Outlook.Attachment att in attachments)
                            {
                                Console.WriteLine("    Name:" + att.FileName);
                            }
                        }
                        Console.WriteLine("OutlookVersion:" + mail.OutlookVersion);
                        Console.WriteLine("EntryID:" + mail.EntryID);
                        Console.WriteLine();
                        continue;
                    }
                    else if (mode == "all")
                    {
                        Console.WriteLine("Subject:" + mail.Subject);
                        Console.WriteLine("From:" + mail.SenderName);
                        Console.WriteLine("To:" + mail.To);
                        Console.WriteLine("CC:" + mail.CC);
                        Console.WriteLine("ReceivedTime:" + mail.ReceivedTime);
                        if (mail.Attachments.Count > 0)
                        {
                            Console.WriteLine("Attachments:" + mail.Attachments.Count);
                            Microsoft.Office.Interop.Outlook.Attachments attachments = mail.Attachments;
                            foreach (Microsoft.Office.Interop.Outlook.Attachment att in attachments)
                            {
                                Console.WriteLine("    Name:" + att.FileName);
                            }
                        }
                        Console.WriteLine("Body:\r\n" + mail.Body);
                        Console.WriteLine("OutlookVersion:" + mail.OutlookVersion);
                        Console.WriteLine("EntryID:" + mail.EntryID);
                        Console.WriteLine();
                    }
                }
            }
        }

        private static void SaveAttachment(Microsoft.Office.Interop.Outlook.NameSpace ns, String folder, String EntryID)
        {
            Console.WriteLine("[*] Try to SaveAttachment");
            Console.WriteLine("[*] Folder:" + folder);
            Console.WriteLine("[*] EntryID:" + EntryID);
            Console.WriteLine();

            Microsoft.Office.Interop.Outlook.MAPIFolder mapifolder = null;
            if (folder == "Inbox")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderInbox);
            else if (folder == "Drafts")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderDrafts);
            else if (folder == "SentItems")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderSentMail);
            else if (folder == "DeletedItems")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderDeletedItems);
            else if (folder == "Outbox")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderOutbox);
            else if (folder == "JunkEmail")
                mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderJunk);
            else
            {
                Console.WriteLine("[!] The folder is not supported yet.\r\n");
                return;
            }
            Microsoft.Office.Interop.Outlook.Items items = mapifolder.Items;
            Console.WriteLine("[!] Notice:When the antivirus software is inactive or out-of-date,it will pop up a Outlook security prompt.\r\n");

            foreach (var item in items)
            {
                var mail = item as Microsoft.Office.Interop.Outlook.MailItem;

                if (mail != null)
                {

                    if (mail.EntryID == EntryID)
                    {
                        Console.WriteLine("[+] Catch the mail.");
                        Console.WriteLine("Subject:" + mail.Subject);
                        Console.WriteLine("From:" + mail.SenderName);
                        Console.WriteLine("To:" + mail.To);
                        Console.WriteLine("CC:" + mail.CC);
                        Console.WriteLine("ReceivedTime:" + mail.ReceivedTime);
                        if (mail.Attachments.Count > 0)
                        {
                            Console.WriteLine("Attachments:" + mail.Attachments.Count);
                            Microsoft.Office.Interop.Outlook.Attachments attachments = mail.Attachments;
                            foreach (Microsoft.Office.Interop.Outlook.Attachment att in attachments)
                            {
                                Console.WriteLine("    Name:" + att.FileName);
                                att.SaveAsFile(System.Environment.CurrentDirectory + "\\" + att.FileName);
                            }
                        }
                    }
                }
            }
        }

        private static void GetConfig(Microsoft.Office.Interop.Outlook.NameSpace ns,String mode)
        {
            Console.WriteLine("[*] Try to get config");
            Console.WriteLine();
            Object CurrentProfileName = ns.GetType().InvokeMember("CurrentProfileName",System.Reflection.BindingFlags.GetProperty,null,ns,null);
            Console.WriteLine("[*] CurrentProfileName:" + CurrentProfileName.ToString());

            Object ExchangeMailboxServerName = ns.GetType().InvokeMember("ExchangeMailboxServerName", System.Reflection.BindingFlags.GetProperty, null, ns, null);
            Console.WriteLine("[*] ExchangeMailboxServerName:" + ExchangeMailboxServerName.ToString());

            Object ExchangeMailboxServerVersion = ns.GetType().InvokeMember("ExchangeMailboxServerVersion", System.Reflection.BindingFlags.GetProperty, null, ns, null);
            Console.WriteLine("[*] ExchangeMailboxServerVersion:" + ExchangeMailboxServerVersion.ToString());
            if(mode =="all")
            {
                Console.WriteLine("[!] Notice:When the antivirus software is inactive or out-of-date,it will pop up a Outlook security prompt.\r\n");
                Console.WriteLine("[*] Account-DisplayName:" + ns.Accounts[1].DisplayName);
                Console.WriteLine("[*] Account-SmtpAddress:" + ns.Accounts[1].SmtpAddress);
                Console.WriteLine("[*] Account-AutoDiscoverXml:\r\n" + ns.Accounts[1].AutoDiscoverXml);
                Console.WriteLine("[*] Account-AccountType:" + ns.Accounts[1].AccountType);
            }
        }

        private static void GetGlobalAddress(Microsoft.Office.Interop.Outlook.NameSpace ns)
        {
            Console.WriteLine("[*] Try to get global address");
            Console.WriteLine();
            Console.WriteLine("[!] Notice:When the antivirus software is inactive or out-of-date,it will pop up a Outlook security prompt.\r\n");
            AddressList aL = ns.GetGlobalAddressList();
            AddressEntries aEs = aL.AddressEntries;
            for (int i = 0; i < aEs.Count; i++)
            {
                Console.WriteLine(aEs[i+1].GetExchangeUser().PrimarySmtpAddress);
            }
        }

        private static void GetContacts(Microsoft.Office.Interop.Outlook.NameSpace ns)
        {
            Console.WriteLine("[*] Try to get contacts");
            Console.WriteLine();
            Console.WriteLine("[!] Notice:When the antivirus software is inactive or out-of-date,it will pop up a Outlook security prompt.\r\n");
            Microsoft.Office.Interop.Outlook.MAPIFolder mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderContacts);
            for (int i= 0;i< mapifolder.Items.Count;i++)
            {
                ContactItem item = (Microsoft.Office.Interop.Outlook.ContactItem)mapifolder.Items[i+1];
                Console.WriteLine(item.Email1Address);
            }
        }

        private static void GetAllFolders(Microsoft.Office.Interop.Outlook.NameSpace ns)
        {
            Console.WriteLine("[*] Try to get the size of all folders");
            Microsoft.Office.Interop.Outlook.MAPIFolder mapifolder = null;
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderInbox);
            Console.WriteLine("Inbox: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderDrafts);
            Console.WriteLine("Drafts: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderSentMail);
            Console.WriteLine("SentItems: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderDeletedItems);
            Console.WriteLine("DeletedItems: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderOutbox);
            Console.WriteLine("Outbox: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderJunk);
            Console.WriteLine("JunkEmail: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderCalendar);
            Console.WriteLine("Calendar: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderContacts);
            Console.WriteLine("Contacts: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderJournal);
            Console.WriteLine("Journal: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderNotes);
            Console.WriteLine("Notes: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderTasks);
            Console.WriteLine("Tasks: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderConflicts);
            Console.WriteLine("Conflicts: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderSyncIssues);
            Console.WriteLine("SyncIssues: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderLocalFailures);
            Console.WriteLine("LocalFailures: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderServerFailures);
            Console.WriteLine("ServerFailures: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderRssFeeds);
            Console.WriteLine("RssFeeds: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderToDo);
            Console.WriteLine("ToDo: " + mapifolder.Items.Count);
            mapifolder = ns.GetDefaultFolder(Microsoft.Office.Interop.Outlook.OlDefaultFolders.olFolderSuggestedContacts);
            Console.WriteLine("SuggestedContacts: " + mapifolder.Items.Count);
        }


        static void ShowUsage()
        {

            string Usage = @"
Use MAPI to manage Outlook.
Author:3gstudent
Complie:
C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe mapi_tool.cs /r:Microsoft.Office.Interop.Outlook.dll
or
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe mapi_tool.cs /r:Microsoft.Office.Interop.Outlook.dll

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

";
            Console.WriteLine(Usage);
        }
        static void Main(string[] args)
        {
            Microsoft.Office.Interop.Outlook.Application app = new Microsoft.Office.Interop.Outlook.Application();
            Microsoft.Office.Interop.Outlook.NameSpace ns = app.GetNamespace("MAPI");

            try
            {
                if (args.Length == 1)
                {
                    if (args[0] == "GetAllFolders")
                        GetAllFolders(ns);
                    else if (args[0] == "GetGlobalAddressEx")
                        GetGlobalAddress(ns);
                    else if (args[0] == "GetContactsEx")
                        GetContacts(ns);
                    else if (args[0] == "GetConfig")
                        GetConfig(ns, "short");
                    else if (args[0] == "GetConfigEx")
                        GetConfig(ns, "all");
                    else
                        Console.WriteLine("[!] Wrong parameter");
                }
                else if (args.Length == 2)
                {
                    if (args[0] == "ListMail")
                        ListMail(ns, args[1], "short");
                    else if (args[0] == "ListUnreadMail")
                        ListUnreadMail(ns, args[1], "short");
                    else if (args[0] == "ListMailEx")
                        ListMail(ns, args[1], "all");
                    else if (args[0] == "ListUnreadMailEx")
                        ListUnreadMail(ns, args[1], "all");
                    else
                        Console.WriteLine("[!] Wrong parameter");
                }

                else if (args.Length == 3)
                {
                    if (args[0] == "SaveAttachment")
                        SaveAttachment(ns, args[1], args[2]);
                    else
                        Console.WriteLine("[!] Wrong parameter");
                }
                else
                {
                    ShowUsage();
                }
            }
            catch(System.Exception ex)
            {
                Console.WriteLine("[!] Exception:" + ex.Message);
            }
        }
    }
}
