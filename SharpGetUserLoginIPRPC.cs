using System;
using System.Diagnostics.Eventing.Reader;
using System.Xml;
using System.Security;
namespace SharpGetUserLoginIPRPC
{
    class Program
    {
        static void ShowUsage()
        {
            String Usage = @"
SharpGetUserLoginIPRPC
Use RPC to get the login IP of domain users through the event log.
Support local and remote access
Complie:
      C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe SharpGetUserLoginIPRPC.cs
      or
      C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe SharpGetUserLoginIPRPC.cs
Usage:
      SharpGetUserLoginIPRPC <target> <query>
target:
- localhost
- domain\username:password@server
query:
- all
- Event/System/TimeCreated/@SystemTime>='2022-01-01T00:00:00'

Eg:
      SharpGetUserLoginIPRPC.exe localhost all
      SharpGetUserLoginIPRPC.exe test.com\administrator:password@123@192.168.1.1 ""Event/System/TimeCreated/@SystemTime >= '2022-01-26T02:30:39' and Event/System/TimeCreated/@SystemTime <= '2022-01-26T02:31:00'""

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
                EventLogSession session;
                String queryPath;
                if (args[0] == "localhost")
                {
                    Console.WriteLine("[*] Try to query local eventlog");
                    session = new EventLogSession();
                }                   
                else
                {
                    Console.WriteLine(args[0]);                    
                    int pos1 = args[0].IndexOf("\\");
                    String domain = args[0].Substring(0, pos1);
                    int pos2 = args[0].IndexOf(":");
                    String username = args[0].Substring(pos1+1, pos2-pos1-1);
                    int pos3 = args[0].LastIndexOf("@");
                    String password = args[0].Substring(pos2+1, pos3-pos2-1);
                    String server = args[0].Substring(pos3+1);
                    Console.WriteLine("[*] Try to query remote eventlog");
                    Console.WriteLine("    Domain   : " + domain);
                    Console.WriteLine("    Username : " + username);
                    Console.WriteLine("    Password : " + password);
                    Console.WriteLine("    Server   : " + server);
                    SecureString securePwd = new SecureString();
                    foreach (char c in password)
                    {
                        securePwd.AppendChar(c);
                    }
                    session = new EventLogSession(server, domain, username, securePwd, SessionAuthentication.Negotiate);
                }
                if (args[1] == "all")
                    queryPath = "(Event/System/EventID=4624)";
                else
                    queryPath = "(Event/System/EventID=4624) and " + args[1];
                Console.WriteLine("[*] Try to query: " + queryPath);
                EventLogQuery eventLogQuery = new EventLogQuery("Security", PathType.LogName, queryPath)
                {
                    Session = session,
                    TolerateQueryErrors = true,
                    ReverseDirection = true
                };
                int flagTotal = 0;
                int flagExist = 0;
                using (EventLogReader eventLogReader = new EventLogReader(eventLogQuery))
                {
                    eventLogReader.Seek(System.IO.SeekOrigin.Begin, 0);
                    do
                    {                  
                        EventRecord eventData = eventLogReader.ReadEvent();
                        if (eventData == null)
                            break;
                        flagTotal++;
                        XmlDocument xmldoc = new XmlDocument();
                        xmldoc.LoadXml(eventData.ToXml());
                        XmlNodeList recordid = xmldoc.GetElementsByTagName("EventRecordID");
                        XmlNodeList data = xmldoc.GetElementsByTagName("Data");
                        String targetUserSid = data[4].InnerText;
                        String targetDomainName = data[6].InnerText;
                        String targetUserName = data[5].InnerText;
                        String ipAddress = data[18].InnerText;                    
                        if (targetUserSid.Length > 9 && ipAddress.Length > 8)
                        {
                            Console.WriteLine("[+] EventRecordID: " + recordid[0].InnerText);
                            Console.WriteLine("    TimeCreated  : " + eventData.TimeCreated);
                            Console.WriteLine("    UserSid:       " + targetUserSid);
                            Console.WriteLine("    DomainName:    " + targetDomainName);
                            Console.WriteLine("    UserName:      " + targetUserName);
                            Console.WriteLine("    IpAddress:     " + ipAddress);
                            flagExist++;
                        }
                        eventData.Dispose();
                    } while (true);
                    Console.WriteLine("Total: " + flagTotal + ", Exist: " + flagExist);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] ERROR: {0}", e);
            }        
        }
    }
}