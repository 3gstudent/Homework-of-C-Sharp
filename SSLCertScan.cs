
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SSLCertScan
{
    class Program
    {
        static void ShowUsage()
        {
            string Usage = @"
SSLCertScan
Use to scan the website SSL certificate.
Modified by 3gstudent
Reference:https://github.com/ryanries/SharpTLSScan

Usage:
      SSLCertScan.exe <IP> <Port>
Eg:
      SSLCertScan.exe 192.168.1.1 443
";
            Console.WriteLine(Usage);
        }
        static void Main(string[] args)
        {
            if (args.Length != 2)
                ShowUsage();
            else
            {
                try
                {
                    TcpClient tcpClient = new TcpClient(args[0], Convert.ToInt32(args[1]));
                    Console.WriteLine("[+] " + args[0] + " responds to TCP on " + args[1] + ".\n");
                    SslStream sslStream = new SslStream(tcpClient.GetStream(), true, CertificateValidationCallBack);
                    sslStream.AuthenticateAsClient(args[0]);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] " + ex.Message);
                    return;
                }
            }

        }
        private static bool CertificateValidationCallBack(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // Certificate2 is better than Certificate1, right?
            X509Certificate2 cert = (X509Certificate2)certificate;

            string[] subjectPieces = splitDN(cert.Subject);

            Console.Write("Certificate Subject   : ");
            for (int x = 0; x < subjectPieces.Length; x++)
            {
                if (x == 0)
                    Console.WriteLine(subjectPieces[x]);
                else
                    Console.WriteLine("                        " + subjectPieces[x]);
            }

            string[] issuerPieces = splitDN(cert.Issuer);

            Console.Write("Certificate Issuer    : ");
            for (int x = 0; x < issuerPieces.Length; x++)
            {
                if (x == 0)
                    Console.WriteLine(issuerPieces[x]);
                else
                    Console.WriteLine("                        " + issuerPieces[x]);
            }

            Console.WriteLine("Certificate Begins    : " + cert.NotBefore);
            Console.WriteLine("Certificate Expires   : " + cert.NotAfter);
            Console.WriteLine("Certificate Version   : " + cert.Version);
            if (cert.SignatureAlgorithm.FriendlyName.ToLower().Contains("md5"))
            {
                Console.WriteLine("Signature Algorithm   : " + cert.SignatureAlgorithm.FriendlyName + " (" + cert.SignatureAlgorithm.Value + ")");
            }
            else
            {
                Console.WriteLine("Signature Algorithm   : " + cert.SignatureAlgorithm.FriendlyName + " (" + cert.SignatureAlgorithm.Value + ")");
            }
            Console.WriteLine("Key Exchange Algorithm: " + cert.PublicKey.Key.KeyExchangeAlgorithm);
            Console.WriteLine("Public Key Algorithm  : " + new System.Security.Cryptography.Oid(cert.GetKeyAlgorithm()).FriendlyName);
            Console.WriteLine("Public Key Size       : " + cert.PublicKey.Key.KeySize);
            byte[] RSAkey = cert.GetPublicKey();
            string strRSAkey = "";
            for (int i = 0; i < RSAkey.Length; i++)
            {
                strRSAkey += RSAkey[i].ToString("X2");
            }
            Console.WriteLine("Public Key            : " + strRSAkey);

            foreach (X509Extension extension in cert.Extensions)
            {
                if (extension.Oid.FriendlyName == "Subject Alternative Name")
                {
                    AsnEncodedData asnData = new AsnEncodedData(extension.Oid, extension.RawData);
                    string[] sans = asnData.Format(false).Split(',');
                    Console.Write("Alternative Names     : ");
                    for (int x = 0; x < sans.Length; x++)
                    {
                        if (x == 0)
                            Console.WriteLine(sans[x]);
                        else
                            Console.WriteLine("                       " + sans[x]);
                    }
                }
            }
            Console.Write("Certificate Validated : ");
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                Console.WriteLine("Yes");
            }
            else
            {
                Console.WriteLine("No (" + sslPolicyErrors + ")");
            }
            return true;
        }

        private static string[] splitDN(string input)
        {
            string[] splitString = input.Split(',');
            List<string> correctedSplitString = new List<string>();
            int index = 0;
            foreach (string part in splitString)
            {
                if (part.Contains('='))
                {
                    correctedSplitString.Add(part.Trim());
                    index++;
                }
                else
                {
                    if (index > 0)
                        correctedSplitString[index - 1] = correctedSplitString[index - 1] + ", " + part.Trim();
                    else
                        correctedSplitString.Add(part.Trim());
                    index++;
                }
            }
            return correctedSplitString.ToArray();
        }
    }

}
