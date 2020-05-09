using System;
using System.Text;

namespace BrailleToASCII
{
    class Program
    {
        public static string StringToUnicode(string source)
        {
            var bytes = Encoding.Unicode.GetBytes(source);
            var stringBuilder = new StringBuilder();
            for (var i = 0; i < bytes.Length; i += 2)
            {
                stringBuilder.AppendFormat("\\u{0:x2}{1:x2}", bytes[i + 1], bytes[i]);
            }
            return stringBuilder.ToString();
        }
        public static string BrailleToASCII(string str)
        {
            string tempstr = null;
            string[] arr = str.Split('\\');
            for (int x = 1; x < arr.Length; x++)
            {

                if (arr[x] == "u283c")
                {
                    x++;
                    if (arr[x] == "u2801")
                        tempstr += "1";
                    else if (arr[x] == "u2803")
                        tempstr += "2";
                    else if (arr[x] == "u2809")
                        tempstr += "3";
                    else if (arr[x] == "u2819")
                        tempstr += "4";
                    else if (arr[x] == "u2811")
                        tempstr += "5";
                    else if (arr[x] == "u280b")
                        tempstr += "6";
                    else if (arr[x] == "u281b")
                        tempstr += "7";
                    else if (arr[x] == "u2813")
                        tempstr += "8";
                    else if (arr[x] == "u280a")
                        tempstr += "9";
                    else if (arr[x] == "u281a")
                        tempstr += "0";
                    else
                        Console.WriteLine("[!]Bad character:" + arr[x - 1] + arr[x] + ",index:" + (x-1));
                }
                else if (arr[x] == "u2820")
                {
                    x++;
                    if (arr[x] == "u2801")
                        tempstr += "A";
                    else if (arr[x] == "u2803")
                        tempstr += "B";
                    else if (arr[x] == "u2809")
                        tempstr += "C";
                    else if (arr[x] == "u2819")
                        tempstr += "D";
                    else if (arr[x] == "u2811")
                        tempstr += "E";
                    else if (arr[x] == "u280b")
                        tempstr += "F";
                    else if (arr[x] == "u281b")
                        tempstr += "G";
                    else if (arr[x] == "u2813")
                        tempstr += "H";
                    else if (arr[x] == "u280a")
                        tempstr += "I";
                    else if (arr[x] == "u281a")
                        tempstr += "J";
                    else if (arr[x] == "u2805")
                        tempstr += "K";
                    else if (arr[x] == "u2807")
                        tempstr += "L";
                    else if (arr[x] == "u280d")
                        tempstr += "M";
                    else if (arr[x] == "u281d")
                        tempstr += "N";
                    else if (arr[x] == "u2815")
                        tempstr += "O";
                    else if (arr[x] == "u280f")
                        tempstr += "P";
                    else if (arr[x] == "u281f")
                        tempstr += "Q";
                    else if (arr[x] == "u2817")
                        tempstr += "R";
                    else if (arr[x] == "u280e")
                        tempstr += "S";
                    else if (arr[x] == "u281e")
                        tempstr += "T";
                    else if (arr[x] == "u2825")
                        tempstr += "U";
                    else if (arr[x] == "u2827")
                        tempstr += "V";
                    else if (arr[x] == "u283a")
                        tempstr += "W";
                    else if (arr[x] == "u282d")
                        tempstr += "X";
                    else if (arr[x] == "u283d")
                        tempstr += "Y";
                    else if (arr[x] == "u2835")
                        tempstr += "Z";
                    else
                        Console.WriteLine("[!]Bad character:" + arr[x - 1] + arr[x] + ",index:" + (x-1));
                }
                else if (arr[x] == "u2801")
                    tempstr += "a";
                else if (arr[x] == "u2803")
                    tempstr += "b";
                else if (arr[x] == "u2809")
                    tempstr += "c";
                else if (arr[x] == "u2819")
                    tempstr += "d";
                else if (arr[x] == "u2811")
                    tempstr += "e";
                else if (arr[x] == "u280b")
                    tempstr += "f";
                else if (arr[x] == "u281b")
                    tempstr += "g";
                else if (arr[x] == "u2813")
                    tempstr += "h";
                else if (arr[x] == "u280a")
                    tempstr += "i";
                else if (arr[x] == "u281a")
                    tempstr += "j";
                else if (arr[x] == "u2805")
                    tempstr += "k";
                else if (arr[x] == "u2807")
                    tempstr += "l";
                else if (arr[x] == "u280d")
                    tempstr += "m";
                else if (arr[x] == "u281d")
                    tempstr += "n";
                else if (arr[x] == "u2815")
                    tempstr += "o";
                else if (arr[x] == "u280f")
                    tempstr += "p";
                else if (arr[x] == "u281f")
                    tempstr += "q";
                else if (arr[x] == "u2817")
                    tempstr += "r";
                else if (arr[x] == "u280e")
                    tempstr += "s";
                else if (arr[x] == "u281e")
                    tempstr += "t";
                else if (arr[x] == "u2825")
                    tempstr += "u";
                else if (arr[x] == "u2827")
                    tempstr += "v";
                else if (arr[x] == "u283a")
                    tempstr += "w";
                else if (arr[x] == "u282d")
                    tempstr += "x";
                else if (arr[x] == "u283d")
                    tempstr += "y";
                else if (arr[x] == "u2835")
                    tempstr += "z";
                else if (arr[x] == "u2836")
                    tempstr += ")";
                else if (arr[x] == "u2802")
                    tempstr += ",";
                else if (arr[x] == "u2816")
                    tempstr += "!";
                else if (arr[x] == "u280c")
                    tempstr += "/";
                else if (arr[x] == "u2824")
                    tempstr += "-";
                else if (arr[x] == "u2832")
                    tempstr += ".";
                else if (arr[x] == "u2826")
                    tempstr += "?";
                else if (arr[x] == "u2806")
                    tempstr += ";";
                else if (arr[x] == "u2804")
                    tempstr += "'";
                else if (arr[x] == "u2832")
                    tempstr += "$";
                else if (arr[x] == "u002b")
                    tempstr += "+";
                else if (arr[x] == "u003d")
                    tempstr += "=";
                else
                    Console.WriteLine("[!]Bad character:" + arr[x] + ",index:" + x);
            }       
            return tempstr;
        }

        static void Main(string[] args)
        {
            string str = "⠼⠁⠼⠃⠼⠉⠼⠙⠼⠑⠼⠋⠼⠛⠼⠓⠼⠊⠼⠚⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵⠠⠁⠠⠃⠠⠉⠠⠙⠠⠑⠠⠋⠠⠛⠠⠓⠠⠊⠠⠚⠠⠅⠠⠇⠠⠍⠠⠝⠠⠕⠠⠏⠠⠟⠠⠗⠠⠎⠠⠞⠠⠥⠠⠧⠠⠺⠠⠭⠠⠽⠠⠵⠶⠂⠖⠌⠤⠲⠦⠆⠄⠲";
            string unistr = StringToUnicode(str);
            string result = BrailleToASCII(unistr);
            Console.WriteLine(result);

        }
    }
}
