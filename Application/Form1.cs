using System;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Web;
using System.Windows.Forms;
using Newtonsoft.Json;
using Process.NET;
using Process.NET.Patterns;

namespace WindowsForms
{
    public partial class Form1 : Form
    {
        private static PatternScanner PatternScanner;
        private static ProcessSharp ProcessSharp;

        private static long LuaTaintedPtrOffset
        {
            get
            {
                var Lua_TaintedPtrOffset = GetAddressFromPattern("4C 8B 0D ?? ?? ?? ?? 45 33 C0 48 8B CE", 3, 4);
                return Lua_TaintedPtrOffset.ToInt64() - ProcessSharp.Native.MainModule.BaseAddress.ToInt64();             
            }
        }

        private static IntPtr GetAddressFromPattern(string pattern, int offset, int size)
        {
            var scanResult = PatternScanner.Find(new DwordPattern(pattern));
            return IntPtr.Add(scanResult.ReadAddress, ProcessSharp.Memory.Read<int>(scanResult.ReadAddress + offset)) + offset + size;
        }

        public Form1()
        {
            InitializeComponent();
        }

        private void InjectCode(int id, IntPtr wHandle)
        {
            byte[] asm =
            {
                0x90,                                                       //nop
                0x55,                                                       //push rbp
                0x48, 0x8B, 0xEC,                                           //mov rbp, rsp
                0x48, 0xB9, 0xEF, 0xBE, 0xAD, 0xDE, 0xDE, 0xAD, 0xBE, 0xEF, //mov rcx, luaTaintedPtrOffset 
                0xC7, 0x01, 0x00, 0x00, 0x00, 0x00,                         //mov [rcx],00000000
                0xC7, 0x41, 0x04, 0x00, 0x00, 0x00, 0x00,                   //mov [rcx+04],00000000
                0xEB, 0xF1,                                                 //jmp (to mov)
                0x48, 0x8B, 0xE5,                                           //mov rsp, rbp
                0x5D,                                                       //pop rbp
                0xC3                                                        //ret
            };

            var hAlloc = (long)VirtualAllocEx(wHandle, 0, (uint)asm.Length, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);

            WriteProcessMemory(wHandle, hAlloc, asm, asm.Length, out int BytesWritten);
            WriteProcessMemory(wHandle, hAlloc + 0x07, BitConverter.GetBytes((long)System.Diagnostics.Process.GetProcessById(id).MainModule.BaseAddress + LuaTaintedPtrOffset), 0x08, out BytesWritten);

            BypasAntiCheat01(true, wHandle);

            var hThread = CreateRemoteThread(wHandle, IntPtr.Zero, 0, (IntPtr)hAlloc, IntPtr.Zero, 0, out uint iThreadId);

            Thread.Sleep(100);

            BypasAntiCheat01(false, wHandle);
        }

        private void BypasAntiCheat01(bool status, IntPtr wHandle)
        {
            byte[] Patch = {0xFF, 0xE0, 0xCC, 0xCC, 0xCC}; //JMP RAX
            byte[] Patch2 = {0x48, 0xFF, 0xC0, 0xFF, 0xE0}; //INC RAX, JMP RAX

            var CreateRemoteThreadPatchOffset = (long) GetProcAddress(GetModuleHandle("kernel32.dll"), "BaseDumpAppcompatCacheWorker") + 0x1E0;

            if (status)
                Patch = Patch2;

            WriteProcessMemory(wHandle, CreateRemoteThreadPatchOffset, Patch, Patch.Length, out int BytesWritten);
        }

        private readonly byte[] RET = { 0xC3 };

        private void PatchAddress(IntPtr handle, string moduleName, string moduleSection, byte[] patch, int offset = 0)
        {
            var patchAddress = (long)GetProcAddress(GetModuleHandle(moduleName), moduleSection) + offset;

            var bytesRead = 0;
            var buffer = new byte[patch.Length];

            ReadProcessMemory(handle, patchAddress, buffer, patch.Length, ref bytesRead);

            WriteProcessMemory(handle, patchAddress, patch, patch.Length, out bytesRead);

            ReadProcessMemory(handle, patchAddress, buffer, patch.Length, ref bytesRead);
        }

        private static string OperatingSystem
        {
            get
            {
                var result = string.Empty;

                var moc = new ManagementObjectSearcher(@"SELECT * FROM Win32_OperatingSystem ");
                foreach (var managementBaseObject in moc.Get())
                {
                    var o = (ManagementObject)managementBaseObject;
                    var x64 = Environment.Is64BitOperatingSystem ? "(x64)" : "(x86)";
                    result = $@"{o["Caption"]} {x64} Version {o["Version"]} SP {o["ServicePackMajorVersion"]}.{o["ServicePackMinorVersion"]}";
                    break;
                }

                return result.Replace("Microsoft", "").Trim();
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            btnInject.Enabled = false;

            var handle = OpenProcess(0x1F0FFF, false, System.Diagnostics.Process.GetCurrentProcess().Id);
            PatchAddress(handle, "ntdll.dll", "DbgBreakPoint", RET);
            PatchAddress(handle, "ntdll.dll", "DbgUserBreakPoint", RET);
                        
            var application = HttpUtility.UrlEncode("Application");
            var dbName = "Lua Unlock";
            var windowsVersion = HttpUtility.UrlEncode(OperatingSystem);
            var computerName = HttpUtility.UrlEncode(Environment.MachineName);
            var applicationVersion = HttpUtility.UrlEncode(Application.ProductVersion);
            var userName = HttpUtility.UrlEncode(Environment.UserName);
            var message = HttpUtility.UrlEncode("Started");

            var url = "http://frozen.fyi/insert.php?";
            url += $"application={application}&dbName={dbName}&windowsVersion={windowsVersion}&computerName={computerName}&";
            url += $"applicationVersion={applicationVersion}&userName={userName}&message={message}";

            using (var web = new WebClient())
            {
                var response = web.DownloadString(url);
                if (response == "Inserted")
                {
                    // Good, but we ignore it anyways
                    btnInject.Enabled = true;
                }
                else
                {
                    MessageBox.Show("Auth server down.", Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Application.Exit();
                }
            }
        }

        private void btnInject_Click(object sender, EventArgs e)
        {
            try
            {
                // Ensure windows hosts file is not modified to point to fake address
                var hostPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"system32\drivers\etc\hosts");
                var file = File.ReadAllText(hostPath);

                if (file.ToLower().Contains("frozen")) throw new Exception("Tampering Exception");
                
                var process = System.Diagnostics.Process.GetProcessesByName("Wow").FirstOrDefault();

                if (process == null) throw new Exception("Wow.exe is not running, nothing to unlock");

                ProcessSharp = new ProcessSharp(process, Process.NET.Memory.MemoryType.Remote);
                PatternScanner = new PatternScanner(ProcessSharp[ProcessSharp.Native.MainModule.ModuleName]);

                var wHandle = OpenProcess((int) MemoryProtection.Proc_All_Access, false, ProcessSharp.Native.Id);
                          
                InjectCode(ProcessSharp.Native.Id, wHandle);

                MessageBox.Show("Success", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failure: {ex.Message}", Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                Application.Exit();
            }
        }

        [DllImport("Kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr handle, long address, byte[] bytes, int nsize, ref int op);

        [DllImport("Kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hwind, long Address, byte[] bytes, int nsize, out int output);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr OpenProcess(int Token, bool inheritH, int ProcID);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, long lpAddress,
            uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        private enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        private enum MemoryProtection
        {
            NoAccess = 0x0001,
            ReadOnly = 0x0002,
            ReadWrite = 0x0004,
            WriteCopy = 0x0008,
            Execute = 0x0010,
            ExecuteRead = 0x0020,
            ExecuteReadWrite = 0x0040,
            ExecuteWriteCopy = 0x0080,
            GuardModifierflag = 0x0100,
            NoCacheModifierflag = 0x0200,
            WriteCombineModifierflag = 0x0400,
            Proc_All_Access = 2035711
        }

        private void btnWebsite_Click(object sender, EventArgs e)
        {
            System.Diagnostics.Process.Start("http://winifix.github.io/");
        }
    }
}