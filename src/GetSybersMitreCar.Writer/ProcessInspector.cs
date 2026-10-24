using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace GetSybersMitreCar.Writer
{
    /// <summary>What a live process shows about itself at the instant it is inspected.</summary>
    public sealed class LiveProcess
    {
        public string ImagePath;
        public string Sid;
        public string User;
        public string IntegrityLevel;
        /// <summary>The command line in the process's own parameter block (PEB).</summary>
        public string CommandLine;
        /// <summary>The current directory in the process's own parameter block (PEB).</summary>
        public string CurrentDirectory;
        /// <summary>The environment block in the process's own memory, one NAME=value per line.</summary>
        public string Environment;
    }

    /// <summary>Live lookups on a running process through the Win32 process and token APIs and a read of its PEB.</summary>
    public static class ProcessInspector
    {
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint TOKEN_QUERY = 0x0008;
        private const int TokenUser = 1;
        private const int TokenIntegrityLevel = 25;

        public static LiveProcess Inspect(int pid, bool withEnvironment)
        {
            var result = new LiveProcess();
            // Full query + memory read when allowed (protected processes refuse it); the limited handle still gives path and token.
            IntPtr process = Native.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            bool canRead = process != IntPtr.Zero;
            if (!canRead) process = Native.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (process == IntPtr.Zero) return result;
            try
            {
                result.ImagePath = QueryImagePath(process);
                IntPtr token;
                if (Native.OpenProcessToken(process, TOKEN_QUERY, out token))
                {
                    try
                    {
                        var user = TokenSid(token, TokenUser);
                        if (user != null)
                        {
                            result.Sid = user.Value;
                            result.User = SidNames.Resolve(result.Sid);
                        }
                        var label = TokenSid(token, TokenIntegrityLevel);
                        if (label != null) result.IntegrityLevel = IntegrityName(label);
                    }
                    finally { Native.CloseHandle(token); }
                }
                if (canRead) Peb.Read(process, result, withEnvironment);
            }
            finally { Native.CloseHandle(process); }
            return result;
        }

        /// <summary>The parent pid as the kernel records it now (0 when the process cannot be opened).</summary>
        public static int ParentPid(int pid)
        {
            IntPtr process = Native.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (process == IntPtr.Zero) return 0;
            try
            {
                var pbi = new Native.PROCESS_BASIC_INFORMATION();
                int len;
                if (Native.NtQueryInformationProcess(process, 0, ref pbi, Marshal.SizeOf(typeof(Native.PROCESS_BASIC_INFORMATION)), out len) != 0) return 0;
                return pbi.InheritedFromUniqueProcessId.ToInt32();
            }
            catch (Exception) { return 0; }
            finally { Native.CloseHandle(process); }
        }

        public static string ImagePath(int pid)
        {
            IntPtr process = Native.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (process == IntPtr.Zero) return null;
            try { return QueryImagePath(process); }
            finally { Native.CloseHandle(process); }
        }

        private static string QueryImagePath(IntPtr process)
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            if (!Native.QueryFullProcessImageName(process, 0, sb, ref size)) return null;
            return size > 0 ? sb.ToString(0, size) : null;
        }

        /// <summary>The SID inside a TOKEN_USER / TOKEN_MANDATORY_LABEL (both start with a SID_AND_ATTRIBUTES).</summary>
        private static SecurityIdentifier TokenSid(IntPtr token, int infoClass)
        {
            int length;
            Native.GetTokenInformation(token, infoClass, IntPtr.Zero, 0, out length);
            if (length <= 0) return null;
            IntPtr buffer = Marshal.AllocHGlobal(length);
            try
            {
                if (!Native.GetTokenInformation(token, infoClass, buffer, length, out length)) return null;
                IntPtr sid = Marshal.ReadIntPtr(buffer);   // SID_AND_ATTRIBUTES.Sid
                return new SecurityIdentifier(sid);
            }
            catch (Exception) { return null; }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        /// <summary>CAR integrity_level MUST be one of low, medium, high, system; anything else is left empty.</summary>
        private static string IntegrityName(SecurityIdentifier label)
        {
            string s = label.Value;                        // S-1-16-<rid>
            int dash = s.LastIndexOf('-');
            int rid;
            if (dash < 0 || !int.TryParse(s.Substring(dash + 1), out rid)) return null;
            if (rid == 0x1000) return "low";
            if (rid == 0x2000 || rid == 0x2100) return "medium";
            if (rid == 0x3000) return "high";
            if (rid == 0x4000) return "system";
            return null;
        }
    }

    /// <summary>SID -> "DOMAIN\user" through the local security authority (LookupAccountSid), remembered per SID.</summary>
    public static class SidNames
    {
        private static readonly ConcurrentDictionary<string, string> Cache = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);

        /// <summary>The account name for the SID, or null when the authority knows no name for it.</summary>
        public static string Resolve(string sid)
        {
            if (string.IsNullOrEmpty(sid)) return null;
            string name;
            if (Cache.TryGetValue(sid, out name)) return name;
            try { name = new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value; }
            catch (Exception) { name = null; }
            if (Cache.Count > 4096) Cache.Clear();
            Cache[sid] = name;
            return name;
        }
    }

    /// <summary>
    /// Reads a process's RTL_USER_PROCESS_PARAMETERS through its PEB: the current directory, the command line and the
    /// environment block as the process itself holds them. The sensor is an x64 process reading the native PEB; for a
    /// WOW64 process the native parameter block holds the values the process started with.
    /// </summary>
    internal static class Peb
    {
        private const int PebProcessParameters = 0x20;          // PEB.ProcessParameters (x64)
        private const int ParamsCurrentDirectory = 0x38;        // RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath (UNICODE_STRING)
        private const int ParamsCommandLine = 0x70;             // .CommandLine (UNICODE_STRING)
        private const int ParamsEnvironment = 0x80;             // .Environment (PVOID)
        private const int ParamsEnvironmentSize = 0x3F0;        // .EnvironmentSize (SIZE_T)
        private const int ParamsBytes = 0x3F8;
        private const int MaxStringBytes = 64 * 1024;           // a command line is at most 32767 UTF-16 characters
        private const int MaxEnvironmentBytes = 256 * 1024;

        public static void Read(IntPtr process, LiveProcess into, bool withEnvironment)
        {
            if (IntPtr.Size != 8) return;
            try
            {
                var pbi = new Native.PROCESS_BASIC_INFORMATION();
                int len;
                if (Native.NtQueryInformationProcess(process, 0, ref pbi, Marshal.SizeOf(typeof(Native.PROCESS_BASIC_INFORMATION)), out len) != 0) return;
                if (pbi.PebBaseAddress == IntPtr.Zero) return;
                byte[] pointer = ReadBytes(process, pbi.PebBaseAddress.ToInt64() + PebProcessParameters, 8);
                if (pointer == null) return;
                long parameters = BitConverter.ToInt64(pointer, 0);
                if (parameters == 0) return;
                byte[] block = ReadBytes(process, parameters, ParamsBytes);
                if (block == null) return;
                into.CurrentDirectory = ReadUnicodeString(process, block, ParamsCurrentDirectory);
                into.CommandLine = ReadUnicodeString(process, block, ParamsCommandLine);
                if (!withEnvironment) return;
                long environment = BitConverter.ToInt64(block, ParamsEnvironment);
                long size = BitConverter.ToInt64(block, ParamsEnvironmentSize);
                if (environment == 0 || size <= 0) return;
                if (size > MaxEnvironmentBytes) size = MaxEnvironmentBytes;
                byte[] bytes = ReadBytes(process, environment, (int)size);
                if (bytes != null) into.Environment = FormatEnvironment(bytes);
            }
            catch (Exception) { /* a process that is gone or protected: nothing observed */ }
        }

        private static string ReadUnicodeString(IntPtr process, byte[] block, int offset)
        {
            int length = BitConverter.ToUInt16(block, offset);          // UNICODE_STRING.Length, in bytes
            long buffer = BitConverter.ToInt64(block, offset + 8);      // UNICODE_STRING.Buffer
            if (length == 0 || buffer == 0 || length > MaxStringBytes) return null;
            byte[] bytes = ReadBytes(process, buffer, length);
            if (bytes == null) return null;
            string s = Encoding.Unicode.GetString(bytes).TrimEnd('\0');
            return s.Length == 0 ? null : s;
        }

        private static byte[] ReadBytes(IntPtr process, long address, int count)
        {
            var bytes = new byte[count];
            IntPtr read;
            if (!Native.ReadProcessMemory(process, new IntPtr(address), bytes, new IntPtr(count), out read)) return null;
            if (read.ToInt64() != count) return null;
            return bytes;
        }

        /// <summary>"A=1\0B=2\0\0" -> "A=1\nB=2".</summary>
        private static string FormatEnvironment(byte[] bytes)
        {
            string s = Encoding.Unicode.GetString(bytes);
            int end = s.IndexOf("\0\0", StringComparison.Ordinal);
            if (end >= 0) s = s.Substring(0, end);
            s = s.Replace('\0', '\n').Trim('\n');
            return s.Length == 0 ? null : s;
        }
    }

    /// <summary>Token privileges the sensor needs enabled (SeDebugPrivilege: open other users' processes to read their PEB).</summary>
    public static class Privileges
    {
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const int ERROR_NOT_ALL_ASSIGNED = 1300;

        /// <summary>Enables the named privilege on the sensor's own token; false when the token does not hold it.</summary>
        public static bool Enable(string name)
        {
            IntPtr token;
            if (!Native.OpenProcessToken(Native.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token)) return false;
            try
            {
                Native.LUID luid;
                if (!Native.LookupPrivilegeValue(null, name, out luid)) return false;
                var privileges = new Native.TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
                if (!Native.AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero)) return false;
                return Marshal.GetLastWin32Error() != ERROR_NOT_ALL_ASSIGNED;
            }
            finally { Native.CloseHandle(token); }
        }
    }

    internal static class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder exeName, ref int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(IntPtr process, IntPtr baseAddress, [Out] byte[] buffer, IntPtr size, out IntPtr bytesRead);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int infoLength, out int returnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "LookupPrivilegeValueW")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string systemName, string name, out LUID luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        /// <summary>TOKEN_PRIVILEGES with exactly one LUID_AND_ATTRIBUTES.</summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationProcess(IntPtr process, int infoClass, ref PROCESS_BASIC_INFORMATION info, int infoLength, out int returnLength);
    }
}
