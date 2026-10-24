using System;
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
    }

    /// <summary>Live lookups on a running process through the Win32 process and token APIs.</summary>
    public static class ProcessInspector
    {
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint TOKEN_QUERY = 0x0008;
        private const int TokenUser = 1;
        private const int TokenIntegrityLevel = 25;

        public static LiveProcess Inspect(int pid)
        {
            var result = new LiveProcess();
            IntPtr process = Native.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
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
                            try { result.User = user.Translate(typeof(NTAccount)).Value; }
                            catch (Exception) { /* no name for this SID: leave empty */ }
                        }
                        var label = TokenSid(token, TokenIntegrityLevel);
                        if (label != null) result.IntegrityLevel = IntegrityName(label);
                    }
                    finally { Native.CloseHandle(token); }
                }
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

    internal static class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder exeName, ref int size);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int infoLength, out int returnLength);

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
