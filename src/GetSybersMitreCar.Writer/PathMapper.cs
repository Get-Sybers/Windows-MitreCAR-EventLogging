using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace GetSybersMitreCar.Writer
{
    /// <summary>Turns the kernel's NT object paths (\Device\HarddiskVolume3\...) into drive paths (C:\...).</summary>
    public static class PathMapper
    {
        private static readonly object Gate = new object();
        private static Dictionary<string, string> _volumes;     // "\Device\HarddiskVolume3" -> "C:"
        private static DateTime _loaded;

        public static string ToDosPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            if (path.StartsWith(@"\??\", StringComparison.Ordinal)) path = path.Substring(4);
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) path = path.Substring(4);
            if (path.Length >= 2 && path[1] == ':') return path;
            if (path.StartsWith(@"\SystemRoot", StringComparison.OrdinalIgnoreCase))
                return Environment.GetEnvironmentVariable("SystemRoot") + path.Substring(@"\SystemRoot".Length);
            if (path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            {
                var map = Volumes();
                foreach (var kv in map)
                    if (path.StartsWith(kv.Key, StringComparison.OrdinalIgnoreCase) &&
                        (path.Length == kv.Key.Length || path[kv.Key.Length] == '\\'))
                        return kv.Value + path.Substring(kv.Key.Length);
                return path;                                   // an unmapped device: left as observed
            }
            if (path.StartsWith(@"\Windows\", StringComparison.OrdinalIgnoreCase) || path.StartsWith(@"\Program Files", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(@"\Users\", StringComparison.OrdinalIgnoreCase) || path.StartsWith(@"\ProgramData\", StringComparison.OrdinalIgnoreCase))
                return Environment.GetEnvironmentVariable("SystemDrive") + path;   // the kernel's system-drive-relative form
            return path;
        }

        private static Dictionary<string, string> Volumes()
        {
            lock (Gate)
            {
                if (_volumes != null && (DateTime.UtcNow - _loaded).TotalMinutes < 5) return _volumes;
                var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                var sb = new StringBuilder(1024);
                for (char c = 'A'; c <= 'Z'; c++)
                {
                    string drive = c + ":";
                    sb.Length = 0;
                    if (QueryDosDevice(drive, sb, sb.Capacity) > 0) map[sb.ToString()] = drive;
                }
                _volumes = map;
                _loaded = DateTime.UtcNow;
                return map;
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath, int max);
    }
}
