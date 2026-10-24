using System;
using System.Globalization;
using System.Text;
using Microsoft.Win32;

namespace GetSybersMitreCar.Writer
{
    /// <summary>Registry paths as CAR shows them, and live reads of a value's data and type.</summary>
    public static class RegistryHelper
    {
        /// <summary>\REGISTRY\MACHINE\SOFTWARE\X -> key "HKLM\SOFTWARE\X", hive "HKEY_LOCAL_MACHINE"; \REGISTRY\USER\S-1-5-21-...\Y -> "HKU\S-1-5-21-...\Y", "HKEY_USERS".</summary>
        public static void Split(string ntKey, out string key, out string hive)
        {
            key = ntKey; hive = null;
            if (string.IsNullOrEmpty(ntKey)) return;
            if (ntKey.StartsWith(@"\REGISTRY\MACHINE", StringComparison.OrdinalIgnoreCase))
            {
                hive = "HKEY_LOCAL_MACHINE";
                key = "HKLM" + ntKey.Substring(@"\REGISTRY\MACHINE".Length);
            }
            else if (ntKey.StartsWith(@"\REGISTRY\USER", StringComparison.OrdinalIgnoreCase))
            {
                hive = "HKEY_USERS";
                key = "HKU" + ntKey.Substring(@"\REGISTRY\USER".Length);
            }
        }

        /// <summary>Reads the value as it is now; data in the model's format, type as REG_*. Both null when unreadable.</summary>
        public static void ReadValue(string ntKey, string valueName, out string data, out string type)
        {
            data = null; type = null;
            try
            {
                RegistryKey root; string sub;
                if (ntKey.StartsWith(@"\REGISTRY\MACHINE\", StringComparison.OrdinalIgnoreCase)) { root = Registry.LocalMachine; sub = ntKey.Substring(@"\REGISTRY\MACHINE\".Length); }
                else if (ntKey.StartsWith(@"\REGISTRY\USER\", StringComparison.OrdinalIgnoreCase)) { root = Registry.Users; sub = ntKey.Substring(@"\REGISTRY\USER\".Length); }
                else return;
                using (var k = root.OpenSubKey(sub, RegistryKeyPermissionCheck.ReadSubTree, System.Security.AccessControl.RegistryRights.QueryValues))
                {
                    if (k == null) return;
                    object v = k.GetValue(valueName ?? "", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    if (v == null) return;
                    var kind = k.GetValueKind(valueName ?? "");
                    type = TypeName(kind);
                    data = Format(v, kind);
                }
            }
            catch (Exception) { data = null; type = null; }
        }

        private static string TypeName(RegistryValueKind kind)
        {
            switch (kind)
            {
                case RegistryValueKind.String: return "REG_SZ";
                case RegistryValueKind.ExpandString: return "REG_EXPAND_SZ";
                case RegistryValueKind.Binary: return "REG_BINARY";
                case RegistryValueKind.DWord: return "REG_DWORD";
                case RegistryValueKind.MultiString: return "REG_MULTI_SZ";
                case RegistryValueKind.QWord: return "REG_QWORD";
                case RegistryValueKind.None: return "REG_NONE";
                default: return "REG_" + kind.ToString().ToUpperInvariant();
            }
        }

        private static string Format(object v, RegistryValueKind kind)
        {
            switch (kind)
            {
                case RegistryValueKind.DWord: return Convert.ToInt64(v, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture);
                case RegistryValueKind.QWord: return Convert.ToInt64(v, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture);
                case RegistryValueKind.MultiString: return string.Join("\n", (string[])v);
                case RegistryValueKind.Binary:
                case RegistryValueKind.None:
                    var bytes = v as byte[];
                    if (bytes == null) return v.ToString();
                    var sb = new StringBuilder(Math.Min(bytes.Length, 4096) * 2);
                    for (int i = 0; i < bytes.Length && i < 4096; i++) sb.Append(bytes[i].ToString("x2"));
                    return sb.ToString();
                default: return v.ToString();
            }
        }
    }
}
