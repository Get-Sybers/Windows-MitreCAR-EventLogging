using System;
using System.Globalization;

namespace GetSybersMitreCar.Writer
{
    /// <summary>The value formats model/templates.yaml declares, applied to observed values.</summary>
    public static class Formats
    {
        public static string Int(long v) { return v.ToString(CultureInfo.InvariantCulture); }
        /// <summary>0x-prefixed upper-case hex, as the CAR examples show addresses.</summary>
        public static string Hex(ulong v) { return "0x" + v.ToString("X", CultureInfo.InvariantCulture); }
        /// <summary>ISO 8601 UTC with milliseconds.</summary>
        public static string Utc(DateTime t) { return t.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture); }
    }
}
