using System;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace GetSybersMitreCar.Writer
{
    /// <summary>What an image file shows about itself: hashes, the embedded Authenticode signer, and whether that signature verifies.</summary>
    public sealed class FileFacts
    {
        public string Md5;
        public string Sha1;
        public string Sha256;
        public string Signer;
        /// <summary>"true" / "false", or null when the file carries no embedded signature (CAR: empty if not signed).</summary>
        public string SignatureValid;
    }

    public static class FileInspector
    {
        /// <summary>Images larger than this are not hashed (the sensor must keep up with the event stream).</summary>
        public const long MaxHashBytes = 64L * 1024 * 1024;

        private static readonly ConcurrentDictionary<string, FileFacts> Cache = new ConcurrentDictionary<string, FileFacts>(StringComparer.OrdinalIgnoreCase);

        public static FileFacts Inspect(string path)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists) return new FileFacts();
                string key = path + "|" + info.Length + "|" + info.LastWriteTimeUtc.Ticks;
                FileFacts cached;
                if (Cache.TryGetValue(key, out cached)) return cached;
                var facts = new FileFacts();
                if (info.Length <= MaxHashBytes) Hash(path, facts);
                facts.Signer = Signer(path);
                facts.SignatureValid = Authenticode.Verify(path);
                if (Cache.Count > 4096) Cache.Clear();
                Cache[key] = facts;
                return facts;
            }
            catch (Exception)
            {
                return new FileFacts();
            }
        }

        /// <summary>The file's creation time as it is now (ISO 8601 UTC), or null.</summary>
        public static string CreationTime(string path)
        {
            try { return File.Exists(path) ? Formats.Utc(File.GetCreationTimeUtc(path)) : null; }
            catch (Exception) { return null; }
        }

        /// <summary>The file's owner account and SID as they are now; both null when unreadable.</summary>
        public static void Owner(string path, out string owner, out string ownerSid)
        {
            owner = null; ownerSid = null;
            try
            {
                var sid = new FileInfo(path).GetAccessControl(System.Security.AccessControl.AccessControlSections.Owner)
                    .GetOwner(typeof(System.Security.Principal.SecurityIdentifier)) as System.Security.Principal.SecurityIdentifier;
                if (sid == null) return;
                ownerSid = sid.Value;
                try { owner = sid.Translate(typeof(System.Security.Principal.NTAccount)).Value; } catch (Exception) { }
            }
            catch (Exception) { }
        }

        private static void Hash(string path, FileFacts facts)
        {
            using (var md5 = MD5.Create())
            using (var sha1 = SHA1.Create())
            using (var sha256 = SHA256.Create())
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 20))
            {
                var buffer = new byte[1 << 20];
                int read;
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    md5.TransformBlock(buffer, 0, read, null, 0);
                    sha1.TransformBlock(buffer, 0, read, null, 0);
                    sha256.TransformBlock(buffer, 0, read, null, 0);
                }
                var empty = new byte[0];
                md5.TransformFinalBlock(empty, 0, 0);
                sha1.TransformFinalBlock(empty, 0, 0);
                sha256.TransformFinalBlock(empty, 0, 0);
                facts.Md5 = Hex(md5.Hash);
                facts.Sha1 = Hex(sha1.Hash);
                facts.Sha256 = Hex(sha256.Hash);
            }
        }

        /// <summary>CAR hashes are lower-case hex without a prefix.</summary>
        private static string Hex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        /// <summary>The subject name of the embedded Authenticode certificate; null when the file has none (catalog-signed Windows binaries included).</summary>
        private static string Signer(string path)
        {
            try
            {
                using (var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path)))
                {
                    string name = cert.GetNameInfo(X509NameType.SimpleName, false);
                    return string.IsNullOrEmpty(name) ? null : name;
                }
            }
            catch (Exception) { return null; }
        }
    }

    /// <summary>WinVerifyTrust on an embedded Authenticode signature (no network revocation lookups).</summary>
    internal static class Authenticode
    {
        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
        private const uint TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003;
        private const uint TRUST_E_PROVIDER_UNKNOWN = 0x800B0001;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;             // WTD_UI_NONE = 2
            public uint fdwRevocationChecks;    // WTD_REVOKE_NONE = 0
            public uint dwUnionChoice;          // WTD_CHOICE_FILE = 1
            public IntPtr pFile;
            public uint dwStateAction;          // WTD_STATEACTION_VERIFY = 1, _CLOSE = 2
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;            // WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid actionId, IntPtr data);

        /// <summary>"true" when the embedded signature verifies, "false" when it is present but does not, null when there is none.</summary>
        public static string Verify(string path)
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
                pcwszFilePath = path,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero,
            };
            IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            IntPtr pData = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_DATA)));
            try
            {
                Marshal.StructureToPtr(fileInfo, pFile, false);
                var data = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                    dwUIChoice = 2,
                    fdwRevocationChecks = 0,
                    dwUnionChoice = 1,
                    pFile = pFile,
                    dwStateAction = 1,
                    dwProvFlags = 0x1000,
                };
                Marshal.StructureToPtr(data, pData, false);
                uint status = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

                data = (WINTRUST_DATA)Marshal.PtrToStructure(pData, typeof(WINTRUST_DATA));
                data.dwStateAction = 2;
                Marshal.StructureToPtr(data, pData, false);
                WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

                if (status == 0) return "true";
                if (status == TRUST_E_NOSIGNATURE || status == TRUST_E_SUBJECT_FORM_UNKNOWN || status == TRUST_E_PROVIDER_UNKNOWN) return null;
                return "false";
            }
            catch (Exception) { return null; }
            finally
            {
                Marshal.DestroyStructure(pFile, typeof(WINTRUST_FILE_INFO));
                Marshal.FreeHGlobal(pFile);
                Marshal.FreeHGlobal(pData);
            }
        }
    }
}
