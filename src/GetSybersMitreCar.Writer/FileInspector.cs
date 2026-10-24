using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace GetSybersMitreCar.Writer
{
    /// <summary>What an image file shows about itself: hashes, the embedded Authenticode signer and whether it verifies, the company in its version resource.</summary>
    public sealed class FileFacts
    {
        public string Md5;
        public string Sha1;
        public string Sha256;
        public string Signer;
        /// <summary>"true" / "false", or null when the file carries no embedded signature (CAR: empty if not signed).</summary>
        public string SignatureValid;
        /// <summary>CompanyName from the file's version resource.</summary>
        public string Company;
    }

    /// <summary>What a file shows about itself on disk at one instant: timestamps, owner and group, permissions, link target, registered MIME type.</summary>
    public sealed class FileState
    {
        public DateTime? Created;
        public DateTime? LastWrite;
        public DateTime? LastAccess;
        public FileAttributes Attributes;
        public string Owner;
        public string OwnerSid;
        public string Group;
        public string GroupSid;
        /// <summary>The DACL in SDDL form: the file's permission set as Windows states it.</summary>
        public string Mode;
        public string LinkTarget;
        public string MimeType;

        public string CreationTime { get { return Created.HasValue ? Formats.Utc(Created.Value) : null; } }
        public bool Exists { get { return Created.HasValue; } }

        public bool TimesDiffer(FileState other)
        {
            return other != null && Exists && other.Exists && (Created != other.Created || LastWrite != other.LastWrite || LastAccess != other.LastAccess);
        }
    }

    public static class FileInspector
    {
        /// <summary>Images larger than this are not hashed (the sensor must keep up with the event stream).</summary>
        public const long MaxHashBytes = 64L * 1024 * 1024;

        private static readonly ConcurrentDictionary<string, FileFacts> Cache = new ConcurrentDictionary<string, FileFacts>(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, KeyValuePair<DateTime, string>> MimeCache = new ConcurrentDictionary<string, KeyValuePair<DateTime, string>>(StringComparer.OrdinalIgnoreCase);

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
                facts.Company = Company(path);
                if (Cache.Count > 4096) Cache.Clear();
                Cache[key] = facts;
                return facts;
            }
            catch (Exception)
            {
                return new FileFacts();
            }
        }

        /// <summary>The file (or directory) as it is on disk right now; an empty state when it is not there or not readable.</summary>
        public static FileState Read(string path)
        {
            var state = new FileState();
            if (string.IsNullOrEmpty(path)) return state;
            try
            {
                bool isDirectory = Directory.Exists(path);
                if (!isDirectory && !File.Exists(path)) return state;
                FileSystemInfo info = isDirectory ? (FileSystemInfo)new DirectoryInfo(path) : new FileInfo(path);
                state.Created = info.CreationTimeUtc;
                state.LastWrite = info.LastWriteTimeUtc;
                state.LastAccess = info.LastAccessTimeUtc;
                state.Attributes = info.Attributes;
                try
                {
                    const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access;
                    FileSystemSecurity security = isDirectory ? (FileSystemSecurity)Directory.GetAccessControl(path, sections) : File.GetAccessControl(path, sections);
                    var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
                    if (owner != null) { state.OwnerSid = owner.Value; state.Owner = SidNames.Resolve(owner.Value); }
                    var group = security.GetGroup(typeof(SecurityIdentifier)) as SecurityIdentifier;
                    if (group != null) { state.GroupSid = group.Value; state.Group = SidNames.Resolve(group.Value); }
                    string sddl = security.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
                    state.Mode = string.IsNullOrEmpty(sddl) ? null : sddl;
                }
                catch (Exception) { /* security descriptor not readable: those properties stay empty */ }
                if ((state.Attributes & FileAttributes.ReparsePoint) != 0) state.LinkTarget = ReparsePoints.Target(path);
                if (!isDirectory) state.MimeType = MimeType(Path.GetExtension(path));
            }
            catch (Exception) { }
            return state;
        }

        /// <summary>The "Content Type" the host registers for the extension under HKLM\Software\Classes (machine-wide), or null.</summary>
        public static string MimeType(string extension)
        {
            if (string.IsNullOrEmpty(extension) || extension[0] != '.') return null;
            KeyValuePair<DateTime, string> cached;
            if (MimeCache.TryGetValue(extension, out cached) && (DateTime.UtcNow - cached.Key).TotalMinutes < 10) return cached.Value;
            string type = null;
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"Software\Classes\" + extension))
                {
                    if (k != null) type = k.GetValue("Content Type") as string;
                }
            }
            catch (Exception) { }
            if (string.IsNullOrEmpty(type)) type = null;
            if (MimeCache.Count > 1024) MimeCache.Clear();
            MimeCache[extension] = new KeyValuePair<DateTime, string>(DateTime.UtcNow, type);
            return type;
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

        /// <summary>CompanyName from the version resource; null when the file has none.</summary>
        private static string Company(string path)
        {
            try
            {
                string company = FileVersionInfo.GetVersionInfo(path).CompanyName;
                return string.IsNullOrWhiteSpace(company) ? null : company.Trim();
            }
            catch (Exception) { return null; }
        }
    }

    /// <summary>The target recorded in a symbolic link or junction (FSCTL_GET_REPARSE_POINT); other reparse tags are not links.</summary>
    internal static class ReparsePoints
    {
        private const uint FILE_READ_ATTRIBUTES = 0x0080;
        private const uint FILE_SHARE_ALL = 0x7;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FSCTL_GET_REPARSE_POINT = 0x000900A8;
        private const uint IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;
        private const uint IO_REPARSE_TAG_SYMLINK = 0xA000000C;
        private const int MAXIMUM_REPARSE_DATA_BUFFER_SIZE = 16 * 1024;

        public static string Target(string path)
        {
            IntPtr handle = CreateFile(path, FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return null;
            IntPtr buffer = Marshal.AllocHGlobal(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
            try
            {
                uint returned;
                if (!DeviceIoControl(handle, FSCTL_GET_REPARSE_POINT, IntPtr.Zero, 0, buffer, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, out returned, IntPtr.Zero)) return null;
                uint tag = (uint)Marshal.ReadInt32(buffer, 0);
                int dataLength = Marshal.ReadInt16(buffer, 4);
                int header;                                    // where SubstituteNameOffset starts
                int pathBuffer;                                // where PathBuffer starts
                if (tag == IO_REPARSE_TAG_SYMLINK) { header = 8; pathBuffer = 20; }
                else if (tag == IO_REPARSE_TAG_MOUNT_POINT) { header = 8; pathBuffer = 16; }
                else return null;
                int substituteOffset = Marshal.ReadInt16(buffer, header), substituteLength = Marshal.ReadInt16(buffer, header + 2);
                int printOffset = Marshal.ReadInt16(buffer, header + 4), printLength = Marshal.ReadInt16(buffer, header + 6);
                string target = ReadName(buffer, pathBuffer + printOffset, printLength, dataLength + 8);
                if (string.IsNullOrEmpty(target)) target = ReadName(buffer, pathBuffer + substituteOffset, substituteLength, dataLength + 8);
                if (string.IsNullOrEmpty(target)) return null;
                return PathMapper.ToDosPath(target);
            }
            catch (Exception) { return null; }
            finally
            {
                Marshal.FreeHGlobal(buffer);
                Native.CloseHandle(handle);
            }
        }

        private static string ReadName(IntPtr buffer, int offset, int length, int limit)
        {
            if (length <= 0 || offset < 0 || offset + length > limit || offset + length > MAXIMUM_REPARSE_DATA_BUFFER_SIZE) return null;
            var bytes = new byte[length];
            Marshal.Copy(new IntPtr(buffer.ToInt64() + offset), bytes, 0, length);
            return Encoding.Unicode.GetString(bytes);
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateFileW")]
        private static extern IntPtr CreateFile(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(IntPtr device, uint ioControlCode, IntPtr inBuffer, uint inBufferSize, IntPtr outBuffer, uint outBufferSize, out uint bytesReturned, IntPtr overlapped);
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
