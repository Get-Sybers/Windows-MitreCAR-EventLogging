using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace GetSybersMitreCar.Writer
{
    public struct ModuleRange
    {
        public ulong Base;
        public ulong Size;
        public string Path;
        public bool Contains(ulong address) { return address >= Base && address < Base + Size; }
    }

    /// <summary>
    /// Which module occupies which address range in each process: filled from the kernel's Image/Load and Image/Unload
    /// events, and for a process that was already running when the sensor started, from a live module snapshot the first
    /// time a thread of it is asked about. Kernel images (pid 0 / 4) are kept the same way for the System process.
    /// </summary>
    public sealed class ModuleMap
    {
        private sealed class Entry
        {
            public readonly List<ModuleRange> Ranges = new List<ModuleRange>();
            public bool Snapshotted;
            public int SnapshotFailures;
        }

        private readonly ConcurrentDictionary<int, Entry> _byPid = new ConcurrentDictionary<int, Entry>();

        public void Load(int pid, ulong baseAddress, ulong size, string path)
        {
            if (baseAddress == 0 || string.IsNullOrEmpty(path)) return;
            var e = _byPid.GetOrAdd(pid, _ => new Entry());
            lock (e)
            {
                RemoveAt(e, baseAddress);
                e.Ranges.Add(new ModuleRange { Base = baseAddress, Size = size, Path = path });
            }
        }

        public void Unload(int pid, ulong baseAddress)
        {
            Entry e;
            if (_byPid.TryGetValue(pid, out e)) lock (e) RemoveAt(e, baseAddress);
        }

        public void Forget(int pid)
        {
            Entry e;
            _byPid.TryRemove(pid, out e);
        }

        /// <summary>The module whose range covers the address in that process, or null when no loaded module does.</summary>
        public ModuleRange? Find(int pid, ulong address)
        {
            if (address == 0) return null;
            if (pid == 0 || pid == 4)
            {
                var kernel = Search(0, address) ?? Search(4, address);
                return kernel;
            }
            var e = _byPid.GetOrAdd(pid, _ => new Entry());
            var found = Search(e, address);
            if (found == null && !e.Snapshotted && e.SnapshotFailures < 3)
            {
                lock (e)
                {
                    if (!e.Snapshotted && e.SnapshotFailures < 3)
                    {
                        if (Snapshot(pid, e)) e.Snapshotted = true; else e.SnapshotFailures++;
                    }
                }
                found = Search(e, address);
            }
            return found;
        }

        private ModuleRange? Search(int pid, ulong address)
        {
            Entry e;
            return _byPid.TryGetValue(pid, out e) ? Search(e, address) : null;
        }

        private static ModuleRange? Search(Entry e, ulong address)
        {
            lock (e)
            {
                foreach (var r in e.Ranges) if (r.Contains(address)) return r;
            }
            return null;
        }

        private static void RemoveAt(Entry e, ulong baseAddress)
        {
            for (int i = e.Ranges.Count - 1; i >= 0; i--) if (e.Ranges[i].Base == baseAddress) e.Ranges.RemoveAt(i);
        }

        /// <summary>The modules a running process has loaded, as the loader lists them now (Toolhelp).</summary>
        private static bool Snapshot(int pid, Entry e)
        {
            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)pid);
            if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1)) return false;
            try
            {
                var entry = new MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32W)) };
                if (!Module32FirstW(snapshot, ref entry)) return false;
                do
                {
                    ulong baseAddress = (ulong)entry.modBaseAddr.ToInt64();
                    bool known = false;
                    foreach (var r in e.Ranges) if (r.Base == baseAddress) { known = true; break; }
                    if (!known) e.Ranges.Add(new ModuleRange { Base = baseAddress, Size = entry.modBaseSize, Path = entry.szExePath });
                    entry.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32W));
                } while (Module32NextW(snapshot, ref entry));
                return true;
            }
            finally { Native.CloseHandle(snapshot); }
        }

        private const uint TH32CS_SNAPMODULE = 0x00000008;
        private const uint TH32CS_SNAPMODULE32 = 0x00000010;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct MODULEENTRY32W
        {
            public uint dwSize;
            public uint th32ModuleID;
            public uint th32ProcessID;
            public uint GlblcntUsage;
            public uint ProccntUsage;
            public IntPtr modBaseAddr;
            public uint modBaseSize;
            public IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool Module32FirstW(IntPtr snapshot, ref MODULEENTRY32W entry);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool Module32NextW(IntPtr snapshot, ref MODULEENTRY32W entry);
    }

    /// <summary>
    /// The export table of a PE file on disk, RVA -> exported name, so the function a thread starts in can be named
    /// exactly: only an address that is an export's own address gets a name (no "nearest symbol" guessing).
    /// </summary>
    public static class PeExports
    {
        private static readonly ConcurrentDictionary<string, Dictionary<uint, string>> Cache = new ConcurrentDictionary<string, Dictionary<uint, string>>(StringComparer.OrdinalIgnoreCase);

        public static string FunctionAt(string path, ulong rva)
        {
            if (string.IsNullOrEmpty(path) || rva > uint.MaxValue) return null;
            var table = Table(path);
            string name;
            return table != null && table.TryGetValue((uint)rva, out name) ? name : null;
        }

        private static Dictionary<uint, string> Table(string path)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists) return null;
                string key = path + "|" + info.Length + "|" + info.LastWriteTimeUtc.Ticks;
                Dictionary<uint, string> table;
                if (Cache.TryGetValue(key, out table)) return table;
                table = Parse(path) ?? new Dictionary<uint, string>();
                if (Cache.Count > 2048) Cache.Clear();
                Cache[key] = table;
                return table;
            }
            catch (Exception) { return null; }
        }

        private struct Section { public uint VirtualAddress, VirtualSize, RawSize, RawPointer; }

        private static Dictionary<uint, string> Parse(string path)
        {
            using (var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16))
            using (var r = new BinaryReader(f))
            {
                if (f.Length < 0x40 || r.ReadUInt16() != 0x5A4D) return null;                 // "MZ"
                f.Position = 0x3C;
                uint pe = r.ReadUInt32();
                if (pe + 24 > f.Length) return null;
                f.Position = pe;
                if (r.ReadUInt32() != 0x00004550) return null;                                 // "PE\0\0"
                f.Position = pe + 4 + 2;
                int sectionCount = r.ReadUInt16();
                f.Position = pe + 4 + 16;
                int optionalSize = r.ReadUInt16();
                long optional = pe + 24;
                f.Position = optional;
                ushort magic = r.ReadUInt16();
                bool plus = magic == 0x20B;
                if (!plus && magic != 0x10B) return null;
                f.Position = optional + (plus ? 108 : 92);
                if (r.ReadUInt32() < 1) return null;                                           // NumberOfRvaAndSizes
                f.Position = optional + (plus ? 112 : 96);                                    // DataDirectory[EXPORT]
                uint exportRva = r.ReadUInt32(), exportSize = r.ReadUInt32();
                if (exportRva == 0) return null;

                var sections = new List<Section>();
                long sectionTable = optional + optionalSize;
                for (int i = 0; i < sectionCount; i++)
                {
                    f.Position = sectionTable + i * 40 + 8;
                    var s = new Section { VirtualSize = r.ReadUInt32(), VirtualAddress = r.ReadUInt32(), RawSize = r.ReadUInt32(), RawPointer = r.ReadUInt32() };
                    sections.Add(s);
                }
                Func<uint, long> toFile = rva =>
                {
                    foreach (var s in sections)
                        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.RawSize))
                            return s.RawPointer + (rva - s.VirtualAddress);
                    return -1;
                };

                long export = toFile(exportRva);
                if (export < 0 || export + 40 > f.Length) return null;
                f.Position = export + 16;
                uint ordinalBase = r.ReadUInt32(), functionCount = r.ReadUInt32(), nameCount = r.ReadUInt32();
                uint functionsRva = r.ReadUInt32(), namesRva = r.ReadUInt32(), ordinalsRva = r.ReadUInt32();
                if (functionCount == 0 || functionCount > 65536 || nameCount > 65536) return null;
                long functions = toFile(functionsRva);
                if (functions < 0) return null;

                var addresses = new uint[functionCount];
                f.Position = functions;
                for (int i = 0; i < functionCount; i++) addresses[i] = r.ReadUInt32();

                var names = new string[functionCount];
                long nameTable = toFile(namesRva), ordinalTable = toFile(ordinalsRva);
                if (nameCount > 0 && nameTable >= 0 && ordinalTable >= 0)
                {
                    var nameRvas = new uint[nameCount];
                    f.Position = nameTable;
                    for (int i = 0; i < nameCount; i++) nameRvas[i] = r.ReadUInt32();
                    var ordinals = new ushort[nameCount];
                    f.Position = ordinalTable;
                    for (int i = 0; i < nameCount; i++) ordinals[i] = r.ReadUInt16();
                    for (int i = 0; i < nameCount; i++)
                    {
                        int index = ordinals[i];
                        if (index >= functionCount || names[index] != null) continue;
                        long at = toFile(nameRvas[i]);
                        if (at >= 0) names[index] = ReadAscii(f, at);
                    }
                }

                var table = new Dictionary<uint, string>();
                for (int i = 0; i < functionCount; i++)
                {
                    uint rva = addresses[i];
                    if (rva == 0 || (rva >= exportRva && rva < exportRva + exportSize)) continue;   // unused slot or forwarder
                    if (!table.ContainsKey(rva)) table[rva] = names[i] ?? ("#" + (ordinalBase + (uint)i));
                }
                return table;
            }
        }

        private static string ReadAscii(FileStream f, long at)
        {
            if (at >= f.Length) return null;
            f.Position = at;
            var bytes = new List<byte>(64);
            int b;
            while (bytes.Count < 512 && (b = f.ReadByte()) > 0) bytes.Add((byte)b);
            return bytes.Count == 0 ? null : System.Text.Encoding.ASCII.GetString(bytes.ToArray());
        }
    }
}
