using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;

namespace GetSybersMitreCar.Writer
{
    /// <summary>The properties of one observed CAR object. Only observed values are set; anything else stays empty.</summary>
    public sealed class CarProps
    {
        private readonly Dictionary<string, string> _values = new Dictionary<string, string>(StringComparer.Ordinal);

        public void Set(string field, string value)
        {
            if (string.IsNullOrEmpty(value)) return;
            _values[field] = value;
        }

        public void Set(string field, int value) { _values[field] = value.ToString(System.Globalization.CultureInfo.InvariantCulture); }

        public bool TryGet(string field, out string value) { return _values.TryGetValue(field, out value); }

        public IEnumerable<string> Fields { get { return _values.Keys; } }
    }

    /// <summary>
    /// Writes CAR events through the native ETW provider API (EventRegister / EventWrite). Every event is the
    /// object's complete property set in the template's order, each property a null-terminated UTF-16 string;
    /// a property that was not observed is written as the empty string.
    /// </summary>
    public sealed unsafe class CarEventWriter : IDisposable
    {
        /// <summary>Longest value written for one property (command lines, environment blocks); keeps a record well under the render limit.</summary>
        public const int MaxValueChars = 8192;

        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_DESCRIPTOR
        {
            public ushort Id;
            public byte Version;
            public byte Channel;
            public byte Level;
            public byte Opcode;
            public ushort Task;
            public ulong Keyword;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_DATA_DESCRIPTOR
        {
            public ulong Ptr;
            public uint Size;
            public uint Reserved;
        }

        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint EventRegister(ref Guid providerId, IntPtr enableCallback, IntPtr callbackContext, out long regHandle);

        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint EventUnregister(long regHandle);

        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint EventWrite(long regHandle, ref EVENT_DESCRIPTOR descriptor, uint userDataCount, EVENT_DATA_DESCRIPTOR* userData);

        private readonly Dictionary<string, EVENT_DESCRIPTOR> _descriptors = new Dictionary<string, EVENT_DESCRIPTOR>(StringComparer.Ordinal);
        private long _handle;
        private long _written;
        private long _failed;
        private uint _lastError;

        public long Written { get { return Interlocked.Read(ref _written); } }
        public long Failed { get { return Interlocked.Read(ref _failed); } }
        /// <summary>The Win32 status of the last failed EventWrite (534 = event too large, 8 = session buffers full).</summary>
        public uint LastError { get { return _lastError; } }

        public CarEventWriter()
        {
            Guid guid = CarModel.ProviderGuid;
            uint status = EventRegister(ref guid, IntPtr.Zero, IntPtr.Zero, out _handle);
            if (status != 0) throw new InvalidOperationException("EventRegister(" + CarModel.ProviderName + ") failed with Win32 error " + status);
            foreach (var e in CarModel.Events)
            {
                // The same descriptor mc.exe generated into GetSybersMitreCar.h: the channel's keyword bit is ORed in so the
                // Event Log service's session accepts the event (Test-Channel.ps1 asserts this against the header).
                _descriptors[e.Object + "/" + e.Action] = new EVENT_DESCRIPTOR
                {
                    Id = (ushort)e.Id,
                    Version = 0,
                    Channel = CarModel.ChannelValue,
                    Level = CarModel.Level,
                    Opcode = (byte)e.Opcode,
                    Task = (ushort)e.Task,
                    Keyword = e.Keyword | CarModel.ChannelKeyword,
                };
            }
        }

        /// <summary>Write one (object, action) with the properties observed for it. Returns false if ETW refused the event.</summary>
        public bool Write(string obj, string action, CarProps props)
        {
            var o = CarModel.Object(obj);
            if (o == null) throw new ArgumentException("unknown CAR object " + obj, "obj");
            EVENT_DESCRIPTOR descriptor;
            if (!_descriptors.TryGetValue(obj + "/" + action, out descriptor))
                throw new ArgumentException("unknown CAR action " + obj + "/" + action, "action");

            foreach (var f in props.Fields)
                if (Array.IndexOf(o.Fields, f) < 0)
                    throw new ArgumentException(f + " is not a property of CAR object " + obj, "props");

            int n = o.Fields.Length;
            var values = new string[n];
            for (int i = 0; i < n; i++)
            {
                string v;
                values[i] = props.TryGet(o.Fields[i], out v) ? Truncate(v) : string.Empty;
            }

            // Pin each string in place: a pinned System.String's address is its first UTF-16 character and the
            // runtime keeps a null terminator after the last one, which is exactly what win:UnicodeString wants.
            var handles = new GCHandle[n];
            var data = new EVENT_DATA_DESCRIPTOR[n];
            try
            {
                for (int i = 0; i < n; i++)
                {
                    handles[i] = GCHandle.Alloc(values[i], GCHandleType.Pinned);
                    data[i].Ptr = (ulong)handles[i].AddrOfPinnedObject().ToInt64();
                    data[i].Size = (uint)((values[i].Length + 1) * 2);
                    data[i].Reserved = 0;
                }
                uint status;
                fixed (EVENT_DATA_DESCRIPTOR* p = data)
                {
                    status = EventWrite(_handle, ref descriptor, (uint)n, p);
                }
                if (status == 0) { Interlocked.Increment(ref _written); return true; }
                _lastError = status;
                Interlocked.Increment(ref _failed);
                return false;
            }
            finally
            {
                for (int i = 0; i < n; i++) if (handles[i].IsAllocated) handles[i].Free();
            }
        }

        private static string Truncate(string v)
        {
            return v.Length <= MaxValueChars ? v : v.Substring(0, MaxValueChars);
        }

        public void Dispose()
        {
            long h = Interlocked.Exchange(ref _handle, 0);
            if (h != 0) EventUnregister(h);
        }
    }
}
