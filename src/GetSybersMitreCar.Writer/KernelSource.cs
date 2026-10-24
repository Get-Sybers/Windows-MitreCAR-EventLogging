using System;
using System.IO;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace GetSybersMitreCar.Writer
{
    /// <summary>
    /// The phase-1 source: one real-time kernel ETW session (process, thread, image, file, registry, TCP/IP)
    /// consumed through TraceEvent. Each handler maps one kernel event to one CAR (object, action) and fills the
    /// object's properties from the event, from a live lookup at that instant, and from the sensor's own process
    /// table - nothing is inferred. The per-object handlers live in the KernelSource.*.cs partials.
    /// </summary>
    public sealed partial class KernelSource : IEventSource
    {
        public const string SessionName = "GSCAR-Sensor";

        private readonly CarEventWriter _writer;
        private readonly ProcessTable _processes;
        private readonly SensorOptions _options;
        private readonly ILog _log;
        private readonly HostIdentity _host = HostIdentity.Current();
        private TraceEventSession _session;
        private Thread _thread;
        private long _handlerErrors;

        public KernelSource(CarEventWriter writer, ProcessTable processes, SensorOptions options, ILog log)
        {
            _writer = writer;
            _processes = processes;
            _options = options;
            _log = log;
        }

        public string Name { get { return "kernel ETW session " + SessionName + " (" + _options + ")"; } }

        public void Start()
        {
            _session = new TraceEventSession(SessionName) { StopOnDispose = true, BufferSizeMB = 256 };
            var keywords = KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.Thread
                | KernelTraceEventParser.Keywords.ImageLoad | KernelTraceEventParser.Keywords.Registry
                | KernelTraceEventParser.Keywords.NetworkTCPIP
                | KernelTraceEventParser.Keywords.FileIO | KernelTraceEventParser.Keywords.FileIOInit | KernelTraceEventParser.Keywords.DiskFileIO;
            _session.EnableKernelProvider(keywords);

            var k = _session.Source.Kernel;
            k.ProcessStart += OnProcessStart;
            k.ProcessStop += OnProcessStop;
            k.ImageLoad += OnImageLoad;
            k.ImageUnload += OnImageUnload;
            k.ThreadStart += OnThreadStart;
            k.ThreadStop += OnThreadStop;
            k.FileIOCreate += OnFileCreate;
            k.FileIOWrite += OnFileWrite;
            k.FileIORead += OnFileRead;
            k.FileIODelete += OnFileDelete;
            k.FileIORename += OnFileRename;
            k.FileIOSetInfo += OnFileSetInfo;
            k.RegistryCreate += OnRegistryCreate;
            k.RegistrySetValue += OnRegistrySetValue;
            k.RegistryDelete += OnRegistryDeleteKey;
            k.RegistryDeleteValue += OnRegistryDeleteValue;
            k.RegistryOpen += OnRegistryAccess;
            k.RegistryQueryValue += OnRegistryAccess;
            k.TcpIpConnect += d => OnTcpStart(d, "outbound", d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport);
            k.TcpIpAccept += d => OnTcpStart(d, "inbound", d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport);
            k.TcpIpConnectIPV6 += d => OnTcpStart(d, "outbound", d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport);
            k.TcpIpAcceptIPV6 += d => OnTcpStart(d, "inbound", d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport);
            k.TcpIpDisconnect += d => OnTcpEnd(d, d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport);
            k.TcpIpDisconnectIPV6 += d => OnTcpEnd(d, d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport);
            k.TcpIpSend += d => OnFlowMessage(d, "tcp", d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, true);
            k.TcpIpRecv += d => OnFlowMessage(d, "tcp", d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, false);
            k.TcpIpSendIPV6 += d => OnFlowMessage(d, "tcp", d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, true);
            k.TcpIpRecvIPV6 += d => OnFlowMessage(d, "tcp", d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, false);
            k.UdpIpSend += d => OnFlowMessage(d, "udp", d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, true);
            k.UdpIpRecv += d => OnFlowMessage(d, "udp", d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, false);
            k.UdpIpSendIPV6 += d => OnFlowMessage(d, "udp", d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, true);
            k.UdpIpRecvIPV6 += d => OnFlowMessage(d, "udp", d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, false);

            _thread = new Thread(() =>
            {
                try { _session.Source.Process(); }
                catch (Exception ex) { _log.Error("ETW processing ended: " + ex.Message); }
            }) { IsBackground = true, Name = SessionName };
            _thread.Start();
        }

        public void Stop()
        {
            var s = _session;
            _session = null;
            if (s != null)
            {
                try { _log.Info("kernel session: " + s.EventsLost + " events lost by ETW, " + Interlocked.Read(ref _handlerErrors) + " handler errors"); }
                catch (Exception) { }
                s.Dispose();                        // stops the session; Process() returns
            }
            var t = _thread;
            _thread = null;
            if (t != null) t.Join(TimeSpan.FromSeconds(10));
        }

        // ---- shared helpers ---------------------------------------------------------------------------

        private void Emit(string obj, string action, CarProps p)
        {
            if (!_writer.Write(obj, action, p))
                Fail(obj + "/" + action + " not written: Win32 " + _writer.LastError);
        }

        private void Fail(string message)
        {
            long n = Interlocked.Increment(ref _handlerErrors);
            if (n <= 20 || n % 1000 == 0) _log.Error(message + (n > 20 ? " (error #" + n + ")" : ""));
        }

        private static void SetPath(CarProps p, string field, string ntPath)
        {
            if (string.IsNullOrEmpty(ntPath)) return;
            p.Set(field, PathMapper.ToDosPath(ntPath));
        }

        /// <summary>file_path / file_name / extension from a kernel file name.</summary>
        private static string SetFilePath(CarProps p, string ntPath)
        {
            if (string.IsNullOrEmpty(ntPath)) return null;
            string path = PathMapper.ToDosPath(ntPath);
            p.Set("file_path", path);
            string name = Path.GetFileName(path);
            p.Set("file_name", name);
            string ext = Path.GetExtension(name);
            p.Set("extension", ext);
            return path;
        }

        private static void SetImageFacts(CarProps p, string dosPath)
        {
            if (string.IsNullOrEmpty(dosPath)) return;
            var f = FileInspector.Inspect(dosPath);
            p.Set("md5_hash", f.Md5);
            p.Set("sha1_hash", f.Sha1);
            p.Set("sha256_hash", f.Sha256);
            p.Set("signer", f.Signer);
            p.Set("signature_valid", f.SignatureValid);
        }
    }
}
