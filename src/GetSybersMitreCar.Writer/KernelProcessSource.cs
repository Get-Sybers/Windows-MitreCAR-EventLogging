using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace GetSybersMitreCar.Writer
{
    /// <summary>
    /// CAR process/create and process/terminate from the kernel's process events, consumed in real time.
    ///
    /// The kernel event itself carries pid, parent pid, session, the image's base name and the full command
    /// line. Everything else the process object asks for is looked up on the live process at the instant the
    /// event is handled (image path, parent image path, user, SID, integrity level) and on the image file
    /// (hashes, signer). A process that has already exited when its start event is delivered simply yields
    /// empty values for those properties - never a guess.
    /// </summary>
    public sealed class KernelProcessSource : IEventSource
    {
        public const string SessionName = "GSCAR-Sensor";

        private readonly CarEventWriter _writer;
        private readonly ILog _log;
        private readonly HostIdentity _host = HostIdentity.Current();
        // image_path observed when the process started, carried onto its terminate event (the sensor's own
        // observation of the same object; the kernel stop event has only the base name).
        private readonly ConcurrentDictionary<int, string> _imagePaths = new ConcurrentDictionary<int, string>();
        private TraceEventSession _session;
        private Thread _thread;

        public KernelProcessSource(CarEventWriter writer, ILog log)
        {
            _writer = writer;
            _log = log;
        }

        public string Name { get { return "kernel process events (ETW session " + SessionName + ")"; } }

        public void Start()
        {
            _session = new TraceEventSession(SessionName) { StopOnDispose = true };
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);
            _session.Source.Kernel.ProcessStart += OnProcessStart;
            _session.Source.Kernel.ProcessStop += OnProcessStop;
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
            if (s != null) s.Dispose();          // stops the session; Process() returns
            var t = _thread;
            _thread = null;
            if (t != null) t.Join(TimeSpan.FromSeconds(10));
        }

        private void OnProcessStart(ProcessTraceData data)
        {
            try
            {
                int pid = data.ProcessID;
                int ppid = data.ParentID;
                var p = new CarProps();
                p.Set("hostname", _host.HostName);
                p.Set("fqdn", _host.Fqdn);
                p.Set("pid", pid);
                p.Set("ppid", ppid);
                p.Set("exe", data.ImageFileName);
                p.Set("command_line", data.CommandLine);

                var live = ProcessInspector.Inspect(pid);
                if (live.ImagePath != null)
                {
                    p.Set("image_path", live.ImagePath);
                    _imagePaths[pid] = live.ImagePath;
                    var file = FileInspector.Inspect(live.ImagePath);
                    p.Set("md5_hash", file.Md5);
                    p.Set("sha1_hash", file.Sha1);
                    p.Set("sha256_hash", file.Sha256);
                    p.Set("signer", file.Signer);
                    p.Set("signature_valid", file.SignatureValid);
                }
                p.Set("sid", live.Sid);
                p.Set("user", live.User);
                p.Set("integrity_level", live.IntegrityLevel);

                string parent = ProcessInspector.ImagePath(ppid);
                if (parent != null)
                {
                    p.Set("parent_image_path", parent);
                    p.Set("parent_exe", Path.GetFileName(parent));
                }

                if (!_writer.Write("process", "create", p))
                    _log.Error("process/create pid " + pid + " not written: " + _writer.LastError);
            }
            catch (Exception ex)
            {
                _log.Error("process/create: " + ex.Message);
            }
        }

        private void OnProcessStop(ProcessTraceData data)
        {
            try
            {
                int pid = data.ProcessID;
                var p = new CarProps();
                p.Set("hostname", _host.HostName);
                p.Set("fqdn", _host.Fqdn);
                p.Set("pid", pid);
                p.Set("ppid", data.ParentID);
                p.Set("exe", data.ImageFileName);
                p.Set("command_line", data.CommandLine);
                string imagePath;
                if (_imagePaths.TryRemove(pid, out imagePath)) p.Set("image_path", imagePath);

                if (!_writer.Write("process", "terminate", p))
                    _log.Error("process/terminate pid " + pid + " not written: " + _writer.LastError);
            }
            catch (Exception ex)
            {
                _log.Error("process/terminate: " + ex.Message);
            }
        }
    }

    /// <summary>The observing host, named the way CAR's fqdn/hostname properties expect.</summary>
    public sealed class HostIdentity
    {
        public string HostName { get; private set; }
        public string Fqdn { get; private set; }

        public static HostIdentity Current()
        {
            var id = new HostIdentity { HostName = Environment.MachineName };
            try
            {
                var ip = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
                if (!string.IsNullOrEmpty(ip.DomainName)) id.Fqdn = ip.HostName + "." + ip.DomainName;
            }
            catch (Exception) { /* fqdn stays empty: not observed */ }
            return id;
        }
    }
}
