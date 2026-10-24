using System;
using System.Collections.Concurrent;
using System.IO;

namespace GetSybersMitreCar.Writer
{
    /// <summary>What the sensor knows about a process: observed at its start, or looked up live when first seen.</summary>
    public sealed class ProcessInfo
    {
        public int Pid;
        public int Ppid;
        public string ImagePath;
        public string Sid;
        public string User;
        public string IntegrityLevel;
        public string CommandLine;
        public string CurrentDirectory;
        public string Environment;
        public string ParentImagePath;
        public string ParentCommandLine;
        private FileFacts _image;

        public string Exe { get { return string.IsNullOrEmpty(ImagePath) ? null : Path.GetFileName(ImagePath); } }
        public string ParentExe { get { return string.IsNullOrEmpty(ParentImagePath) ? null : Path.GetFileName(ParentImagePath); } }

        /// <summary>Hashes, signer, signature state and company of the image file (read once; a mapped image cannot change on disk).</summary>
        public FileFacts Image
        {
            get { return _image ?? (_image = string.IsNullOrEmpty(ImagePath) ? new FileFacts() : FileInspector.Inspect(ImagePath)); }
            set { _image = value; }
        }
    }

    /// <summary>
    /// The sensor's process table. A process start event fills it from the kernel event plus live lookups (token, PEB);
    /// a later event from a pid the sensor has not seen (it was running before the sensor started) is filled by
    /// the same live lookups at that moment. Nothing here is inferred.
    /// </summary>
    public sealed class ProcessTable
    {
        private readonly ConcurrentDictionary<int, ProcessInfo> _table = new ConcurrentDictionary<int, ProcessInfo>();
        private readonly bool _environment;

        public ProcessTable(bool captureEnvironment) { _environment = captureEnvironment; }

        public bool CapturesEnvironment { get { return _environment; } }

        public void Add(ProcessInfo info) { _table[info.Pid] = info; }

        public ProcessInfo Remove(int pid)
        {
            ProcessInfo info;
            return _table.TryRemove(pid, out info) ? info : null;
        }

        /// <summary>The table entry, or a fresh live lookup (cached) when the pid is unknown; null for the kernel itself.</summary>
        public ProcessInfo Get(int pid)
        {
            if (pid <= 4) return null;
            ProcessInfo info;
            if (_table.TryGetValue(pid, out info)) return info;
            info = Lookup(pid);
            if (info.ImagePath != null || info.Sid != null)
            {
                if (_table.Count > 65536) _table.Clear();
                _table[pid] = info;
            }
            return info;
        }

        /// <summary>Everything a running process shows about itself right now, including its parent's image and command line.</summary>
        public ProcessInfo Lookup(int pid)
        {
            var live = ProcessInspector.Inspect(pid, _environment);
            var info = new ProcessInfo
            {
                Pid = pid,
                Ppid = ProcessInspector.ParentPid(pid),
                ImagePath = live.ImagePath,
                Sid = live.Sid,
                User = live.User,
                IntegrityLevel = live.IntegrityLevel,
                CommandLine = live.CommandLine,
                CurrentDirectory = live.CurrentDirectory,
                Environment = live.Environment,
            };
            if (info.Ppid > 4)
            {
                ProcessInfo parent;
                if (!_table.TryGetValue(info.Ppid, out parent))
                {
                    var p = ProcessInspector.Inspect(info.Ppid, false);
                    parent = new ProcessInfo { Pid = info.Ppid, ImagePath = p.ImagePath, CommandLine = p.CommandLine };
                }
                info.ParentImagePath = parent.ImagePath;
                info.ParentCommandLine = parent.CommandLine;
            }
            return info;
        }

        /// <summary>
        /// Fills the acting-process properties an object has - hostname, fqdn, pid, ppid, image_path, exe, user, uid -
        /// but only those the object's CAR property set defines (module, for one, has no user).
        /// </summary>
        public ProcessInfo Describe(CarProps p, string obj, int pid, HostIdentity host)
        {
            var fields = CarModel.Object(obj).Fields;
            if (Array.IndexOf(fields, "hostname") >= 0) p.Set("hostname", host.HostName);
            if (Array.IndexOf(fields, "fqdn") >= 0) p.Set("fqdn", host.Fqdn);
            if (Array.IndexOf(fields, "pid") >= 0) p.Set("pid", pid);
            var info = Get(pid);
            if (info == null) return null;
            if (Array.IndexOf(fields, "ppid") >= 0 && info.Ppid > 0) p.Set("ppid", info.Ppid);
            if (Array.IndexOf(fields, "image_path") >= 0) p.Set("image_path", info.ImagePath);
            if (Array.IndexOf(fields, "exe") >= 0) p.Set("exe", info.Exe);
            if (Array.IndexOf(fields, "user") >= 0) p.Set("user", info.User);
            if (Array.IndexOf(fields, "uid") >= 0) p.Set("uid", info.Sid);
            return info;
        }
    }
}
