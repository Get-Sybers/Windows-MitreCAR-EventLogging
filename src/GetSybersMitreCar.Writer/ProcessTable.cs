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
        public string Exe { get { return string.IsNullOrEmpty(ImagePath) ? null : Path.GetFileName(ImagePath); } }
    }

    /// <summary>
    /// The sensor's process table. A process start event fills it from the kernel event plus a live token lookup;
    /// a later event from a pid the sensor has not seen (it was running before the sensor started) is filled by
    /// a live lookup at that moment. Nothing here is inferred.
    /// </summary>
    public sealed class ProcessTable
    {
        private readonly ConcurrentDictionary<int, ProcessInfo> _table = new ConcurrentDictionary<int, ProcessInfo>();

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
            var live = ProcessInspector.Inspect(pid);
            info = new ProcessInfo { Pid = pid, Ppid = ProcessInspector.ParentPid(pid), ImagePath = live.ImagePath, Sid = live.Sid, User = live.User };
            if (info.ImagePath != null || info.Sid != null)
            {
                if (_table.Count > 65536) _table.Clear();
                _table[pid] = info;
            }
            return info;
        }

        /// <summary>
        /// Fills the shared acting-process properties an object has (hostname, fqdn, pid, image_path, user) - only
        /// those the object's CAR property set defines (module, for one, has no user).
        /// </summary>
        public ProcessInfo Describe(CarProps p, string obj, int pid, HostIdentity host)
        {
            var fields = CarModel.Object(obj).Fields;
            if (Array.IndexOf(fields, "hostname") >= 0) p.Set("hostname", host.HostName);
            if (Array.IndexOf(fields, "fqdn") >= 0) p.Set("fqdn", host.Fqdn);
            if (Array.IndexOf(fields, "pid") >= 0) p.Set("pid", pid);
            var info = Get(pid);
            if (info == null) return null;
            if (Array.IndexOf(fields, "image_path") >= 0) p.Set("image_path", info.ImagePath);
            if (Array.IndexOf(fields, "user") >= 0) p.Set("user", info.User);
            return info;
        }
    }
}
