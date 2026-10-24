using System;
using System.IO;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace GetSybersMitreCar.Writer
{
    public sealed partial class KernelSource
    {
        private void OnProcessStart(ProcessTraceData data)
        {
            try
            {
                int pid = data.ProcessID, ppid = data.ParentID;
                var p = new CarProps();
                p.Set("hostname", _host.HostName);
                p.Set("fqdn", _host.Fqdn);
                p.Set("pid", pid);
                p.Set("ppid", ppid);
                p.Set("exe", data.ImageFileName);
                p.Set("command_line", data.CommandLine);
                string imagePath = string.IsNullOrEmpty(data.KernelImageFileName) ? null : PathMapper.ToDosPath(data.KernelImageFileName);

                var live = ProcessInspector.Inspect(pid);
                if (imagePath == null) imagePath = live.ImagePath;          // the kernel path is preferred; the live one is the fallback
                p.Set("image_path", imagePath);
                p.Set("sid", live.Sid);
                p.Set("user", live.User);
                p.Set("integrity_level", live.IntegrityLevel);
                SetImageFacts(p, imagePath);

                string parent = ProcessInspector.ImagePath(ppid);
                if (parent != null)
                {
                    p.Set("parent_image_path", parent);
                    p.Set("parent_exe", Path.GetFileName(parent));
                }

                _processes.Add(new ProcessInfo { Pid = pid, Ppid = ppid, ImagePath = imagePath, Sid = live.Sid, User = live.User });
                Emit("process", "create", p);
            }
            catch (Exception ex) { Fail("process/create: " + ex.Message); }
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
                var known = _processes.Remove(pid);
                string imagePath = string.IsNullOrEmpty(data.KernelImageFileName) ? (known != null ? known.ImagePath : null) : PathMapper.ToDosPath(data.KernelImageFileName);
                p.Set("image_path", imagePath);
                if (known != null) { p.Set("sid", known.Sid); p.Set("user", known.User); }
                Emit("process", "terminate", p);
            }
            catch (Exception ex) { Fail("process/terminate: " + ex.Message); }
        }
    }
}
