using System;
using System.IO;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace GetSybersMitreCar.Writer
{
    public sealed partial class KernelSource
    {
        private static bool IsKernelProcess(int pid) { return pid == 0 || pid == 4; }

        private void OnImageLoad(ImageLoadTraceData data)
        {
            try
            {
                if (IsKernelProcess(data.ProcessID)) { Driver("load", data, true); return; }
                var p = new CarProps();
                _processes.Describe(p, "module", data.ProcessID, _host);
                string path = PathMapper.ToDosPath(data.FileName);
                p.Set("module_path", path);
                p.Set("module_name", Path.GetFileName(path));
                p.Set("base_address", Formats.Hex(data.ImageBase));
                p.Set("tid", data.ThreadID);
                SetImageFacts(p, path);
                Emit("module", "load", p);
            }
            catch (Exception ex) { Fail("module/load: " + ex.Message); }
        }

        private void OnImageUnload(ImageLoadTraceData data)
        {
            try
            {
                if (IsKernelProcess(data.ProcessID)) { Driver("unload", data, false); return; }
                var p = new CarProps();
                _processes.Describe(p, "module", data.ProcessID, _host);
                string path = PathMapper.ToDosPath(data.FileName);
                p.Set("module_path", path);
                p.Set("module_name", Path.GetFileName(path));
                p.Set("base_address", Formats.Hex(data.ImageBase));
                p.Set("tid", data.ThreadID);
                Emit("module", "unload", p);
            }
            catch (Exception ex) { Fail("module/unload: " + ex.Message); }
        }

        /// <summary>A kernel-mode image loaded or unloaded by the kernel itself: CAR driver.</summary>
        private void Driver(string action, ImageLoadTraceData data, bool withFacts)
        {
            try
            {
                var p = new CarProps();
                p.Set("hostname", _host.HostName);
                p.Set("fqdn", _host.Fqdn);
                string path = PathMapper.ToDosPath(data.FileName);
                p.Set("image_path", path);
                p.Set("module_name", Path.GetFileName(path));
                p.Set("base_address", Formats.Hex(data.ImageBase));
                p.Set("pid", data.ProcessID);
                if (withFacts) SetImageFacts(p, path);
                Emit("driver", action, p);
            }
            catch (Exception ex) { Fail("driver/" + action + ": " + ex.Message); }
        }
    }
}
