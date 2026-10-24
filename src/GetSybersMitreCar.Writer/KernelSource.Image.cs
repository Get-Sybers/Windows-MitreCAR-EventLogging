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
                string path = PathMapper.ToDosPath(data.FileName);
                _modules.Load(data.ProcessID, data.ImageBase, (ulong)(uint)data.ImageSize, path);
                if (IsKernelProcess(data.ProcessID)) { Driver("load", data, path); return; }
                Emit("module", "load", ModuleProps(data, path));
            }
            catch (Exception ex) { Fail("module/load: " + ex.Message); }
        }

        private void OnImageUnload(ImageLoadTraceData data)
        {
            try
            {
                string path = PathMapper.ToDosPath(data.FileName);
                _modules.Unload(data.ProcessID, data.ImageBase);
                if (IsKernelProcess(data.ProcessID)) { Driver("unload", data, path); return; }
                Emit("module", "unload", ModuleProps(data, path));
            }
            catch (Exception ex) { Fail("module/unload: " + ex.Message); }
        }

        /// <summary>The module object: the hosting process, the module file (hashed and checked on disk - still there at unload), its base, the loading thread.</summary>
        private CarProps ModuleProps(ImageLoadTraceData data, string path)
        {
            var p = new CarProps();
            _processes.Describe(p, "module", data.ProcessID, _host);
            p.Set("module_path", path);
            p.Set("module_name", Path.GetFileName(path));
            p.Set("base_address", Formats.Hex(data.ImageBase));
            p.Set("tid", data.ThreadID);
            SetImageFacts(p, path);
            return p;
        }

        /// <summary>A kernel-mode image loaded or unloaded by the kernel itself: CAR driver. The file is on disk for both, so it is hashed and checked for both.</summary>
        private void Driver(string action, ImageLoadTraceData data, string path)
        {
            try
            {
                var p = new CarProps();
                p.Set("hostname", _host.HostName);
                p.Set("fqdn", _host.Fqdn);
                p.Set("image_path", path);
                p.Set("module_name", Path.GetFileName(path));
                p.Set("base_address", Formats.Hex(data.ImageBase));
                p.Set("pid", data.ProcessID);
                SetImageFacts(p, path);
                Emit("driver", action, p);
            }
            catch (Exception ex) { Fail("driver/" + action + ": " + ex.Message); }
        }
    }
}
