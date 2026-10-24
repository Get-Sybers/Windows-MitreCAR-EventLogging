using System;
using System.IO;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace GetSybersMitreCar.Writer
{
    public sealed partial class KernelSource
    {
        private void OnThreadStart(ThreadTraceData data)
        {
            try
            {
                int owner = data.ProcessID, creator = data.ParentProcessID;
                bool remote = creator > 0 && creator != owner;
                if (!remote && !_options.Threads) return;
                var p = new CarProps();
                p.Set("hostname", _host.HostName);
                if (creator > 0) { p.Set("src_pid", creator); p.Set("src_tid", data.ParentThreadID); }   // the kernel reports the creator only on recent event versions
                p.Set("tgt_pid", owner);
                p.Set("tgt_tid", data.ThreadID);
                SetThreadStart(p, owner, data);
                // The user context of the creating thread: its process's token (an impersonating thread is not visible here).
                var src = _processes.Get(creator > 0 ? creator : owner);
                if (src != null) { p.Set("user", src.User); p.Set("uid", src.Sid); }
                Emit("thread", remote ? "remote_create" : "create", p);
            }
            catch (Exception ex) { Fail("thread/create: " + ex.Message); }
        }

        private void OnThreadStop(ThreadTraceData data)
        {
            if (!_options.Threads) return;
            try
            {
                int owner = data.ProcessID;
                var p = new CarProps();
                p.Set("hostname", _host.HostName);
                p.Set("tgt_pid", owner);
                p.Set("tgt_tid", data.ThreadID);
                SetThreadStart(p, owner, data);
                // The ending thread runs in its owning process: that process's token is the user who acted on it.
                var proc = _processes.Get(owner);
                if (proc != null) { p.Set("user", proc.User); p.Set("uid", proc.Sid); }
                Emit("thread", "terminate", p);
            }
            catch (Exception ex) { Fail("thread/terminate: " + ex.Message); }
        }

        /// <summary>
        /// The stack bounds and start address the kernel reports, and the module and function the start address falls in,
        /// resolved from the sensor's module map for that process and the module file's export table. start_function is set
        /// only when the start address is exactly an exported function - no nearest-symbol guessing.
        /// </summary>
        private void SetThreadStart(CarProps p, int ownerPid, ThreadTraceData data)
        {
            p.Set("stack_base", Formats.Hex(data.StackBase));
            p.Set("stack_limit", Formats.Hex(data.StackLimit));
            p.Set("user_stack_base", Formats.Hex(data.UserStackBase));
            p.Set("user_stack_limit", Formats.Hex(data.UserStackLimit));
            ulong start = data.Win32StartAddr;
            p.Set("start_address", Formats.Hex(start));
            var module = _modules.Find(ownerPid, start);
            if (module == null) return;
            var range = module.Value;
            p.Set("start_module", range.Path);
            p.Set("start_module_name", Path.GetFileName(range.Path));
            string function = PeExports.FunctionAt(range.Path, start - range.Base);
            p.Set("start_function", function);
        }
    }
}
