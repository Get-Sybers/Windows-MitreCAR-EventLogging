using System;
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
                p.Set("src_pid", creator);
                p.Set("src_tid", data.ParentThreadID);
                p.Set("tgt_pid", owner);
                p.Set("tgt_tid", data.ThreadID);
                p.Set("stack_base", Formats.Hex(data.StackBase));
                p.Set("stack_limit", Formats.Hex(data.StackLimit));
                p.Set("user_stack_base", Formats.Hex(data.UserStackBase));
                p.Set("user_stack_limit", Formats.Hex(data.UserStackLimit));
                p.Set("start_address", Formats.Hex(data.Win32StartAddr));
                var src = _processes.Get(creator);
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
                var p = new CarProps();
                p.Set("hostname", _host.HostName);
                p.Set("tgt_pid", data.ProcessID);
                p.Set("tgt_tid", data.ThreadID);
                p.Set("stack_base", Formats.Hex(data.StackBase));
                p.Set("stack_limit", Formats.Hex(data.StackLimit));
                p.Set("user_stack_base", Formats.Hex(data.UserStackBase));
                p.Set("user_stack_limit", Formats.Hex(data.UserStackLimit));
                p.Set("start_address", Formats.Hex(data.Win32StartAddr));
                Emit("thread", "terminate", p);
            }
            catch (Exception ex) { Fail("thread/terminate: " + ex.Message); }
        }
    }
}
