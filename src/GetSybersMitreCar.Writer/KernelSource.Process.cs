using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
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

                // The kernel event carries the token's user SID; the live lookups add what only the running process shows.
                var live = ProcessInspector.Inspect(pid, _processes.CapturesEnvironment);
                if (imagePath == null) imagePath = live.ImagePath;          // the kernel path is preferred; the live one is the fallback
                string sid = EventSid(data) ?? live.Sid;
                string user = live.User ?? SidNames.Resolve(sid);
                p.Set("image_path", imagePath);
                p.Set("sid", sid);
                p.Set("uid", sid);
                p.Set("user", user);
                p.Set("integrity_level", live.IntegrityLevel);
                p.Set("current_working_directory", live.CurrentDirectory);
                p.Set("env_vars", live.Environment);
                var image = string.IsNullOrEmpty(imagePath) ? new FileFacts() : FileInspector.Inspect(imagePath);
                SetImageFacts(p, image);

                // The parent: what the sensor saw it start with, else what it shows live now.
                var parent = _processes.Get(ppid);
                if (parent != null)
                {
                    p.Set("parent_image_path", parent.ImagePath);
                    p.Set("parent_exe", parent.Exe);
                    p.Set("parent_command_line", parent.CommandLine);
                }

                _processes.Add(new ProcessInfo
                {
                    Pid = pid, Ppid = ppid, ImagePath = imagePath, Sid = sid, User = user, IntegrityLevel = live.IntegrityLevel,
                    CommandLine = data.CommandLine, CurrentDirectory = live.CurrentDirectory, Environment = live.Environment,
                    ParentImagePath = parent != null ? parent.ImagePath : null, ParentCommandLine = parent != null ? parent.CommandLine : null,
                    Image = image,
                });
                Emit("process", "create", p);
            }
            catch (Exception ex) { Fail("process/create: " + ex.Message); }
        }

        private void OnProcessStop(ProcessTraceData data)
        {
            try
            {
                int pid = data.ProcessID;
                var known = _processes.Remove(pid);
                _modules.Forget(pid);
                var p = new CarProps();
                p.Set("hostname", _host.HostName);
                p.Set("fqdn", _host.Fqdn);
                p.Set("pid", pid);
                p.Set("ppid", data.ParentID);
                p.Set("exe", data.ImageFileName);
                p.Set("command_line", data.CommandLine);
                string imagePath = string.IsNullOrEmpty(data.KernelImageFileName) ? (known != null ? known.ImagePath : null) : PathMapper.ToDosPath(data.KernelImageFileName);
                p.Set("image_path", imagePath);
                string sid = EventSid(data) ?? (known != null ? known.Sid : null);
                p.Set("sid", sid);
                p.Set("uid", sid);
                p.Set("user", known != null && known.User != null ? known.User : SidNames.Resolve(sid));
                SetImageFacts(p, known != null && known.ImagePath == imagePath ? known.Image : FileInspector.Inspect(imagePath));
                if (known != null)
                {
                    // The sensor's own observations of this process at its start: fixed for its lifetime (token label, parent)
                    // or the state it started with (working directory, environment) - the exited process shows nothing now.
                    p.Set("integrity_level", known.IntegrityLevel);
                    p.Set("parent_image_path", known.ParentImagePath);
                    p.Set("parent_exe", known.ParentExe);
                    p.Set("parent_command_line", known.ParentCommandLine);
                    p.Set("current_working_directory", known.CurrentDirectory);
                    p.Set("env_vars", known.Environment);
                }
                Emit("process", "terminate", p);
            }
            catch (Exception ex) { Fail("process/terminate: " + ex.Message); }
        }

        /// <summary>
        /// The user SID the kernel wrote into the Process/Start and Process/End payload (after the fixed fields: a
        /// TOKEN_USER - two pointers - followed by the SID), or null when the payload carries none.
        /// </summary>
        private static string EventSid(ProcessTraceData data)
        {
            try
            {
                int ps = data.PointerSize;
                int offset = data.Version >= 4 ? 28 + 2 * (ps - 4) : data.Version >= 3 ? 24 + 2 * (ps - 4) : 20 + (ps - 4);
                int length = data.EventDataLength;
                IntPtr start = data.DataStart;
                if (start == IntPtr.Zero || offset + 4 > length) return null;
                if (Marshal.ReadInt32(start, offset) == 0) return null;          // a null token: no SID follows
                offset += 8 + 2 * (ps - 4);                                       // TOKEN_USER: Sid pointer + Attributes
                if (offset + 8 > length) return null;
                int count = Marshal.ReadByte(start, offset + 1);                  // SID.SubAuthorityCount
                int size = 8 + 4 * count;
                if (count == 0 || count > 15 || offset + size > length) return null;
                var bytes = new byte[size];
                Marshal.Copy(new IntPtr(start.ToInt64() + offset), bytes, 0, size);
                return new SecurityIdentifier(bytes, 0).Value;
            }
            catch (Exception) { return null; }
        }
    }
}
