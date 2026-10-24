using System;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace GetSybersMitreCar.Writer
{
    public sealed partial class KernelSource
    {
        private const int FileBasicInformation = 4;   // FILE_INFORMATION_CLASS: timestamps and attributes

        private CarProps FileProps(int pid, string ntPath, out string dosPath)
        {
            var p = new CarProps();
            var info = _processes.Describe(p, "file", pid, _host);
            if (info != null) p.Set("uid", info.Sid);
            dosPath = SetFilePath(p, ntPath);
            return p;
        }

        private void OnFileCreate(FileIOCreateTraceData data)
        {
            try
            {
                // Supersede, Create, OverwriteIf create or replace a file; Open/OpenIf/Overwrite work on an existing one.
                int disposition = (int)data.CreateDisposition;
                if (disposition != 0 && disposition != 2 && disposition != 5) return;
                string path;
                var p = FileProps(data.ProcessID, data.FileName, out path);
                if (path == null) return;
                p.Set("creation_time", FileInspector.CreationTime(path));
                string owner, ownerSid;
                FileInspector.Owner(path, out owner, out ownerSid);
                p.Set("owner", owner);
                p.Set("owner_uid", ownerSid);
                Emit("file", "create", p);
            }
            catch (Exception ex) { Fail("file/create: " + ex.Message); }
        }

        private void OnFileWrite(FileIOReadWriteTraceData data)
        {
            try
            {
                string path;
                var p = FileProps(data.ProcessID, data.FileName, out path);
                if (path == null) return;
                Emit("file", "write", p);
            }
            catch (Exception ex) { Fail("file/write: " + ex.Message); }
        }

        private void OnFileRead(FileIOReadWriteTraceData data)
        {
            if (!_options.FileReads) return;
            try
            {
                string path;
                var p = FileProps(data.ProcessID, data.FileName, out path);
                if (path == null) return;
                Emit("file", "read", p);
            }
            catch (Exception ex) { Fail("file/read: " + ex.Message); }
        }

        private void OnFileDelete(FileIOInfoTraceData data)
        {
            try
            {
                string path;
                var p = FileProps(data.ProcessID, data.FileName, out path);
                if (path == null) return;
                Emit("file", "delete", p);
            }
            catch (Exception ex) { Fail("file/delete: " + ex.Message); }
        }

        private void OnFileRename(FileIOInfoTraceData data)
        {
            try
            {
                string path;
                var p = FileProps(data.ProcessID, data.FileName, out path);
                if (path == null) return;
                Emit("file", "modify", p);
            }
            catch (Exception ex) { Fail("file/modify: " + ex.Message); }
        }

        private void OnFileSetInfo(FileIOInfoTraceData data)
        {
            try
            {
                string path;
                var p = FileProps(data.ProcessID, data.FileName, out path);
                if (path == null) return;
                if (data.InfoClass == FileBasicInformation)
                {
                    p.Set("creation_time", FileInspector.CreationTime(path));
                    Emit("file", "timestomp", p);
                }
                else
                {
                    Emit("file", "modify", p);
                }
            }
            catch (Exception ex) { Fail("file/setinfo: " + ex.Message); }
        }
    }
}
