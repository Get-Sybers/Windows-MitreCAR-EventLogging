using System;
using System.Collections.Concurrent;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace GetSybersMitreCar.Writer
{
    public sealed partial class KernelSource
    {
        // FILE_INFORMATION_CLASS values whose NtSetInformationFile changes the file (the rest - position, mode,
        // completion ports - change only the handle and are not a modification of the file).
        private const int FileBasicInformation = 4;            // timestamps and attributes
        private const int FileRenameInformation = 10;
        private const int FileLinkInformation = 11;            // a new hard link
        private const int FileAllocationInformation = 19;
        private const int FileEndOfFileInformation = 20;
        private const int FileValidDataLengthInformation = 39;
        private const int FileShortNameInformation = 40;

        // IoStatus.Information of a completed IRP_MJ_CREATE (the kernel's OpEnd ExtraInfo for a Create).
        private const ulong FILE_SUPERSEDED = 0, FILE_OPENED = 1, FILE_CREATED = 2, FILE_OVERWRITTEN = 3;

        /// <summary>A create or set-information request waiting for its completion event (matched by IRP).</summary>
        private sealed class PendingFileOp
        {
            public bool IsCreate;
            public int Pid;
            public string NtPath;
            public FileState Before;         // set-information: the file as it was when the request started
        }

        private readonly ConcurrentDictionary<ulong, PendingFileOp> _pendingFileOps = new ConcurrentDictionary<ulong, PendingFileOp>();

        /// <summary>
        /// The file object's properties: the acting process (hostname, fqdn, pid, ppid, image_path, user, uid, and the
        /// hashes / signer / company of that image - CAR defines them on `image_path`), the path, and the file's own state
        /// on disk right now (times, owner, group, permissions, link target, MIME type).
        /// </summary>
        private CarProps FileProps(int pid, string ntPath, out string dosPath, out FileState state)
        {
            var p = new CarProps();
            var info = _processes.Describe(p, "file", pid, _host);
            if (info != null)
            {
                var image = info.Image;
                SetImageFacts(p, image);
                p.Set("company", image.Company);
            }
            dosPath = SetFilePath(p, ntPath);
            state = FileInspector.Read(dosPath);
            p.Set("creation_time", state.CreationTime);
            p.Set("owner", state.Owner);
            p.Set("owner_uid", state.OwnerSid);
            p.Set("group", state.Group);
            p.Set("gid", state.GroupSid);
            p.Set("mode", state.Mode);
            p.Set("link_target", state.LinkTarget);
            p.Set("mime_type", state.MimeType);
            return p;
        }

        private void OnFileCreate(FileIOCreateTraceData data)
        {
            try
            {
                // Only a request that can create or replace a file is followed to its result: Supersede 0, Create 2,
                // OpenIf 3, Overwrite 4, OverwriteIf 5. Open 1 never creates.
                int disposition = (int)data.CreateDisposition;
                if (disposition == 1 || disposition > 5 || string.IsNullOrEmpty(data.FileName)) return;
                if (_pendingFileOps.Count > 50000) _pendingFileOps.Clear();      // completions lost: start over
                _pendingFileOps[data.IrpPtr] = new PendingFileOp { IsCreate = true, Pid = data.ProcessID, NtPath = data.FileName };
            }
            catch (Exception ex) { Fail("file/create: " + ex.Message); }
        }

        /// <summary>The completion of a create or set-information request: the kernel's own result decides what happened.</summary>
        private void OnFileOperationEnd(FileIOOpEndTraceData data)
        {
            PendingFileOp op;
            if (!_pendingFileOps.TryRemove(data.IrpPtr, out op)) return;
            try
            {
                if (data.NtStatus < 0) return;                                   // the request failed: nothing was created or changed
                string path;
                FileState after;
                if (op.IsCreate)
                {
                    ulong result = data.ExtraInfo;
                    if (result != FILE_CREATED && result != FILE_SUPERSEDED && result != FILE_OVERWRITTEN) return;   // opened an existing file
                    var p = FileProps(op.Pid, op.NtPath, out path, out after);
                    if (path == null) return;
                    Emit("file", "create", p);
                }
                else
                {
                    var p = FileProps(op.Pid, op.NtPath, out path, out after);
                    if (path == null) return;
                    if (after.TimesDiffer(op.Before))
                    {
                        if (op.Before != null) p.Set("previous_creation_time", op.Before.CreationTime);
                        Emit("file", "timestomp", p);
                    }
                    else
                    {
                        Emit("file", "modify", p);                               // attributes (or the same times) were set
                    }
                }
            }
            catch (Exception ex) { Fail("file/" + (op.IsCreate ? "create" : "setinfo") + ": " + ex.Message); }
        }

        private void OnFileWrite(FileIOReadWriteTraceData data)
        {
            try
            {
                string path; FileState state;
                var p = FileProps(data.ProcessID, data.FileName, out path, out state);
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
                string path; FileState state;
                var p = FileProps(data.ProcessID, data.FileName, out path, out state);
                if (path == null) return;
                Emit("file", "read", p);
            }
            catch (Exception ex) { Fail("file/read: " + ex.Message); }
        }

        private void OnFileDelete(FileIOInfoTraceData data)
        {
            try
            {
                string path; FileState state;
                var p = FileProps(data.ProcessID, data.FileName, out path, out state);
                if (path == null) return;
                Emit("file", "delete", p);
            }
            catch (Exception ex) { Fail("file/delete: " + ex.Message); }
        }

        private void OnFileRename(FileIOInfoTraceData data)
        {
            try
            {
                string path; FileState state;
                var p = FileProps(data.ProcessID, data.FileName, out path, out state);
                if (path == null) return;
                Emit("file", "modify", p);
            }
            catch (Exception ex) { Fail("file/modify: " + ex.Message); }
        }

        private void OnFileSetInfo(FileIOInfoTraceData data)
        {
            try
            {
                if (string.IsNullOrEmpty(data.FileName)) return;
                switch (data.InfoClass)
                {
                    case FileBasicInformation:
                        // Timestamps or attributes: the file's times are read now and again at completion, and the kernel's
                        // result decides between timestomp (a time changed) and modify.
                        if (_pendingFileOps.Count > 50000) _pendingFileOps.Clear();
                        _pendingFileOps[data.IrpPtr] = new PendingFileOp { Pid = data.ProcessID, NtPath = data.FileName, Before = FileInspector.Read(PathMapper.ToDosPath(data.FileName)) };
                        return;
                    case FileRenameInformation:
                    case FileLinkInformation:
                    case FileAllocationInformation:
                    case FileEndOfFileInformation:
                    case FileValidDataLengthInformation:
                    case FileShortNameInformation:
                        string path; FileState state;
                        var p = FileProps(data.ProcessID, data.FileName, out path, out state);
                        if (path == null) return;
                        Emit("file", "modify", p);
                        return;
                    default:
                        return;                                                  // handle state only: not a change to the file
                }
            }
            catch (Exception ex) { Fail("file/setinfo: " + ex.Message); }
        }
    }
}
