using System;
using System.Collections.Generic;

namespace GetSybersMitreCar.Writer
{
    /// <summary>What the sensor observes. The high-volume pairs are opt-in; everything else is always on.</summary>
    public sealed class SensorOptions
    {
        /// <summary>thread/create and thread/terminate for threads created inside their own process (remote_create is always on).</summary>
        public bool Threads;
        /// <summary>file/read.</summary>
        public bool FileReads;
        /// <summary>flow/message for every TCP/UDP send and receive.</summary>
        public bool FlowMessages;
        /// <summary>registry/access for every key open and value query.</summary>
        public bool RegistryAccess;
        /// <summary>process env_vars: the environment block read from the new process (off with --no-env-vars; it can hold secrets).</summary>
        public bool EnvVars = true;

        public bool Console;
        public int DurationSeconds;
        public bool SelfTest;
        public readonly List<int> SelfTestIds = new List<int>();

        public static SensorOptions Parse(IEnumerable<string> args, out string error)
        {
            var o = new SensorOptions();
            error = null;
            var list = new List<string>(args);
            for (int i = 0; i < list.Count; i++)
            {
                switch (list[i])
                {
                    case "--console": o.Console = true; break;
                    case "--duration":
                        if (i + 1 >= list.Count || !int.TryParse(list[++i], out o.DurationSeconds)) { error = "--duration needs a number of seconds"; return o; }
                        o.Console = true;
                        break;
                    case "--threads": o.Threads = true; break;
                    case "--file-reads": o.FileReads = true; break;
                    case "--flow-messages": o.FlowMessages = true; break;
                    case "--registry-access": o.RegistryAccess = true; break;
                    case "--no-env-vars": o.EnvVars = false; break;
                    case "--selftest":
                        o.SelfTest = true;
                        while (i + 1 < list.Count && int.TryParse(list[i + 1], out int id)) { o.SelfTestIds.Add(id); i++; }
                        break;
                    default:
                        error = "unknown argument: " + list[i];
                        return o;
                }
            }
            return o;
        }

        public override string ToString()
        {
            return "threads=" + Threads + " file-reads=" + FileReads + " flow-messages=" + FlowMessages + " registry-access=" + RegistryAccess + " env-vars=" + EnvVars;
        }
    }
}
