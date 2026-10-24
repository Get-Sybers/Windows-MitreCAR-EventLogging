using System;
using System.Collections.Generic;

namespace GetSybersMitreCar.Writer
{
    /// <summary>A live telemetry source that turns observed actions into CAR events.</summary>
    public interface IEventSource
    {
        string Name { get; }
        void Start();
        void Stop();
    }

    /// <summary>The sensor: one event writer, the process table, one or more live sources.</summary>
    public sealed class Sensor : IDisposable
    {
        private readonly ILog _log;
        private readonly CarEventWriter _writer;
        private readonly List<IEventSource> _sources = new List<IEventSource>();
        private bool _started;

        public Sensor(ILog log, SensorOptions options)
        {
            _log = log;
            _writer = new CarEventWriter();
            // Other users' processes open for a PEB read only with SeDebugPrivilege enabled (LocalSystem holds it; an elevated console does too).
            if (!Privileges.Enable("SeDebugPrivilege")) log.Info("SeDebugPrivilege not held: command lines, working directories and environments of other users' processes will not be read");
            var processes = new ProcessTable(options.EnvVars);
            _sources.Add(new KernelSource(_writer, processes, new ModuleMap(), new FlowTable(), options, log));
        }

        public void Start()
        {
            foreach (var s in _sources)
            {
                s.Start();
                _log.Info("source started: " + s.Name);
            }
            _started = true;
            _log.Info("sensor started: writing to " + CarModel.ChannelName + " as " + CarModel.ProviderName);
        }

        public void Stop()
        {
            if (!_started) return;
            _started = false;
            foreach (var s in _sources)
            {
                try { s.Stop(); } catch (Exception ex) { _log.Error("stopping " + s.Name + ": " + ex.Message); }
            }
            _log.Info("sensor stopped: " + _writer.Written + " events written, " + _writer.Failed + " refused by ETW");
        }

        public void Dispose()
        {
            Stop();
            _writer.Dispose();
        }
    }
}
