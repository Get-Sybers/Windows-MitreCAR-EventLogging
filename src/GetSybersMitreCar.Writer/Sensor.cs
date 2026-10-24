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

    /// <summary>The sensor: one event writer, one or more live sources.</summary>
    public sealed class Sensor : IDisposable
    {
        private readonly ILog _log;
        private readonly CarEventWriter _writer;
        private readonly List<IEventSource> _sources = new List<IEventSource>();
        private bool _started;

        public Sensor(ILog log)
        {
            _log = log;
            _writer = new CarEventWriter();
            _sources.Add(new KernelProcessSource(_writer, log));
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
            _log.Info("sensor stopped: " + _writer.Written + " events written, " + _writer.Failed + " failed");
        }

        public void Dispose()
        {
            Stop();
            _writer.Dispose();
        }
    }
}
