using System;
using System.ServiceProcess;
using System.Threading;

namespace GetSybersMitreCar.Writer
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            bool console = false;
            int duration = 0;
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--console":
                        console = true;
                        break;
                    case "--duration":
                        if (i + 1 >= args.Length || !int.TryParse(args[++i], out duration)) { Usage(); return 2; }
                        console = true;
                        break;
                    case "-h":
                    case "/?":
                    case "--help":
                        Usage();
                        return 0;
                    default:
                        Console.Error.WriteLine("unknown argument: " + args[i]);
                        Usage();
                        return 2;
                }
            }

            if (!console)
            {
                ServiceBase.Run(new SensorService());
                return 0;
            }

            var log = new ConsoleLog();
            using (var sensor = new Sensor(log))
            {
                try
                {
                    sensor.Start();
                }
                catch (Exception ex)
                {
                    log.Error("sensor failed to start: " + ex);
                    return 1;
                }
                var stop = new ManualResetEvent(false);
                Console.CancelKeyPress += (s, e) => { e.Cancel = true; stop.Set(); };
                if (duration > 0) stop.WaitOne(TimeSpan.FromSeconds(duration)); else stop.WaitOne();
                sensor.Stop();
            }
            return 0;
        }

        private static void Usage()
        {
            Console.Error.WriteLine("GetSybersMitreCar.Writer [--console] [--duration <seconds>]");
            Console.Error.WriteLine("  (no arguments)        run as the GetSybersMitreCar Windows service");
            Console.Error.WriteLine("  --console             run in the foreground until Ctrl+C (needs an elevated prompt)");
            Console.Error.WriteLine("  --duration <seconds>  run in the foreground for a fixed time, then exit");
        }
    }

    public interface ILog
    {
        void Info(string message);
        void Error(string message);
    }

    public sealed class ConsoleLog : ILog
    {
        public void Info(string message) { Console.WriteLine(DateTime.UtcNow.ToString("HH:mm:ss.fff") + " " + message); }
        public void Error(string message) { Console.Error.WriteLine(DateTime.UtcNow.ToString("HH:mm:ss.fff") + " ERROR " + message); }
    }

    /// <summary>Service-mode log: the Application event log under the sensor's own source.</summary>
    public sealed class EventLogLog : ILog
    {
        private const string Source = "GetSybersMitreCar";
        public void Info(string message) { Write(message, System.Diagnostics.EventLogEntryType.Information); }
        public void Error(string message) { Write(message, System.Diagnostics.EventLogEntryType.Error); }
        private static void Write(string message, System.Diagnostics.EventLogEntryType type)
        {
            try
            {
                if (!System.Diagnostics.EventLog.SourceExists(Source)) System.Diagnostics.EventLog.CreateEventSource(Source, "Application");
                System.Diagnostics.EventLog.WriteEntry(Source, message, type);
            }
            catch (Exception) { /* nothing better to do without a log */ }
        }
    }

    public sealed class SensorService : ServiceBase
    {
        private Sensor _sensor;
        public SensorService() { ServiceName = "GetSybersMitreCar"; CanStop = true; AutoLog = false; }
        protected override void OnStart(string[] args)
        {
            _sensor = new Sensor(new EventLogLog());
            _sensor.Start();
        }
        protected override void OnStop()
        {
            if (_sensor != null) { _sensor.Dispose(); _sensor = null; }
        }
    }
}
