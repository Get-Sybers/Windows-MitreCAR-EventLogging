using System;
using System.ServiceProcess;
using System.Threading;

namespace GetSybersMitreCar.Writer
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            string error;
            var options = SensorOptions.Parse(args, out error);
            if (error != null) { Console.Error.WriteLine(error); Usage(); return 2; }
            if (args.Length == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "/?")) { Usage(); return 0; }

            if (options.SelfTest) return SelfTest(options);

            if (!options.Console)
            {
                ServiceBase.Run(new SensorService());
                return 0;
            }

            var log = new ConsoleLog();
            using (var sensor = new Sensor(log, options))
            {
                try { sensor.Start(); }
                catch (Exception ex) { log.Error("sensor failed to start: " + ex); return 1; }
                var stop = new ManualResetEvent(false);
                Console.CancelKeyPress += (s, e) => { e.Cancel = true; stop.Set(); };
                if (options.DurationSeconds > 0) stop.WaitOne(TimeSpan.FromSeconds(options.DurationSeconds)); else stop.WaitOne();
                sensor.Stop();
            }
            return 0;
        }

        /// <summary>
        /// Channel self-test: for every EventID (or the given ones) write one event whose every property holds its
        /// own name, then one whose every property is empty, through the same EventWrite path the live sensor uses.
        /// </summary>
        private static int SelfTest(SensorOptions options)
        {
            using (var writer = new CarEventWriter())
            {
                int n = 0;
                foreach (var e in CarModel.Events)
                {
                    if (options.SelfTestIds.Count > 0 && !options.SelfTestIds.Contains(e.Id)) continue;
                    var o = CarModel.Object(e.Object);
                    var full = new CarProps();
                    foreach (var f in o.Fields) full.Set(f, f);
                    if (!writer.Write(e.Object, e.Action, full)) { Console.Error.WriteLine("EventWrite failed for " + e.Id + " (Win32 " + writer.LastError + ")"); return 1; }
                    if (!writer.Write(e.Object, e.Action, new CarProps())) { Console.Error.WriteLine("EventWrite failed for " + e.Id + " (Win32 " + writer.LastError + ")"); return 1; }
                    n += 2;
                }
                Console.WriteLine("selftest: wrote " + n + " events to " + CarModel.ChannelName);
            }
            return 0;
        }

        private static void Usage()
        {
            Console.Error.WriteLine("GetSybersMitreCar.Writer [--console] [--duration <seconds>] [--threads] [--file-reads] [--flow-messages] [--registry-access]");
            Console.Error.WriteLine("GetSybersMitreCar.Writer --selftest [eventid ...]");
            Console.Error.WriteLine("  (no arguments)        run as the GetSybersMitreCar Windows service (flags may follow in the service's binPath)");
            Console.Error.WriteLine("  --console             run in the foreground until Ctrl+C (needs an elevated prompt)");
            Console.Error.WriteLine("  --duration <seconds>  run in the foreground for a fixed time, then exit");
            Console.Error.WriteLine("  --threads             also emit thread/create and thread/terminate for in-process threads (remote_create is always on)");
            Console.Error.WriteLine("  --file-reads          also emit file/read");
            Console.Error.WriteLine("  --flow-messages       also emit flow/message for every TCP/UDP send and receive");
            Console.Error.WriteLine("  --registry-access     also emit registry/access for every key open and value query");
            Console.Error.WriteLine("  --selftest            write two events per EventID (properties = their names, then all empty) and exit");
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
            // flags may be given on the service's binPath (sc create ... binPath= "...exe --threads")
            var cmd = Environment.GetCommandLineArgs();
            var rest = new string[Math.Max(0, cmd.Length - 1)];
            Array.Copy(cmd, 1, rest, 0, rest.Length);
            string error;
            var options = SensorOptions.Parse(rest, out error);
            _sensor = new Sensor(new EventLogLog(), options);
            _sensor.Start();
        }
        protected override void OnStop()
        {
            if (_sensor != null) { _sensor.Dispose(); _sensor = null; }
        }
    }
}
