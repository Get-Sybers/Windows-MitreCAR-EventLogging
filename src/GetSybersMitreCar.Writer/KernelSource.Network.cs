using System;
using Microsoft.Diagnostics.Tracing;

namespace GetSybersMitreCar.Writer
{
    public sealed partial class KernelSource
    {
        private CarProps FlowProps(TraceEvent data, string proto, string sip, int sport, string dip, int dport)
        {
            var p = new CarProps();
            var info = _processes.Describe(p, "flow", data.ProcessID, _host);
            if (info != null) { p.Set("exe", info.Exe); p.Set("uid", info.Sid); }
            p.Set("src_ip", sip);
            p.Set("src_port", sport);
            p.Set("dest_ip", dip);
            p.Set("dest_port", dport);
            p.Set("transport_protocol", proto);
            return p;
        }

        private void OnTcpStart(TraceEvent data, string direction, string sip, int sport, string dip, int dport)
        {
            try
            {
                var p = FlowProps(data, "tcp", sip, sport, dip, dport);
                p.Set("network_direction", direction);
                p.Set("start_time", Formats.Utc(data.TimeStamp));
                Emit("flow", "start", p);
            }
            catch (Exception ex) { Fail("flow/start: " + ex.Message); }
        }

        private void OnTcpEnd(TraceEvent data, string sip, int sport, string dip, int dport)
        {
            try
            {
                var p = FlowProps(data, "tcp", sip, sport, dip, dport);
                p.Set("end_time", Formats.Utc(data.TimeStamp));
                Emit("flow", "end", p);
            }
            catch (Exception ex) { Fail("flow/end: " + ex.Message); }
        }

        private void OnFlowMessage(TraceEvent data, string proto, string sip, int sport, string dip, int dport, int size, bool send)
        {
            if (!_options.FlowMessages) return;
            try
            {
                var p = FlowProps(data, proto, sip, sport, dip, dport);
                p.Set(send ? "out_bytes" : "in_bytes", size);
                Emit("flow", "message", p);
            }
            catch (Exception ex) { Fail("flow/message: " + ex.Message); }
        }
    }
}
