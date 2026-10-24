using System;
using Microsoft.Diagnostics.Tracing;

namespace GetSybersMitreCar.Writer
{
    public sealed partial class KernelSource
    {
        /// <summary>
        /// The flow object's properties: the owning process (hostname, fqdn, pid, ppid, image_path, exe, user, uid), the
        /// endpoints as the kernel reports them, this host's name on whichever endpoint is one of its own addresses, and
        /// what the sensor saw when the flow started.
        /// </summary>
        private CarProps FlowProps(TraceEvent data, string proto, string sip, int sport, string dip, int dport, FlowState flow)
        {
            var p = new CarProps();
            _processes.Describe(p, "flow", data.ProcessID, _host);
            p.Set("src_ip", sip);
            p.Set("src_port", sport);
            p.Set("dest_ip", dip);
            p.Set("dest_port", dport);
            p.Set("transport_protocol", proto);
            // An endpoint that is one of this host's own addresses is this host - no DNS, no reverse lookup.
            if (LocalAddresses.IsLocal(sip)) { p.Set("src_hostname", _host.HostName); p.Set("src_fqdn", _host.Fqdn); }
            if (LocalAddresses.IsLocal(dip)) { p.Set("dest_hostname", _host.HostName); p.Set("dest_fqdn", _host.Fqdn); }
            if (flow != null)
            {
                p.Set("network_direction", flow.Direction);
                p.Set("start_time", Formats.Utc(flow.StartUtc));
            }
            return p;
        }

        private void OnTcpStart(TraceEvent data, string direction, string sip, int sport, string dip, int dport)
        {
            try
            {
                var flow = _flows.Start("tcp", sip, sport, dip, dport, direction, data.TimeStamp.ToUniversalTime());
                var p = FlowProps(data, "tcp", sip, sport, dip, dport, flow);
                Emit("flow", "start", p);
            }
            catch (Exception ex) { Fail("flow/start: " + ex.Message); }
        }

        private void OnTcpEnd(TraceEvent data, string sip, int sport, string dip, int dport)
        {
            try
            {
                var flow = _flows.End("tcp", sip, sport, dip, dport);
                var p = FlowProps(data, "tcp", sip, sport, dip, dport, flow);
                p.Set("end_time", Formats.Utc(data.TimeStamp));
                if (flow != null)
                {
                    // Totals counted on this flow since its start, from the kernel's send and receive events.
                    lock (flow)
                    {
                        p.Set("in_bytes", flow.InBytes);
                        p.Set("out_bytes", flow.OutBytes);
                        p.Set("packet_count", flow.Packets);
                    }
                }
                Emit("flow", "end", p);
            }
            catch (Exception ex) { Fail("flow/end: " + ex.Message); }
        }

        private void OnFlowMessage(TraceEvent data, string proto, string sip, int sport, string dip, int dport, int size, bool send)
        {
            try
            {
                var flow = proto == "tcp" ? _flows.Find(proto, sip, sport, dip, dport) : null;
                if (flow != null) flow.Count(send, size);                      // counted whether or not messages are written
                if (!_options.FlowMessages) return;
                var p = FlowProps(data, proto, sip, sport, dip, dport, flow);
                p.Set(send ? "out_bytes" : "in_bytes", size);
                Emit("flow", "message", p);
            }
            catch (Exception ex) { Fail("flow/message: " + ex.Message); }
        }
    }
}
