using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.NetworkInformation;

namespace GetSybersMitreCar.Writer
{
    /// <summary>A TCP flow the sensor saw start: what the connect/accept showed, and the bytes counted on it since.</summary>
    public sealed class FlowState
    {
        public string Direction;
        public DateTime StartUtc;
        public long InBytes;
        public long OutBytes;
        public long Packets;

        public void Count(bool send, int size)
        {
            lock (this)
            {
                if (send) OutBytes += size; else InBytes += size;
                Packets++;
            }
        }
    }

    /// <summary>
    /// The TCP flows the sensor has seen start, keyed by their endpoints in either orientation, so the end and message
    /// events of the same flow carry what was observed at its start and the bytes counted since.
    /// </summary>
    public sealed class FlowTable
    {
        private readonly ConcurrentDictionary<string, FlowState> _flows = new ConcurrentDictionary<string, FlowState>(StringComparer.Ordinal);

        private static string Key(string proto, string a, int ap, string b, int bp) { return proto + "|" + a + ":" + ap + ">" + b + ":" + bp; }

        public FlowState Start(string proto, string sip, int sport, string dip, int dport, string direction, DateTime startUtc)
        {
            if (_flows.Count > 100000) _flows.Clear();
            var state = new FlowState { Direction = direction, StartUtc = startUtc };
            _flows[Key(proto, sip, sport, dip, dport)] = state;
            return state;
        }

        public FlowState Find(string proto, string sip, int sport, string dip, int dport)
        {
            FlowState state;
            if (_flows.TryGetValue(Key(proto, sip, sport, dip, dport), out state)) return state;
            if (_flows.TryGetValue(Key(proto, dip, dport, sip, sport), out state)) return state;
            return null;
        }

        public FlowState End(string proto, string sip, int sport, string dip, int dport)
        {
            FlowState state;
            if (_flows.TryRemove(Key(proto, sip, sport, dip, dport), out state)) return state;
            if (_flows.TryRemove(Key(proto, dip, dport, sip, sport), out state)) return state;
            return null;
        }
    }

    /// <summary>The IP addresses this host holds right now, so a flow endpoint on this machine can be named without any lookup.</summary>
    public static class LocalAddresses
    {
        private static readonly object Gate = new object();
        private static HashSet<string> _addresses;
        private static DateTime _loaded;

        public static bool IsLocal(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;
            if (ip.StartsWith("127.", StringComparison.Ordinal) || ip == "::1") return true;
            return Current().Contains(Strip(ip));
        }

        private static HashSet<string> Current()
        {
            lock (Gate)
            {
                if (_addresses != null && (DateTime.UtcNow - _loaded).TotalSeconds < 60) return _addresses;
                var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                        foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                            set.Add(Strip(unicast.Address.ToString()));
                }
                catch (Exception) { }
                _addresses = set;
                _loaded = DateTime.UtcNow;
                return set;
            }
        }

        /// <summary>"fe80::1%12" -> "fe80::1" (the kernel event carries no scope id).</summary>
        private static string Strip(string ip)
        {
            int percent = ip.IndexOf('%');
            return percent < 0 ? ip : ip.Substring(0, percent);
        }
    }
}
