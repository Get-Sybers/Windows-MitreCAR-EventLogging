using System;

namespace GetSybersMitreCar.Writer
{
    /// <summary>The observing host, named the way CAR's hostname/fqdn properties expect.</summary>
    public sealed class HostIdentity
    {
        public string HostName { get; private set; }
        /// <summary>host.domain when the machine is domain-joined; null (written empty) otherwise.</summary>
        public string Fqdn { get; private set; }

        public static HostIdentity Current()
        {
            var id = new HostIdentity { HostName = Environment.MachineName };
            try
            {
                var ip = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
                if (!string.IsNullOrEmpty(ip.DomainName)) id.Fqdn = ip.HostName + "." + ip.DomainName;
            }
            catch (Exception) { /* fqdn stays empty: not observed */ }
            return id;
        }
    }
}
