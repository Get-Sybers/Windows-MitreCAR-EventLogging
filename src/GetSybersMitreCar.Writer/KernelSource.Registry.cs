using System;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace GetSybersMitreCar.Writer
{
    public sealed partial class KernelSource
    {
        private CarProps RegistryProps(RegistryTraceData data, bool withValue)
        {
            var p = new CarProps();
            _processes.Describe(p, "registry", data.ProcessID, _host);
            string key, hive;
            RegistryHelper.Split(data.KeyName, out key, out hive);
            p.Set("key", key);
            p.Set("hive", hive);
            if (withValue) p.Set("value", data.ValueName);
            return p;
        }

        private void OnRegistryCreate(RegistryTraceData data)
        {
            try { Emit("registry", "add", RegistryProps(data, false)); }
            catch (Exception ex) { Fail("registry/add: " + ex.Message); }
        }

        private void OnRegistrySetValue(RegistryTraceData data)
        {
            try
            {
                var p = RegistryProps(data, true);
                string value, type;
                RegistryHelper.ReadValue(data.KeyName, data.ValueName, out value, out type);
                p.Set("data", value);
                p.Set("type", type);
                p.Set("new_content", value);
                Emit("registry", "value_edit", p);
            }
            catch (Exception ex) { Fail("registry/value_edit: " + ex.Message); }
        }

        private void OnRegistryDeleteKey(RegistryTraceData data)
        {
            try { Emit("registry", "remove", RegistryProps(data, false)); }
            catch (Exception ex) { Fail("registry/remove: " + ex.Message); }
        }

        private void OnRegistryDeleteValue(RegistryTraceData data)
        {
            try { Emit("registry", "remove", RegistryProps(data, true)); }
            catch (Exception ex) { Fail("registry/remove: " + ex.Message); }
        }

        private void OnRegistryAccess(RegistryTraceData data)
        {
            if (!_options.RegistryAccess) return;
            try { Emit("registry", "access", RegistryProps(data, true)); }
            catch (Exception ex) { Fail("registry/access: " + ex.Message); }
        }
    }
}
