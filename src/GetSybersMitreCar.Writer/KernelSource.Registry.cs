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

        /// <summary>data / type of the named value as it is now (the kernel event carries neither).</summary>
        private static void SetValueData(CarProps p, RegistryTraceData data, bool asNewContent)
        {
            string value, type;
            RegistryHelper.ReadValue(data.KeyName, data.ValueName, out value, out type);
            p.Set("data", value);
            p.Set("type", type);
            if (asNewContent) p.Set("new_content", value);
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
                SetValueData(p, data, true);
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

        /// <summary>A key open (no value) or a value query (the value's data and type are read live).</summary>
        private void OnRegistryAccess(RegistryTraceData data, bool valueQuery)
        {
            if (!_options.RegistryAccess) return;
            try
            {
                var p = RegistryProps(data, valueQuery);
                if (valueQuery) SetValueData(p, data, false);
                Emit("registry", "access", p);
            }
            catch (Exception ex) { Fail("registry/access: " + ex.Message); }
        }
    }
}
