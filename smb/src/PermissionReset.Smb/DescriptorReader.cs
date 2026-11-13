using System.Runtime.Versioning;

namespace PermissionReset.Smb;

// IDescriptorReader is what inspect needs from the OS: enable a privilege, read one object's
// descriptor. Failures are Win32Exceptions whose message names the failed step. The seam exists so
// the CLI's records and exit codes can be tested on any OS; it is not a second implementation.
interface IDescriptorReader
{
    void EnablePrivilege(string name);
    byte[] Read(string path, bool withSacl);
}

[SupportedOSPlatform("windows")]
sealed class Win32DescriptorReader : IDescriptorReader
{
    public void EnablePrivilege(string name) => Win32Security.EnablePrivilege(name);
    public byte[] Read(string path, bool withSacl) => Win32Security.ReadDescriptor(path, withSacl);
}
