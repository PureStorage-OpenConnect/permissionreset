using System.ComponentModel;
using System.Text.Json;

namespace PermissionReset.Smb.Tests;

// inspect's records and exit codes, through a fake reader. The Win32 reads themselves are checked on
// hardware (benchmarks/qual-smb-inspect-20261109/); these pin what the CLI does with their results.
public class InspectCliTests
{
    // The smallest valid descriptor: a self-relative header with nothing in it.
    static readonly byte[] EmptySd = [1, 0, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    sealed class FakeReader : IDescriptorReader
    {
        public HashSet<string> Missing { get; } = [];
        public Dictionary<string, Exception> Fails { get; } = [];
        public List<string> Enabled { get; } = [];
        public List<(string Path, bool WithSacl)> Reads { get; } = [];

        public void EnablePrivilege(string name)
        {
            if (Missing.Contains(name))
                throw new Win32Exception(1300, $"this account does not hold {name}; run elevated as an account that does");
            Enabled.Add(name);
        }

        public byte[] Read(string path, bool withSacl)
        {
            Reads.Add((path, withSacl));
            return Fails.TryGetValue(path, out var e) ? throw e : EmptySd;
        }
    }

    static (int Code, string Out, string Err) Run(FakeReader r, params string[] args)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        int code = Cli.Run(args, o, e, r);
        return (code, o.ToString(), e.ToString());
    }

    static List<JsonElement> Records(string stdout) =>
        stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
              .Select(l => JsonDocument.Parse(l).RootElement.Clone()).ToList();

    [Fact]
    public void MissingBackupPrivilegeExitsOneAndReadsNothing()
    {
        var r = new FakeReader();
        r.Missing.Add("SeBackupPrivilege");
        var (code, stdout, stderr) = Run(r, "inspect", @"\\array\share\a.txt");

        Assert.Equal(1, code);
        Assert.Empty(stdout);
        Assert.Empty(r.Reads);
        Assert.Contains("does not hold SeBackupPrivilege", stderr);
        Assert.Contains("Win32 error 1300", stderr);
        Assert.DoesNotContain("--help", stderr); // not a usage error
    }

    [Fact]
    public void MissingBackupPrivilegeWithNoSaclExitsOne()
    {
        var r = new FakeReader();
        r.Missing.Add("SeBackupPrivilege");
        var (code, stdout, _) = Run(r, "inspect", "--no-sacl", @"\\array\share\a.txt");

        Assert.Equal(1, code);
        Assert.Empty(stdout);
        Assert.Empty(r.Reads);
    }

    [Fact]
    public void MissingSecurityPrivilegeExitsOneUnlessNoSacl()
    {
        var r = new FakeReader();
        r.Missing.Add("SeSecurityPrivilege");
        var (code, _, stderr) = Run(r, "inspect", @"\\array\share\a.txt");
        Assert.Equal(1, code);
        Assert.Contains("SeSecurityPrivilege", stderr);
        Assert.Empty(r.Reads);

        var (code2, stdout2, _) = Run(r, "inspect", "--no-sacl", @"\\array\share\a.txt");
        Assert.Equal(0, code2);
        Assert.Single(Records(stdout2));
        Assert.DoesNotContain("SeSecurityPrivilege", r.Enabled);
    }

    [Fact]
    public void FailedOpenRecordCarriesCodeAndOmitsSaclRead()
    {
        var r = new FakeReader();
        r.Fails[@"\\array\share\gone.txt"] = new Win32Exception(2, "open: The system cannot find the file specified.");
        var (code, stdout, _) = Run(r, "inspect", @"\\array\share\gone.txt", @"\\array\share\a.txt");

        Assert.Equal(1, code);
        var recs = Records(stdout);
        Assert.Equal(2, recs.Count);

        var bad = recs[0];
        Assert.Equal(@"\\array\share\gone.txt", bad.GetProperty("path").GetString());
        Assert.Equal("open: The system cannot find the file specified.", bad.GetProperty("error").GetString());
        Assert.Equal(2, bad.GetProperty("win32_error").GetInt32());
        Assert.False(bad.TryGetProperty("sacl_read", out _));
        Assert.False(bad.TryGetProperty("descriptor", out _));

        // The good path after it still gets its record.
        var good = recs[1];
        Assert.True(good.GetProperty("sacl_read").GetBoolean());
        Assert.True(good.TryGetProperty("descriptor", out _));
        Assert.False(good.TryGetProperty("error", out _));
        Assert.False(good.TryGetProperty("win32_error", out _));
    }

    [Fact]
    public void UndecodableDescriptorHasErrorButNoWin32Code()
    {
        var r = new FakeReader();
        r.Fails["x"] = new PermissionReset.Smb.Core.DescriptorFormatException("descriptor revision 2, want 1");
        var (code, stdout, _) = Run(r, "inspect", "x");

        Assert.Equal(1, code);
        var rec = Assert.Single(Records(stdout));
        Assert.Equal("descriptor revision 2, want 1", rec.GetProperty("error").GetString());
        Assert.False(rec.TryGetProperty("win32_error", out _));
        Assert.False(rec.TryGetProperty("sacl_read", out _));
    }

    [Fact]
    public void NoSaclRecordSaysSaclWasNotRead()
    {
        var r = new FakeReader();
        var (code, stdout, _) = Run(r, "inspect", "--no-sacl", "a");

        Assert.Equal(0, code);
        Assert.False(Assert.Single(Records(stdout)).GetProperty("sacl_read").GetBoolean());
        Assert.Equal([("a", false)], r.Reads);
    }

    [Fact]
    public void UsageErrorsStayExitTwo()
    {
        Assert.Equal(2, Run(new FakeReader(), "inspect").Code);
        Assert.Equal(2, Run(new FakeReader(), "inspect", "--bogus", "a").Code);
    }

    [Fact]
    public void Win32ErrorKeepsTheSystemText()
    {
        if (!OperatingSystem.IsWindows()) return; // the system text is Windows' own
        var e = Win32Security.Error(5, "open");
        Assert.Equal(5, e.NativeErrorCode);
        Assert.StartsWith("open: ", e.Message);
        Assert.True(e.Message.Length > "open: ".Length);
    }
}
