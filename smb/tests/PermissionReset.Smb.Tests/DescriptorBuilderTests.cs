using PermissionReset.Smb.Core;

namespace PermissionReset.Smb.Tests;

public class DescriptorBuilderTests
{
    [Theory]
    [InlineData("S-1-1-0")]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-5-21-1004336348-1177238915-682003330-512")]
    [InlineData("S-1-3-4")]
    [InlineData("S-1-0x123456789ABC-7")]
    public void SidsRoundTrip(string sid)
    {
        var b = SidFormat.Encode(sid);
        Assert.Equal(sid, SidFormat.Parse(b, out int len));
        Assert.Equal(b.Length, len);
    }

    [Theory]
    [InlineData("")]
    [InlineData("S-1")]
    [InlineData("X-1-5")]
    [InlineData("S-1-5-x")]
    [InlineData("S-1-281474976710656")]
    [InlineData("S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16")]
    public void BadSidsAreRefused(string sid) => Assert.Throws<FormatException>(() => SidFormat.Encode(sid));

    [Fact]
    public void ADescriptorDecodesToWhatWasBuilt()
    {
        var dacl = new[] { new Ace(AceTypes.Deny, 0, 0x1, "S-1-1-0"), new Ace(AceTypes.Allow, AceFlags.Inherited | AceFlags.ContainerInherit, 0x1f01ff, "S-1-5-32-544") };
        var sacl = new[] { new Ace(AceTypes.Audit, AceFlags.SuccessfulAccess | AceFlags.FailedAccess, 0x1, "S-1-1-0") };
        var sd = DescriptorBuilder.Build(Control.DaclProtected | Control.DaclAutoInherited, "S-1-5-32-544", "S-1-5-18", sacl, dacl);
        var d = Descriptor.Decode(sd);
        Assert.Equal("S-1-5-32-544", d.Owner);
        Assert.Equal("S-1-5-18", d.Group);
        Assert.Equal(Control.SelfRelative | Control.DaclPresent | Control.SaclPresent | Control.DaclProtected | Control.DaclAutoInherited, d.Control);
        Assert.Equal(dacl, d.Dacl!.Aces.Select(a => Ace.FromView(a)!.Value));
        Assert.Equal(sacl, d.Sacl!.Aces.Select(a => Ace.FromView(a)!.Value));
        Assert.Equal(2, d.Dacl.Revision);
    }

    [Fact]
    public void AbsentPartsHaveNoOffsetAndNoPresentBit()
    {
        var sd = DescriptorBuilder.Build(Control.SaclPresent, null, null, null, []);
        var d = Descriptor.Decode(sd);
        Assert.Null(d.Owner);
        Assert.Null(d.Group);
        Assert.Null(d.Sacl);
        Assert.NotNull(d.Dacl);
        Assert.Empty(d.Dacl!.Aces);                                    // an empty DACL, not a null one
        Assert.Equal(Control.SelfRelative | Control.DaclPresent, d.Control);
        Assert.Equal(0u, BitConverter.ToUInt32(sd, 4));
        Assert.Equal(0u, BitConverter.ToUInt32(sd, 12));
    }

    // ---- the descriptor size limit (Q4) ---------------------------------------------------------------

    // AuditAcesOfSize returns audit ACEs whose encoded ACL is exactly bytes long: 20-byte ACEs on
    // S-1-1-0 and 24-byte ones on S-1-5-32-545, so any multiple of 4 from 128 up is reachable.
    internal static Ace[] AuditAcesOfSize(int bytes, byte flags = AceFlags.SuccessfulAccess | AceFlags.FailedAccess)
    {
        int units = (bytes - 8) / 4, wide = units % 5, narrow = (units - 6 * wide) / 5;
        var aces = Enumerable.Range(0, narrow + wide)
            .Select(i => new Ace(AceTypes.Audit, flags, (uint)(0x1000 + i), i < narrow ? "S-1-1-0" : "S-1-5-32-545"))
            .ToArray();
        Assert.Equal(bytes, DescriptorBuilder.AclSize(aces));
        return aces;
    }

    [Fact]
    public void TheLimitIsOnTheWholeDescriptor()
    {
        DescriptorBuilder.CheckDescriptorSize(DescriptorBuilder.MaxDescriptorSize);
        var e = Assert.Throws<ArgumentException>(() => DescriptorBuilder.CheckDescriptorSize(DescriptorBuilder.MaxDescriptorSize + 1));
        Assert.Contains("65537 bytes", e.Message);
        Assert.Contains("65536-byte limit", e.Message);
    }

    [Fact]
    public void ASaclOnlyDescriptorOf65536BytesIsBuilt()
    {
        // A single-part SACL write: the 20-byte header and a 65,516-byte ACL, the largest the
        // array accepts.
        var aces = AuditAcesOfSize(65516);
        var sd = DescriptorBuilder.Build(Control.SaclProtected, null, null, aces, null);
        Assert.Equal(DescriptorBuilder.MaxDescriptorSize, sd.Length);
        Assert.Equal(aces, Descriptor.Decode(sd).Sacl!.Aces.Select(a => Ace.FromView(a)!.Value));
    }

    [Theory]
    [InlineData(65520)]
    [InlineData(65524)]
    [InlineData(65528)]
    [InlineData(65532)]
    public void AnAclTheOldPerAclCheckPassedIsRefused(int aclBytes)
    {
        // Q4: ACLs of 65,520-65,532 bytes fit the 16-bit ACL size field, so the old 65,535-byte
        // check passed them, and the array refused them with 87. Once in a descriptor they are over.
        var e = Assert.Throws<ArgumentException>(() =>
            DescriptorBuilder.Build(Control.SaclProtected, null, null, AuditAcesOfSize(aclBytes), null));
        Assert.Contains($"descriptor is {aclBytes + 20} bytes (SACL {aclBytes} bytes)", e.Message);
        Assert.Contains("65536-byte limit", e.Message);
    }

    [Fact]
    public void OwnerAndGroupCountAgainstTheLimit()
    {
        // The same 65,516-byte ACL that fits alone is over once the DACL call also carries owner
        // and group: the limit is the descriptor's, not a per-ACL constant.
        var aces = AuditAcesOfSize(65516).Select(a => a with { Type = AceTypes.Allow, Flags = 0 }).ToArray();
        DescriptorBuilder.Build(Control.DaclProtected, null, null, null, aces);
        var e = Assert.Throws<ArgumentException>(() =>
            DescriptorBuilder.Build(Control.DaclProtected, "S-1-5-32-544", "S-1-5-18", null, aces));
        Assert.Contains("descriptor is 65564 bytes (DACL 65516 bytes)", e.Message);
    }
}
