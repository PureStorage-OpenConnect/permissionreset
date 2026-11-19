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
}
