using System.Buffers.Binary;
using PermissionReset.Smb.Core;

namespace PermissionReset.Smb.Tests;

public class DescriptorTests
{
    // Builders for MS-DTYP binary structures.
    static byte[] SidBytes(ulong authority, params uint[] subs)
    {
        var b = new byte[8 + 4 * subs.Length];
        b[0] = 1; b[1] = (byte)subs.Length;
        for (int i = 0; i < 6; i++) b[2 + i] = (byte)(authority >> (8 * (5 - i)));
        for (int i = 0; i < subs.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8 + 4 * i), subs[i]);
        return b;
    }

    static byte[] Ace(byte type, byte flags, uint mask, byte[] sid)
    {
        var b = new byte[8 + sid.Length];
        b[0] = type; b[1] = flags;
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(2), (ushort)b.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), mask);
        sid.CopyTo(b, 8);
        return b;
    }

    static byte[] Acl(params byte[][] aces)
    {
        int size = 8 + aces.Sum(a => a.Length);
        var b = new byte[size];
        b[0] = 2;
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(2), (ushort)size);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(4), (ushort)aces.Length);
        int at = 8;
        foreach (var a in aces) { a.CopyTo(b, at); at += a.Length; }
        return b;
    }

    static byte[] Sd(ushort control, byte[]? owner, byte[]? group, byte[]? sacl, byte[]? dacl)
    {
        var parts = new List<byte>(new byte[20]);
        uint Put(byte[]? x) { if (x is null) return 0; uint off = (uint)parts.Count; parts.AddRange(x); return off; }
        uint o = Put(owner), g = Put(group), s = Put(sacl), d = Put(dacl);
        var b = parts.ToArray();
        b[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(2), control);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), o);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8), g);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(12), s);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(16), d);
        return b;
    }

    static readonly byte[] Admins = SidBytes(5, 32, 544), Everyone = SidBytes(1, 0), User = SidBytes(5, 21, 1, 2, 3, 1105);

    [Fact]
    public void DecodesWhatTheArrayStored()
    {
        // SelfRelative | DaclPresent | SaclPresent | DaclAutoInherited | SaclProtected
        ushort control = 0x8000 | 0x0004 | 0x0010 | 0x0400 | 0x2000;
        var sd = Sd(control, User, Admins,
            Acl(Ace(2, 0xC3, 0x1f01ff, Everyone)),
            Acl(Ace(0, 0x00, 0x1f01ff, Admins), Ace(0, 0x13, 0x1200a9, User)));

        var d = Descriptor.Decode(sd);
        Assert.Equal("S-1-5-21-1-2-3-1105", d.Owner);
        Assert.Equal("S-1-5-32-544", d.Group);
        Assert.Equal(["DaclPresent", "SaclPresent", "DaclAutoInherited", "SaclProtected", "SelfRelative"], d.ControlFlags);
        Assert.Equal(2, d.Dacl!.Aces.Count);
        Assert.False(d.Dacl.Aces[0].Inherited);
        var inh = d.Dacl.Aces[1];
        Assert.Equal("Allow", inh.Type);
        Assert.True(inh.Inherited);
        Assert.Equal(["OI", "CI", "ID"], inh.FlagNames);
        Assert.Equal(0x1200a9u, inh.Mask);
        var audit = Assert.Single(d.Sacl!.Aces);
        Assert.Equal("Audit", audit.Type);
        Assert.Equal("S-1-1-0", audit.Sid);
        Assert.Equal(["OI", "CI", "SA", "FA"], audit.FlagNames);
        Assert.Equal(sd, Convert.FromBase64String(d.Raw));
    }

    [Fact]
    public void AbsentAndEmptyAclsDiffer()
    {
        // DACL present but empty (deny everyone) is not the same as no DACL (allow everyone).
        var empty = Descriptor.Decode(Sd(0x8004, Admins, Admins, null, Acl()));
        Assert.NotNull(empty.Dacl);
        Assert.Empty(empty.Dacl!.Aces);
        Assert.Null(empty.Sacl);
        var none = Descriptor.Decode(Sd(0x8000, Admins, Admins, null, null));
        Assert.Null(none.Dacl);
    }

    [Fact]
    public void KeepsUnknownBitsVisible()
    {
        Assert.Equal(["SelfRelative", "0x0040"], Descriptor.DescribeControl(0x8040));
        Assert.Equal(["ID", "0x20"], AceView.DescribeFlags(0x30));
    }

    [Fact]
    public void KeepsAnUndecodedAceAsBytes()
    {
        var obj = new byte[] { 0x05, 0x00, 12, 0, 1, 2, 3, 4, 5, 6, 7, 8 }; // ACCESS_ALLOWED_OBJECT_ACE
        var d = Descriptor.Decode(Sd(0x8004, null, null, null, Acl(obj)));
        var a = Assert.Single(d.Dacl!.Aces);
        Assert.Equal("0x05", a.Type);
        Assert.Null(a.Sid);
        Assert.Equal(Convert.ToBase64String(obj[4..]), a.Body);
    }

    [Theory]
    [InlineData(new byte[] { 1, 0, 4, 0x80 }, "shorter than its 20-byte header")]
    [InlineData(new byte[] { 2, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, "revision 2")]
    [InlineData(new byte[] { 1, 0, 4, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, "not self-relative")]
    [InlineData(new byte[] { 1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 0, 0, 0 }, "past the 20-byte")]
    public void RefusesMalformed(byte[] sd, string want)
    {
        var e = Assert.Throws<DescriptorFormatException>(() => Descriptor.Decode(sd));
        Assert.Contains(want, e.Message);
    }

    [Fact]
    public void RefusesAnAceThatOverrunsItsAcl()
    {
        var acl = Acl(Ace(0, 0, 1, Admins));
        BinaryPrimitives.WriteUInt16LittleEndian(acl.AsSpan(8 + 2), 200);
        var e = Assert.Throws<DescriptorFormatException>(() => Descriptor.Decode(Sd(0x8004, null, null, null, acl)));
        Assert.Contains("does not fit the ACL", e.Message);
    }
}
