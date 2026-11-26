using System.Buffers.Binary;

namespace PermissionReset.Smb.Core;

// SecurityInformation is the SECURITY_INFORMATION bits a write names (MS-DTYP 2.4.7). A write
// passes only the parts it changes (smb/DESIGN-write-path.md, 1.4), and always states the DACL's
// protection explicitly (3.1) rather than leaving it to the server's default.
public static class SecurityInformation
{
    public const uint Owner = 0x1, Group = 0x2, Dacl = 0x4, Sacl = 0x8;
    public const uint ProtectedDacl = 0x80000000, ProtectedSacl = 0x40000000,
        UnprotectedDacl = 0x20000000, UnprotectedSacl = 0x10000000;
}

// Control holds the SECURITY_DESCRIPTOR_CONTROL bits the write path reads and sets.
public static class Control
{
    public const ushort DaclPresent = 0x0004, SaclPresent = 0x0010,
        DaclAutoInherited = 0x0400, SaclAutoInherited = 0x0800,
        DaclProtected = 0x1000, SaclProtected = 0x2000, SelfRelative = 0x8000;
}

// DescriptorBuilder encodes a self-relative security descriptor (MS-DTYP 2.4.6) from the parts a
// write sets. It is the inverse of Descriptor.Decode for the simple ACEs the write path writes, and
// is managed code, so the bytes a write sends are tested on any OS.
public static class DescriptorBuilder
{
    const byte AclRevision = 2;

    // MaxDescriptorSize is the largest self-relative descriptor one write may send. FlashArray's
    // limit is on the whole descriptor, not on each ACL: a single-part SACL write holds 65,516
    // bytes of ACL after the 20-byte header, and the array refuses anything larger with error 87
    // (Q4, smb/DESIGN-sacl-write.md 4.5). The limit is checked on the descriptor, so a write that
    // also carries owner or group has that much less room for its ACL.
    public const int MaxDescriptorSize = 65536;

    // CheckDescriptorSize refuses a descriptor of size bytes over MaxDescriptorSize; parts says
    // what it holds, for the message.
    public static void CheckDescriptorSize(int size, string parts = "")
    {
        if (size > MaxDescriptorSize)
            throw new ArgumentException($"descriptor is {size} bytes{parts}, over the {MaxDescriptorSize}-byte limit");
    }

    // Build returns the descriptor. A null part is absent (its offset is 0); the DACL and SACL
    // present bits are set from whether that ACL is given, and SelfRelative always. The whole
    // descriptor is size-checked before either ACL is encoded.
    public static byte[] Build(ushort control, string? owner, string? group, IReadOnlyList<Ace>? sacl, IReadOnlyList<Ace>? dacl)
    {
        byte[]? o = owner is null ? null : SidFormat.Encode(owner);
        byte[]? g = group is null ? null : SidFormat.Encode(group);
        int? saclSize = sacl is null ? null : AclSize(sacl), daclSize = dacl is null ? null : AclSize(dacl);
        string parts = string.Concat(saclSize is null ? "" : $", SACL {saclSize} bytes", daclSize is null ? "" : $", DACL {daclSize} bytes");
        CheckDescriptorSize(20 + (o?.Length ?? 0) + (g?.Length ?? 0) + (saclSize ?? 0) + (daclSize ?? 0),
            parts.Length == 0 ? "" : $" ({parts[2..]})");
        byte[]? s = sacl is null ? null : Acl(sacl);
        byte[]? d = dacl is null ? null : Acl(dacl);
        control |= Control.SelfRelative;
        control = (ushort)(sacl is null ? control & ~Control.SaclPresent : control | Control.SaclPresent);
        control = (ushort)(dacl is null ? control & ~Control.DaclPresent : control | Control.DaclPresent);

        var buf = new byte[20 + (o?.Length ?? 0) + (g?.Length ?? 0) + (s?.Length ?? 0) + (d?.Length ?? 0)];
        buf[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(2), control);
        int at = 20;
        uint Put(byte[]? part)
        {
            if (part is null) return 0;
            part.CopyTo(buf, at);
            int off = at;
            at += part.Length;
            return (uint)off;
        }
        // Order: owner, group, SACL, DACL, as Windows lays a self-relative descriptor out.
        uint offOwner = Put(o), offGroup = Put(g), offSacl = Put(s), offDacl = Put(d);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(4), offOwner);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(8), offGroup);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(12), offSacl);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(16), offDacl);
        return buf;
    }

    // AclSize is the encoded size of Acl(aces): the 8-byte header and, per ACE, 8 bytes and its SID.
    public static int AclSize(IReadOnlyList<Ace> aces) => 8 + aces.Sum(a => 8 + SidFormat.Encode(a.Sid).Length);

    // Acl encodes an ACL (MS-DTYP 2.4.5) of simple ACEs, in the order given. Its own check is the
    // 16-bit AclSize field; the array's tighter limit is on the descriptor (CheckDescriptorSize).
    public static byte[] Acl(IReadOnlyList<Ace> aces)
    {
        var bodies = aces.Select(a =>
        {
            var sid = SidFormat.Encode(a.Sid);
            var ace = new byte[8 + sid.Length];
            ace[0] = (byte)a.Type;
            ace[1] = a.Flags;
            BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2), (ushort)ace.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(4), a.Mask);
            sid.CopyTo(ace, 8);
            return ace;
        }).ToList();
        int size = 8 + bodies.Sum(b => b.Length);
        if (size > ushort.MaxValue) throw new ArgumentException($"ACL of {aces.Count} ACEs is {size} bytes, over the 65535 bytes an ACL's size field holds");
        var acl = new byte[size];
        acl[0] = AclRevision;
        BinaryPrimitives.WriteUInt16LittleEndian(acl.AsSpan(2), (ushort)size);
        BinaryPrimitives.WriteUInt16LittleEndian(acl.AsSpan(4), (ushort)aces.Count);
        int at = 8;
        foreach (var b in bodies) { b.CopyTo(acl, at); at += b.Length; }
        return acl;
    }
}
