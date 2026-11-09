using System.Buffers.Binary;
using System.Text;

namespace PermissionReset.Smb.Core;

// Descriptor is a decoded raw security descriptor: exactly what the array returned, with nothing
// normalized away. It is the verification primitive (decision record, section 8 question 5): the
// owner, group, control flags, and each ACE of the DACL and SACL as stored, plus the raw bytes so
// two reads can be compared byte for byte. The parser is managed code with no Win32 dependency,
// so it runs and is tested on any OS.
public sealed record Descriptor(
    string? Owner,
    string? Group,
    ushort Control,
    IReadOnlyList<string> ControlFlags,
    AclView? Dacl,
    AclView? Sacl,
    string Raw)
{
    const ushort SelfRelative = 0x8000, DaclPresent = 0x0004, SaclPresent = 0x0010;

    // Decode a self-relative SECURITY_DESCRIPTOR (MS-DTYP 2.4.6), as GetKernelObjectSecurity
    // returns it. Malformed input throws DescriptorFormatException; nothing is guessed.
    public static Descriptor Decode(ReadOnlySpan<byte> sd)
    {
        if (sd.Length < 20) throw new DescriptorFormatException($"descriptor is {sd.Length} bytes, shorter than its 20-byte header");
        if (sd[0] != 1) throw new DescriptorFormatException($"descriptor revision {sd[0]}, want 1");
        ushort control = BinaryPrimitives.ReadUInt16LittleEndian(sd[2..]);
        if ((control & SelfRelative) == 0) throw new DescriptorFormatException("descriptor is not self-relative");
        uint offOwner = BinaryPrimitives.ReadUInt32LittleEndian(sd[4..]);
        uint offGroup = BinaryPrimitives.ReadUInt32LittleEndian(sd[8..]);
        uint offSacl = BinaryPrimitives.ReadUInt32LittleEndian(sd[12..]);
        uint offDacl = BinaryPrimitives.ReadUInt32LittleEndian(sd[16..]);
        return new Descriptor(
            offOwner == 0 ? null : SidFormat.Parse(At(sd, offOwner, "owner"), out _),
            offGroup == 0 ? null : SidFormat.Parse(At(sd, offGroup, "group"), out _),
            control,
            DescribeControl(control),
            (control & DaclPresent) != 0 && offDacl != 0 ? AclView.Parse(At(sd, offDacl, "DACL")) : null,
            (control & SaclPresent) != 0 && offSacl != 0 ? AclView.Parse(At(sd, offSacl, "SACL")) : null,
            Convert.ToBase64String(sd));
    }

    static ReadOnlySpan<byte> At(ReadOnlySpan<byte> sd, uint off, string what) =>
        off >= sd.Length ? throw new DescriptorFormatException($"{what} offset {off} is past the {sd.Length}-byte descriptor") : sd[(int)off..];

    static readonly (ushort Bit, string Name)[] ControlNames =
    [
        (0x0001, "OwnerDefaulted"),
        (0x0002, "GroupDefaulted"),
        (0x0004, "DaclPresent"),
        (0x0008, "DaclDefaulted"),
        (0x0010, "SaclPresent"),
        (0x0020, "SaclDefaulted"),
        (0x0100, "DaclAutoInheritRequired"),
        (0x0200, "SaclAutoInheritRequired"),
        (0x0400, "DaclAutoInherited"),
        (0x0800, "SaclAutoInherited"),
        (0x1000, "DaclProtected"),
        (0x2000, "SaclProtected"),
        (0x4000, "RMControlValid"),
        (0x8000, "SelfRelative"),
    ];

    public static IReadOnlyList<string> DescribeControl(ushort control)
    {
        var names = new List<string>();
        ushort known = 0;
        foreach (var (bit, name) in ControlNames)
        {
            known |= bit;
            if ((control & bit) != 0) names.Add(name);
        }
        if ((control & ~known) != 0) names.Add($"0x{control & ~known:x4}");
        return names;
    }
}

public sealed record AclView(byte Revision, IReadOnlyList<AceView> Aces)
{
    // ACL header (MS-DTYP 2.4.5): revision, pad, size, count, pad; then count ACEs.
    public static AclView Parse(ReadOnlySpan<byte> b)
    {
        if (b.Length < 8) throw new DescriptorFormatException("ACL header is truncated");
        ushort size = BinaryPrimitives.ReadUInt16LittleEndian(b[2..]);
        ushort count = BinaryPrimitives.ReadUInt16LittleEndian(b[4..]);
        if (size < 8 || size > b.Length) throw new DescriptorFormatException($"ACL size {size} does not fit the descriptor");
        var acl = b[..size];
        var aces = new List<AceView>(count);
        int at = 8;
        for (int i = 0; i < count; i++)
        {
            if (at + 4 > acl.Length) throw new DescriptorFormatException($"ACE {i} header is past the ACL");
            ushort aceSize = BinaryPrimitives.ReadUInt16LittleEndian(acl[(at + 2)..]);
            if (aceSize < 4 || at + aceSize > acl.Length) throw new DescriptorFormatException($"ACE {i} size {aceSize} does not fit the ACL");
            aces.Add(AceView.Parse(acl.Slice(at, aceSize)));
            at += aceSize;
        }
        return new AclView(b[0], aces);
    }
}

// AceView keeps the ACE's type and flag bytes as stored. Inherited (ID) and the inheritance flags
// are the fields that dynamic inheritance and protection questions turn on, so they are spelled out.
// Mask and Sid are null for an ACE type whose body this parser does not decode (object ACEs,
// callback ACEs); Body then holds its bytes.
public sealed record AceView(string Type, byte TypeCode, byte Flags, IReadOnlyList<string> FlagNames, uint? Mask, string? Sid, string? Body)
{
    public bool Inherited => (Flags & 0x10) != 0;

    // ACE types whose body starts with ACCESS_MASK + SID (MS-DTYP 2.4.4). Any trailing data (a
    // resource attribute's claim) is not decoded.
    static readonly Dictionary<byte, string> Simple = new()
    {
        [0x00] = "Allow", [0x01] = "Deny", [0x02] = "Audit", [0x03] = "Alarm",
        [0x11] = "MandatoryLabel", [0x12] = "ResourceAttribute", [0x13] = "ScopedPolicyId",
    };

    public static AceView Parse(ReadOnlySpan<byte> ace)
    {
        byte type = ace[0], flags = ace[1];
        var body = ace[4..];
        if (Simple.TryGetValue(type, out var name) && body.Length >= 4 + 8)
        {
            uint mask = BinaryPrimitives.ReadUInt32LittleEndian(body);
            string sid = SidFormat.Parse(body[4..], out _);
            return new AceView(name, type, flags, DescribeFlags(flags), mask, sid, null);
        }
        return new AceView($"0x{type:x2}", type, flags, DescribeFlags(flags), null, null, Convert.ToBase64String(body));
    }

    static readonly (byte Bit, string Name)[] FlagNamesTable =
    [
        (0x01, "OI"), (0x02, "CI"), (0x04, "NP"), (0x08, "IO"), (0x10, "ID"), (0x40, "SA"), (0x80, "FA"),
    ];

    public static IReadOnlyList<string> DescribeFlags(byte flags)
    {
        var names = new List<string>();
        byte known = 0;
        foreach (var (bit, name) in FlagNamesTable)
        {
            known |= bit;
            if ((flags & bit) != 0) names.Add(name);
        }
        if ((flags & ~known) != 0) names.Add($"0x{flags & ~known:x2}");
        return names;
    }
}

// Sid renders a binary SID (MS-DTYP 2.4.2.2) in S-R-I-S... form.
public static class SidFormat
{
    public static string Parse(ReadOnlySpan<byte> b, out int length)
    {
        if (b.Length < 8) throw new DescriptorFormatException("SID is truncated");
        int n = b[1];
        length = 8 + 4 * n;
        if (n > 15 || b.Length < length) throw new DescriptorFormatException($"SID with {n} subauthorities does not fit");
        ulong auth = 0;
        for (int i = 2; i < 8; i++) auth = (auth << 8) | b[i];
        var sb = new StringBuilder($"S-{b[0]}-");
        sb.Append(auth < (1UL << 32) ? auth.ToString() : $"0x{auth:X12}");
        for (int i = 0; i < n; i++) sb.Append('-').Append(BinaryPrimitives.ReadUInt32LittleEndian(b[(8 + 4 * i)..]));
        return sb.ToString();
    }
}

public sealed class DescriptorFormatException(string message) : Exception(message);
