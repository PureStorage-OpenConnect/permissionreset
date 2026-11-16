using PermissionReset.Smb.Core;

namespace PermissionReset.Smb.Tests;

public class InheritanceTests
{
    const string Users = "S-1-5-21-1-2-3-1001", Admins = "S-1-5-21-1-2-3-1002", Blocked = "S-1-5-21-1-2-3-1003";
    const int OI = AceFlags.ObjectInherit, CI = AceFlags.ContainerInherit, NP = AceFlags.NoPropagate,
        IO = AceFlags.InheritOnly, ID = AceFlags.Inherited, SA = AceFlags.SuccessfulAccess, FA = AceFlags.FailedAccess;

    static Ace Allow(int flags, string sid = Users, uint mask = 0x1200a9) => new(AceTypes.Allow, (byte)flags, mask, sid);

    // The design's prediction (smb/DESIGN-write-path.md 2.4) for one parent ACE, per child type.
    // null means the child does not inherit it. Q-INH checks this same table on the array.
    [Theory]
    //          parent flags       file child     dir child
    [InlineData(0,                 null,          null)]
    [InlineData(OI,                ID,            ID | IO | OI)]
    [InlineData(CI,                null,          ID | CI)]
    [InlineData(OI | CI,           ID,            ID | OI | CI)]
    [InlineData(OI | NP,           ID,            null)]
    [InlineData(CI | NP,           null,          ID)]
    [InlineData(OI | CI | NP,      ID,            ID)]
    [InlineData(OI | IO,           ID,            ID | IO | OI)]
    [InlineData(CI | IO,           null,          ID | CI)]
    [InlineData(OI | CI | IO,      ID,            ID | OI | CI)]
    [InlineData(OI | CI | NP | IO, ID,            ID)]
    public void InheritsPerFlagTable(int parent, int? file, int? dir)
    {
        var p = new[] { Allow(parent) };
        Check(Inheritance.Inherit(p, childIsDir: false), file);
        Check(Inheritance.Inherit(p, childIsDir: true), dir);

        static void Check(List<Ace> got, int? want)
        {
            if (want is null) { Assert.Empty(got); return; }
            var a = Assert.Single(got);
            Assert.Equal(want, (int)a.Flags);
            Assert.Equal(0x1200a9u, a.Mask);
            Assert.Equal(Users, a.Sid);
        }
    }

    [Fact]
    public void KeepsAuditFlagsAndOrder()
    {
        var p = new[]
        {
            new Ace(AceTypes.Audit, (byte)(OI | CI | SA | FA), 0x1f01ff, Users),
            new Ace(AceTypes.Deny, (byte)(OI | CI), 0x116, Blocked),
            Allow(OI | CI, Admins),
        };
        var f = Inheritance.Inherit(p, childIsDir: false);
        Assert.Equal([ID | SA | FA, ID, ID], f.Select(a => (int)a.Flags));
        Assert.Equal([AceTypes.Audit, AceTypes.Deny, AceTypes.Allow], f.Select(a => a.Type));
    }

    [Fact]
    public void RefusesToInheritCreatorOwner()
    {
        var e = Assert.Throws<NotSupportedException>(() => Inheritance.Inherit([Allow(OI | CI, "S-1-3-0")], true));
        Assert.Contains("creating account", e.Message);
        // A creator ACE that does not reach the child is fine.
        Assert.Empty(Inheritance.Inherit([Allow(CI, "S-1-3-0")], childIsDir: false));
    }

    // ---- the three forms ----------------------------------------------------------------------

    static readonly Ace[] DirRule = [Allow(OI | CI, Users), Allow(OI | CI, Admins, 0x1f01ff)];

    [Fact]
    public void FileMatchingWhatItInheritsIsInherits()
    {
        var inh = Inheritance.Inherit(DirRule, childIsDir: false);
        var d = Desired.Classify([Allow(0, Users), Allow(0, Admins, 0x1f01ff)], inh);
        Assert.Equal(Form.Inherits, d.Form);
        Assert.False(d.Protected);
        Assert.All(d.Aces, a => Assert.True(a.Inherited));
    }

    [Fact]
    public void DirRepeatingItsParentIsInherits()
    {
        var d = Desired.Classify(DirRule, Inheritance.Inherit(DirRule, childIsDir: true));
        Assert.Equal(Form.Inherits, d.Form);
        Assert.Equal([ID | OI | CI, ID | OI | CI], d.Aces.Select(a => (int)a.Flags));
    }

    [Fact]
    public void ExtraLeadingAceIsExplicitPlusInherits()
    {
        var deny = new Ace(AceTypes.Deny, (byte)(OI | CI), 0x116, Blocked);
        var d = Desired.Classify([deny, .. DirRule], Inheritance.Inherit(DirRule, childIsDir: true));
        Assert.Equal(Form.ExplicitPlusInherits, d.Form);
        Assert.False(d.Protected);
        Assert.Equal(3, d.Aces.Count);
        Assert.False(d.Aces[0].Inherited);
        Assert.True(d.Aces[1].Inherited && d.Aces[2].Inherited);
    }

    [Theory]
    [InlineData("different mask")]
    [InlineData("fewer ACEs")]
    [InlineData("inherited part not last")]
    [InlineData("parent passes nothing")]
    public void AnythingElseIsProtected(string why)
    {
        var inh = Inheritance.Inherit(DirRule, childIsDir: false);
        Ace[] want = why switch
        {
            "different mask" => [Allow(0, Users, 0x1301bf), Allow(0, Admins, 0x1f01ff)],
            "fewer ACEs" => [Allow(0, Admins, 0x1f01ff)],
            "inherited part not last" => [Allow(0, Users), Allow(0, Admins, 0x1f01ff), Allow(0, Blocked)],
            _ => [Allow(0, Users)],
        };
        var d = Desired.Classify(want, why == "parent passes nothing" ? [] : inh);
        Assert.Equal(Form.Protected, d.Form);
        Assert.True(d.Protected);
        Assert.Equal(want, d.Aces);
    }

    [Fact]
    public void ClassifyRefusesAWantedIdAce() =>
        Assert.Throws<ArgumentException>(() => Desired.Classify([Allow(ID)], []));

    // ---- comparing with what is stored --------------------------------------------------------

    static AclView View(params Ace[] aces) =>
        new(2, aces.Select(a => new AceView("x", (byte)a.Type, a.Flags, AceView.DescribeFlags(a.Flags), a.Mask, a.Sid, null)).ToList());

    [Fact]
    public void MatchesComparesRawIncludingIdAndProtection()
    {
        var d = Desired.Classify([Allow(0, Users)], Inheritance.Inherit([Allow(OI | CI)], false));
        Assert.Equal(Form.Inherits, d.Form);
        Assert.Null(d.Matches(View(Allow(ID)), storedProtected: false));
        Assert.Contains("want unprotected", d.Matches(View(Allow(ID)), storedProtected: true));
        Assert.Contains("ACE 0", d.Matches(View(Allow(0)), storedProtected: false));          // explicit, not ID
        Assert.Contains("2 ACE(s)", d.Matches(View(Allow(ID), Allow(ID)), storedProtected: false));
        Assert.Contains("0 ACE(s)", d.Matches(null, storedProtected: false));
    }

    [Fact]
    public void AnUnmodeledStoredAceNeverMatches()
    {
        var d = new Desired(Form.Protected, [Allow(0)], true);
        var stored = new AclView(2, [new AceView("0x05", 0x05, 0, [], null, null, "AAAA")]);
        Assert.Contains("does not write", d.Matches(stored, storedProtected: true));
    }
}
