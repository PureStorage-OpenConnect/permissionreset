using PermissionReset.Smb.Core;

namespace PermissionReset.Smb.Tests;

public class PlanTests
{
    static string SmbGolden => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "testdata", "smbplan.golden.json"));
    static string SmbDaclGolden => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "testdata", "smbplan-dacl.golden.json"));
    static string Golden => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "testdata", "saclplan.golden.json"));

    [Fact]
    public void LoadsTheBuildSpecGolden()
    {
        var p = Plan.Parse(Golden);
        Assert.Equal(1, p.Schema);
        Assert.Equal("nfsv4", p.Protocol);
        Assert.Equal("default", p.Default.Label);
        Assert.True(p.Default.KeepDacl);
        var ace = Assert.Single(p.Default.Sacl!);
        Assert.Equal("S-1-1-0", ace.Sid);
        Assert.Equal(2, ace.WindowsType);
        Assert.Equal(0xC3, ace.WindowsFlags);
        Assert.NotEmpty(p.Rules);
        Assert.Contains(".snapshot", p.Exclude.Base);
    }

    [Theory]
    [InlineData("\"schema\": 1", "\"schema\": 4", "schema 4 is not supported")]
    [InlineData("\"sacl\": [", "\"dacl\": [], \"sacl\": [", "schema 1 plan has no dacl")]
    [InlineData("\"protocol\": \"nfsv4\"", "\"protocol\": \"posix\"", "protocol \"posix\"")]
    [InlineData("\"schema\": 1,", "\"schema\": 1, \"surprise\": true,", "not valid JSON")]
    [InlineData("\"type\": \"directory\"", "\"type\": \"dir\"", "unknown match type \"dir\"")]
    public void RefusesWhatItWouldMisread(string from, string to, string want)
    {
        Assert.Contains(from, Golden);
        var e = Assert.Throws<PlanException>(() => Plan.Parse(ReplaceFirst(Golden, from, to)));
        Assert.Contains(want, e.Message);
    }

    [Fact]
    public void LoadsTheSmbPlanGolden()
    {
        var p = Plan.Parse(SmbGolden);
        Assert.Equal(Plan.SmbSaclSchema, p.Schema);         // a rule sets sacl: (2.1)
        Assert.True(p.Default.HasAcl);
        Assert.Equal(2, p.Default.Dacl!.Count);
        Assert.Equal(AceTypes.Allow, p.Default.Dacl[0].WindowsType);
        Assert.Equal("S-1-1-0", p.Default.Dacl[0].Sid);
        Assert.Null(p.Rules[0].Dacl);                       // sacl:-only rule
        Assert.Equal(AceTypes.Deny, p.Rules[1].Dacl![0].WindowsType);
        Assert.Empty(p.Rules[1].Sacl!);                     // sacl: []
    }

    [Fact]
    public void LoadsASchema2DaclOnlyPlanWithUnchangedMeaning()
    {
        var p = Plan.Parse(SmbDaclGolden);
        Assert.Equal(Plan.SmbSchema, p.Schema);
        Assert.True(p.Default.HasAcl);
        Assert.NotEmpty(p.Default.Dacl!);
        Assert.False(p.Default.SaclSet);
        Assert.Empty(p.Default.Sacl!);
        Assert.DoesNotContain(p.Rules, r => r.SaclSet || r.Dacl is null);
    }

    // 2.1's schema rule: no schema 2 build ever wrote a sacl rule, and phase 2 refused one, so a
    // hand-moved schema 2 SACL plan is never reinterpreted.
    [Fact]
    public void RefusesASchema2PlanWithSaclSet()
    {
        var e = Assert.Throws<PlanException>(() => Plan.Parse(ReplaceFirst(SmbGolden, "\"schema\": 3", $"\"schema\": {Plan.SmbSchema}")));
        Assert.Contains("sacl: set", e.Message);
        Assert.Contains("rebuild", e.Message);
    }

    // 2.2 item 2: every audit ACE carries SA, FA or both. The golden's one audit ACE flags are
    // 0xC3 (OI|CI|SA|FA); dropping SA and FA leaves 0x03.
    [Fact]
    public void RefusesAnAuditAceThatAuditsNothing()
    {
        var e = Assert.Throws<PlanException>(() => Plan.Parse(ReplaceFirst(SmbGolden, "\"windows_flags\": 195", "\"windows_flags\": 3")));
        Assert.Contains("neither SA nor FA", e.Message);
    }

    // 2.2 item 3: all four creator SIDs are refused in sacl.
    [Theory]
    [InlineData("S-1-3-0")]
    [InlineData("S-1-3-1")]
    [InlineData("S-1-3-2")]
    [InlineData("S-1-3-3")]
    public void RefusesACreatorSidInSacl(string sid)
    {
        var root = System.Text.Json.Nodes.JsonNode.Parse(SmbGolden)!.AsObject();
        root["rules"]![0]!["sacl"]![0]!["sid"] = sid;
        var e = Assert.Throws<PlanException>(() => Plan.Parse(root.ToJsonString()));
        Assert.Contains($"creator SID {sid}", e.Message);
    }

    // A hand edit can also spell a creator SID as the principal, with no sid field.
    [Fact]
    public void RefusesACreatorSidSpelledAsThePrincipal()
    {
        var root = System.Text.Json.Nodes.JsonNode.Parse(SmbGolden)!.AsObject();
        var ace = root["rules"]![0]!["sacl"]![0]!.AsObject();
        ace["principal"] = "S-1-3-0";
        ace["sid"] = "";
        var e = Assert.Throws<PlanException>(() => Plan.Parse(root.ToJsonString()));
        Assert.Contains("creator SID S-1-3-0", e.Message);
    }

    // 2.2 items 4 and 5.
    [Theory]
    [InlineData("contradictory", "sacl_set is false")]
    [InlineData("missing", "has no sacl list")]
    [InlineData("null", "has no sacl list")]
    public void RefusesABrokenSaclPair(string what, string want)
    {
        var root = System.Text.Json.Nodes.JsonNode.Parse(SmbGolden)!.AsObject();
        var rule = root["rules"]![0]!.AsObject();
        switch (what)
        {
            case "contradictory": rule["sacl_set"] = false; break;
            case "missing": rule.Remove("sacl"); break;
            case "null": rule["sacl"] = null; break;
        }
        var e = Assert.Throws<PlanException>(() => Plan.Parse(root.ToJsonString()));
        Assert.Contains(want, e.Message);
    }

    [Theory]
    [InlineData("\"has_acl\": true", "\"has_acl\": false", "has_acl is false but dacl is present")]
    [InlineData("\"windows_type\": 0", "\"windows_type\": 2", "want allow (0) or deny (1)")]
    [InlineData("\"windows_flags\": 3", "\"windows_flags\": 19", "carries ID")]
    public void RefusesAMisshapedSmbPlan(string from, string to, string want)
    {
        Assert.Contains(from, SmbGolden);
        var e = Assert.Throws<PlanException>(() => Plan.Parse(ReplaceFirst(SmbGolden, from, to)));
        Assert.Contains(want, e.Message);
    }

    [Fact]
    public void RefusesNotJson() => Assert.Throws<PlanException>(() => Plan.Parse("schema: 1"));

    // internal/saclplan writes every field but dacl, so a missing or null one is a malformed plan:
    // refused by name, not defaulted or left to throw NullReferenceException downstream.
    [Theory]
    [InlineData("missing match", "plan rule rule[0]: has no match")]
    [InlineData("null rule", "plan rule[1] is null")]
    [InlineData("missing pattern", "plan rule rule[0]: match has no pattern")]
    [InlineData("missing type", "plan rule default: match has no type")]
    [InlineData("missing label", "plan rule[0] has no label")]
    [InlineData("null owner", "plan rule default: has no owner")]
    [InlineData("missing group", "plan rule rule[1]: has no group")]
    [InlineData("missing sid", "plan rule default: dacl[0] has no sid")]
    [InlineData("null principal", "plan rule default: dacl[1] has no principal")]
    [InlineData("null ace", "plan rule rule[0]: sacl[0] is null")]
    [InlineData("missing rules", "plan has no rules")]
    [InlineData("missing exclude", "plan has no exclude")]
    [InlineData("missing exclude base", "plan exclude has no base")]
    [InlineData("null exclude pattern", "plan exclude patterns has a null entry")]
    [InlineData("missing source", "plan has no source")]
    public void RefusesAMissingField(string what, string want)
    {
        var root = System.Text.Json.Nodes.JsonNode.Parse(SmbGolden)!.AsObject();
        var rules = root["rules"]!.AsArray();
        var def = root["default"]!.AsObject();
        switch (what)
        {
            case "missing match": rules[0]!.AsObject().Remove("match"); break;
            case "null rule": rules[1] = null; break;
            case "missing pattern": rules[0]!["match"]!.AsObject().Remove("pattern"); break;
            case "missing type": def["match"]!.AsObject().Remove("type"); break;
            case "missing label": rules[0]!.AsObject().Remove("label"); break;
            case "null owner": def["owner"] = null; break;
            case "missing group": rules[1]!.AsObject().Remove("group"); break;
            case "missing sid": def["dacl"]![0]!.AsObject().Remove("sid"); break;
            case "null principal": def["dacl"]![1]!["principal"] = null; break;
            case "null ace": rules[0]!["sacl"]![0] = null; break;
            case "missing rules": root.Remove("rules"); break;
            case "missing exclude": root.Remove("exclude"); break;
            case "missing exclude base": root["exclude"]!.AsObject().Remove("base"); break;
            case "null exclude pattern": root["exclude"]!["patterns"]!.AsArray().Add(null); break;
            case "missing source": root.Remove("source"); break;
            default: throw new ArgumentException(what);
        }
        var e = Assert.Throws<PlanException>(() => Plan.Parse(root.ToJsonString()));
        Assert.Equal(want, e.Message);
    }

    [Fact]
    public void LoadOfAMissingFileNamesThePath()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"smbplan-missing-{Guid.NewGuid():N}.json");
        var e = Assert.Throws<PlanException>(() => Plan.Load(missing));
        Assert.StartsWith($"cannot read plan {missing}: ", e.Message);
        Assert.IsType<FileNotFoundException>(e.InnerException);
    }

    static string ReplaceFirst(string s, string from, string to)
    {
        int i = s.IndexOf(from, StringComparison.Ordinal);
        return s[..i] + to + s[(i + from.Length)..];
    }
}
