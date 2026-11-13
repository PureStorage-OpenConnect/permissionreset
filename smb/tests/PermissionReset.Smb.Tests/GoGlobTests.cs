using System.Text.Json;
using PermissionReset.Smb.Core;

namespace PermissionReset.Smb.Tests;

// The vectors are Go's own path.Match answers (tools/set-saclonly/testdata/genvectors.go), shared
// with the Set-SaclOnly Pester suite, so all three implementations agree by construction.
public class GoGlobTests
{
    record Vector(string pattern, string name, bool match);

    public static IEnumerable<object[]> Vectors()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "testdata", "glob-vectors.json");
        var vs = JsonSerializer.Deserialize<List<Vector>>(File.ReadAllText(path))!;
        Assert.NotEmpty(vs);
        return vs.Select(v => new object[] { v.pattern, v.name, v.match });
    }

    [Theory]
    [MemberData(nameof(Vectors))]
    public void MatchesGo(string pattern, string name, bool want) => Assert.Equal(want, GoGlob.Match(pattern, name));
}
