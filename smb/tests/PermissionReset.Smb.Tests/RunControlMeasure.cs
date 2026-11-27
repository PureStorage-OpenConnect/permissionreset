using System.Text.Json;
using PermissionReset.Smb.Core;

namespace PermissionReset.Smb.Tests;

// The checkpoint-size measurement docs/plan-smb-run-control.md 4.4 asks for when it lands
// (CHECKPOINT_SCALE.md is the NFS tool's): records.jsonl and checkpoint.jsonl bytes for a
// ~2-million-object tree, after a completed run and after a stop at about half. Skipped unless
// PERMISSIONRESET_SMB_MEASURE names a report file; the run takes about a minute and is not part
// of the suite. The tree is a custom fast ITree: shared descriptor bytes and precomputed
// listings, since FakeTree's children scan is quadratic at this size.
public sealed class RunControlMeasure
{
    sealed class MeasureTree(byte[] rootDesc, byte[] dirDesc, byte[] fileDesc,
        Dictionary<string, IReadOnlyList<TreeEntry>> children, HashSet<string> dirs) : IWritableTree
    {
        public long Reads;
        public Action<string>? BeforeRead;

        public IReadOnlyList<TreeEntry> List(string rel) => children[rel];

        public TreeObject Read(string rel, bool withSacl)
        {
            Interlocked.Increment(ref Reads);
            BeforeRead?.Invoke(rel);
            return rel.Length == 0 ? new TreeObject(rootDesc, true, false)
                : dirs.Contains(rel) ? new TreeObject(dirDesc, true, false)
                : new TreeObject(fileDesc, false, false);
        }

        public void Write(string rel, uint securityInformation, byte[] descriptor) => throw new IOException("check writes nothing");
        public void CreateDirectory(string rel) => throw new IOException("check writes nothing");
        public void CreateFile(string rel) => throw new IOException("check writes nothing");
        public void Delete(string rel, bool isDir) => throw new IOException("check writes nothing");
    }

    // ~2.25 million objects: 45 x 45 x 10 subdirectory levels, 100 files in every directory, all
    // right under the usual plan.
    static MeasureTree BigTree(out long objects)
    {
        byte[] u = DescriptorTests.SidBytes(5, 21, 1, 2, 3, 1001), a = DescriptorTests.SidBytes(5, 21, 1, 2, 3, 1002);
        const byte OICI = 0x03, ID = 0x10;
        const ushort SelfRelative = 0x8000, DaclPresent = 0x0004, DaclProtected = 0x1000;
        var rootDesc = DescriptorTests.Sd(SelfRelative | DaclPresent | DaclProtected, a, a, null,
            DescriptorTests.Acl(DescriptorTests.Ace(0, OICI, 0x1200a9, u), DescriptorTests.Ace(0, OICI, 0x1f01ff, a)));
        var dirDesc = DescriptorTests.Sd(SelfRelative | DaclPresent, a, a, null,
            DescriptorTests.Acl(DescriptorTests.Ace(0, (byte)(ID | OICI), 0x1200a9, u), DescriptorTests.Ace(0, (byte)(ID | OICI), 0x1f01ff, a)));
        var fileDesc = DescriptorTests.Sd(SelfRelative | DaclPresent, a, a, null,
            DescriptorTests.Acl(DescriptorTests.Ace(0, ID, 0x1200a9, u), DescriptorTests.Ace(0, ID, 0x1f01ff, a)));

        var children = new Dictionary<string, IReadOnlyList<TreeEntry>>(StringComparer.Ordinal);
        var dirs = new HashSet<string>(StringComparer.Ordinal);
        long files = 0;
        IReadOnlyList<TreeEntry> Listing(string rel, int subdirs)
        {
            var list = new List<TreeEntry>();
            for (int d = 0; d < subdirs; d++)
            {
                var child = rel.Length == 0 ? $"d{d:D2}" : $"{rel}/d{d:D2}";
                dirs.Add(child);
                list.Add(new TreeEntry($"d{d:D2}", true, false));
            }
            for (int f = 0; f < 100; f++)
            {
                list.Add(new TreeEntry($"f{f:D2}", false, false));
                files++;
            }
            return children[rel] = list;
        }
        Listing("", 45);
        for (int i = 0; i < 45; i++)
        {
            var l1 = $"d{i:D2}";
            Listing(l1, 45);
            for (int j = 0; j < 45; j++)
            {
                var l2 = $"{l1}/d{j:D2}";
                Listing(l2, 10);
                for (int k = 0; k < 10; k++) Listing($"{l2}/d{k:D2}", 0);
            }
        }
        objects = 1 + dirs.Count + files;
        return new MeasureTree(rootDesc, dirDesc, fileDesc, children, dirs);
    }

    [Fact]
    public void MeasureCheckpointAndRecordsSizes()
    {
        if (Environment.GetEnvironmentVariable("PERMISSIONRESET_SMB_MEASURE") is not { Length: > 0 } report) return;
        var plan = Path.Combine(Path.GetTempPath(), $"smbplan-measure-{Guid.NewGuid():N}.json");
        var dirA = Path.Combine(Path.GetTempPath(), $"smbmeasure-full-{Guid.NewGuid():N}");
        var dirB = Path.Combine(Path.GetTempPath(), $"smbmeasure-half-{Guid.NewGuid():N}");
        try
        {
            File.WriteAllText(plan, JsonSerializer.Serialize(CheckerTests.Usual));
            var tree = BigTree(out long objects);
            CheckDeps Deps(CancellationToken stop = default) =>
                new(_ => { }, _ => tree, _ => null, Stop: stop,
                    Identity: () => @"TESTDOMAIN\testuser", Elevated: () => false);

            var clock = System.Diagnostics.Stopwatch.StartNew();
            var codeA = Cli.Run(["check", "--workers", "8", "--state-dir", dirA, plan, "R"], TextWriter.Null, TextWriter.Null, check: Deps());
            var secondsA = clock.Elapsed.TotalSeconds;
            Assert.Equal(0, codeA);

            // A stop at about half the objects: as soon as this run's reads pass half, the token
            // cancels. Reads counted from run A go back to 0 first.
            var cts = new CancellationTokenSource();
            Interlocked.Exchange(ref tree.Reads, 0);
            long total = objects;
            tree.BeforeRead = _ => { if (Interlocked.Read(ref tree.Reads) >= total / 2) cts.Cancel(); };
            clock.Restart();
            var codeB = Cli.Run(["check", "--workers", "8", "--state-dir", dirB, plan, "R"], TextWriter.Null, TextWriter.Null, check: Deps(cts.Token));
            var secondsB = clock.Elapsed.TotalSeconds;
            Assert.Equal(3, codeB);

            string Sizes(string dir) =>
                $"records.jsonl {new FileInfo(Path.Combine(dir, "records.jsonl")).Length:N0} bytes, " +
                $"checkpoint.jsonl {new FileInfo(Path.Combine(dir, "checkpoint.jsonl")).Length:N0} bytes " +
                $"({File.ReadLines(Path.Combine(dir, "checkpoint.jsonl")).Count():N0} lines)";
            File.WriteAllText(report,
                $"objects {objects:N0}\n" +
                $"completed ({secondsA:N1}s): {Sizes(dirA)}\n" +
                $"stopped at ~50% ({secondsB:N1}s): {Sizes(dirB)}\n");
        }
        finally
        {
            File.Delete(plan);
            foreach (var d in new[] { dirA, dirB })
                if (Directory.Exists(d)) Directory.Delete(d, recursive: true);
        }
    }
}
