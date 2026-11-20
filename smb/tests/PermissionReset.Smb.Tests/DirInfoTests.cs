using System.Text;
using PermissionReset.Smb;

namespace PermissionReset.Smb.Tests;

// DirInfo.Parse reads a FILE_FULL_DIR_INFO chain whose offsets and lengths the server supplies.
public class DirInfoTests
{
    const int H = DirInfo.HeaderSize;

    // Entry builds one FILE_FULL_DIR_INFO record; next and nameLen default to the honest values
    // (next is filled in by Chain).
    static byte[] Entry(string name, uint attrs, int? nameLen = null)
    {
        var n = Encoding.Unicode.GetBytes(name);
        var e = new byte[(H + n.Length + 7) & ~7];
        BitConverter.GetBytes(attrs).CopyTo(e, 56);
        BitConverter.GetBytes(nameLen ?? n.Length).CopyTo(e, 60);
        n.CopyTo(e, H);
        return e;
    }

    // Chain lays the entries out back to back in a 64 KB buffer, each pointing at the next.
    static byte[] Chain(params byte[][] entries)
    {
        var buf = new byte[64 * 1024];
        int off = 0;
        for (int i = 0; i < entries.Length; i++)
        {
            entries[i].CopyTo(buf, off);
            if (i < entries.Length - 1) BitConverter.GetBytes(entries[i].Length).CopyTo(buf, off);
            off += entries[i].Length;
        }
        return buf;
    }

    static List<(string Name, uint Attributes)> Parse(byte[] buf, int? valid = null)
    {
        var list = new List<(string Name, uint Attributes)>();
        DirInfo.Parse(buf, valid ?? buf.Length, list);
        return list;
    }

    [Fact]
    public void ParsesAChainAndSkipsDotEntries()
    {
        var buf = Chain(Entry(".", 0x10), Entry("..", 0x10), Entry("a.txt", 0x20), Entry("sub", 0x10), Entry("ünï", 0x400));
        Assert.Equal([("a.txt", 0x20u), ("sub", 0x10u), ("ünï", 0x400u)], Parse(buf));
    }

    [Fact]
    public void ParsesAnEntryEndingExactlyAtTheBuffer()
    {
        var e = Entry("x", 0x20);
        var buf = new byte[H + 2];
        Array.Copy(e, buf, H + 2);
        Assert.Equal([("x", 0x20u)], Parse(buf));
    }

    [Fact]
    public void RejectsANameRunningPastTheBuffer()
    {
        var buf = Chain(Entry("a", 0x20, nameLen: 64 * 1024));
        var e = Assert.Throws<InvalidDataException>(() => Parse(buf));
        Assert.StartsWith("list: malformed directory entry at offset 0", e.Message);
        Assert.Contains("runs past", e.Message);
    }

    [Theory]
    [InlineData(-2)]
    [InlineData(3)]
    [InlineData(int.MinValue)]
    public void RejectsANegativeOrOddNameLength(int nameLen)
    {
        var e = Assert.Throws<InvalidDataException>(() => Parse(Chain(Entry("ab", 0x20, nameLen))));
        Assert.Contains("name length", e.Message);
    }

    [Theory]
    [InlineData(-80)]          // backwards
    [InlineData(int.MinValue)]
    [InlineData(4)]            // inside its own header: no progress past this entry
    [InlineData(H)]            // overlaps its own name
    [InlineData(64 * 1024)]    // past the buffer
    public void RejectsABadNextOffset(int next)
    {
        var buf = Chain(Entry("abc", 0x20), Entry("def", 0x20));
        BitConverter.GetBytes(next).CopyTo(buf, 0);
        var e = Assert.Throws<InvalidDataException>(() => Parse(buf));
        Assert.Contains("next entry offset", e.Message);
    }

    [Fact]
    public void RejectsACycleBackToTheFirstEntry()
    {
        // A non-zero offset pointing back would loop forever; one that leads to an entry pointing
        // at itself (0 progress) is the same loop. Both are refused, not spun on.
        var buf = Chain(Entry("abc", 0x20), Entry("def", 0x20));
        int second = Entry("abc", 0x20).Length;
        BitConverter.GetBytes(-second).CopyTo(buf, second);
        Assert.Throws<InvalidDataException>(() => Parse(buf));
        BitConverter.GetBytes(0).CopyTo(buf, second);   // honest end parses
        Assert.Equal(2, Parse(buf).Count);
    }

    [Fact]
    public void RejectsAHeaderThatDoesNotFit()
    {
        var e = Assert.Throws<InvalidDataException>(() => Parse(new byte[H - 1]));
        Assert.Contains("header", e.Message);
        var buf = Chain(Entry("abc", 0x20), Entry("def", 0x20));
        Assert.Throws<InvalidDataException>(() => Parse(buf, Entry("abc", 0x20).Length + 10));
        Assert.Throws<InvalidDataException>(() => Parse(buf, buf.Length + 1));
    }
}
