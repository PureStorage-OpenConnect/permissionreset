// GoGlob is Go's path.Match: the grammar permissionreset's spec matching uses (filepath.Match on
// Linux, where '/' is the only separator and '\' escapes). Case-sensitive, as the NFS run is.
// A malformed pattern matches nothing; build-spec has already refused one at spec load.
// Matching runs on UTF-8 bytes, as Go's does on its byte strings: '*' backtracks by byte and '?'
// decodes one rune, with a lone continuation byte decoding as RuneError, width 1. Matching by
// UTF-16 code unit would diverge there ("*??" matches 3-byte 本 in Go, and a multibyte name after
// a star would be stepped by surrogate units instead of bytes).
// Ported from Go's src/path/match.go; tools/set-saclonly/SaclOnly.cs carries the same port in
// C# 5. Both are tested against the same Go-generated vectors.
namespace PermissionReset.Smb.Core;

public static class GoGlob {
    class BadPattern : Exception { }

    const int RuneError = 0xFFFD;

    public static bool Match(string pattern, string name) {
        try { return MatchOrThrow(System.Text.Encoding.UTF8.GetBytes(pattern), System.Text.Encoding.UTF8.GetBytes(name)); }
        catch (BadPattern) { return false; }
    }

    static bool MatchOrThrow(byte[] pattern, byte[] name) {
        int p = 0, n = 0;
        while (p < pattern.Length) {
            ScanChunk(pattern, ref p, out bool star, out int cs, out int ce);
            if (star && cs == ce) return IndexOfByte(name, (byte)'/', n) < 0;
            if (MatchChunk(pattern, cs, ce, name, n, out int t) && (t == name.Length || p < pattern.Length)) { n = t; continue; }
            if (star) {
                bool advanced = false;
                for (int i = n; i < name.Length && name[i] != (byte)'/'; i++) {
                    if (MatchChunk(pattern, cs, ce, name, i + 1, out t)) {
                        if (p == pattern.Length && t < name.Length) continue;
                        n = t; advanced = true; break;
                    }
                }
                if (advanced) continue;
            }
            return false;
        }
        return n == name.Length;
    }

    static int IndexOfByte(byte[] s, byte b, int from) {
        for (int i = from; i < s.Length; i++) if (s[i] == b) return i;
        return -1;
    }

    static void ScanChunk(byte[] pattern, ref int p, out bool star, out int cs, out int ce) {
        star = false;
        while (p < pattern.Length && pattern[p] == (byte)'*') { p++; star = true; }
        bool inrange = false;
        int i = p;
        for (; i < pattern.Length; i++) {
            byte c = pattern[i];
            if (c == (byte)'\\') { if (i + 1 < pattern.Length) i++; }
            else if (c == (byte)'[') inrange = true;
            else if (c == (byte)']') inrange = false;
            else if (c == (byte)'*' && !inrange) break;
        }
        cs = p; ce = i; p = i;
    }

    // One UTF-8 rune, with utf8.DecodeRune semantics: a byte that cannot start or continue a
    // valid sequence decodes as RuneError with width 1, so '?' consumes exactly one byte there.
    static int DecodeRune(byte[] s, int at, out int width) {
        byte b0 = s[at];
        if (b0 < 0x80) { width = 1; return b0; }
        if (b0 < 0xC2) { width = 1; return RuneError; }
        if (at + 1 >= s.Length) { width = 1; return RuneError; }
        int lo = 0x80, hi = 0xBF;
        if (b0 == 0xE0) lo = 0xA0;
        else if (b0 == 0xED) hi = 0x9F;
        else if (b0 == 0xF0) lo = 0x90;
        else if (b0 == 0xF4) hi = 0x8F;
        byte b1 = s[at + 1];
        if (b1 < lo || b1 > hi) { width = 1; return RuneError; }
        if (b0 < 0xE0) { width = 2; return ((b0 & 0x1F) << 6) | (b1 & 0x3F); }
        if (at + 2 >= s.Length) { width = 1; return RuneError; }
        byte b2 = s[at + 2];
        if (b2 < 0x80 || b2 > 0xBF) { width = 1; return RuneError; }
        if (b0 < 0xF0) { width = 3; return ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F); }
        if (b0 >= 0xF5) { width = 1; return RuneError; }
        if (at + 3 >= s.Length) { width = 1; return RuneError; }
        byte b3 = s[at + 3];
        if (b3 < 0x80 || b3 > 0xBF) { width = 1; return RuneError; }
        width = 4; return ((b0 & 0x07) << 18) | ((b1 & 0x3F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F);
    }

    static bool MatchChunk(byte[] chunk, int ci, int ce, byte[] s, int si, out int rest) {
        bool failed = false;
        while (ci < ce) {
            if (!failed && si >= s.Length) failed = true;
            byte c = chunk[ci];
            if (c == (byte)'[') {
                int r = 0;
                if (!failed) { r = DecodeRune(s, si, out int w); si += w; }
                ci++;
                bool negated = false;
                if (ci < ce && chunk[ci] == (byte)'^') { negated = true; ci++; }
                bool match = false; int nrange = 0;
                while (true) {
                    if (ci < ce && chunk[ci] == (byte)']' && nrange > 0) { ci++; break; }
                    int lo = GetEsc(chunk, ref ci, ce), hi = lo;
                    if (chunk[ci] == (byte)'-') { ci++; hi = GetEsc(chunk, ref ci, ce); }
                    if (lo <= r && r <= hi) match = true;
                    nrange++;
                }
                if (match == negated) failed = true;
            } else if (c == (byte)'?') {
                if (!failed) {
                    if (s[si] == (byte)'/') failed = true;
                    DecodeRune(s, si, out int w); si += w;
                }
                ci++;
            } else {
                if (c == (byte)'\\') { ci++; if (ci >= ce) throw new BadPattern(); }
                if (!failed) { if (chunk[ci] != s[si]) failed = true; si++; }
                ci++;
            }
        }
        rest = si;
        return !failed;
    }

    static int GetEsc(byte[] chunk, ref int ci, int ce) {
        if (ci >= ce || chunk[ci] == (byte)'-' || chunk[ci] == (byte)']') throw new BadPattern();
        if (chunk[ci] == (byte)'\\') { ci++; if (ci >= ce) throw new BadPattern(); }
        int r = DecodeRune(chunk, ci, out int w);
        if (r == RuneError && w == 1) throw new BadPattern();
        ci += w;
        if (ci >= ce) throw new BadPattern();
        return r;
    }
}
