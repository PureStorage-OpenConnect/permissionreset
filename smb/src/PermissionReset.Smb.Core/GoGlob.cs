// GoGlob is Go's path.Match: the grammar permissionreset's spec matching uses (filepath.Match on
// Linux, where '/' is the only separator and '\' escapes). Case-sensitive, as the NFS run is.
// A malformed pattern matches nothing; build-spec has already refused one at spec load.
// Ported from tools/set-saclonly/SaclOnly.cs; both are tested against the same Go-generated vectors.
namespace PermissionReset.Smb.Core;

public static class GoGlob {
    class BadPattern : Exception { }

    public static bool Match(string pattern, string name) {
        try { return MatchOrThrow(pattern, name); }
        catch (BadPattern) { return false; }
    }

    static bool MatchOrThrow(string pattern, string name) {
        while (pattern.Length > 0) {
            bool star; string chunk;
            ScanChunk(ref pattern, out star, out chunk);
            if (star && chunk.Length == 0) return name.IndexOf('/') < 0;
            string t; bool ok = MatchChunk(chunk, name, out t);
            if (ok && (t.Length == 0 || pattern.Length > 0)) { name = t; continue; }
            if (star) {
                bool advanced = false;
                for (int i = 0; i < name.Length && name[i] != '/'; i++) {
                    if (MatchChunk(chunk, name.Substring(i + 1), out t)) {
                        if (pattern.Length == 0 && t.Length > 0) continue;
                        name = t; advanced = true; break;
                    }
                }
                if (advanced) continue;
            }
            return false;
        }
        return name.Length == 0;
    }

    static void ScanChunk(ref string pattern, out bool star, out string chunk) {
        star = false;
        while (pattern.Length > 0 && pattern[0] == '*') { pattern = pattern.Substring(1); star = true; }
        bool inrange = false;
        int i;
        for (i = 0; i < pattern.Length; i++) {
            char c = pattern[i];
            if (c == '\\') { if (i + 1 < pattern.Length) i++; }
            else if (c == '[') inrange = true;
            else if (c == ']') inrange = false;
            else if (c == '*' && !inrange) break;
        }
        chunk = pattern.Substring(0, i);
        pattern = pattern.Substring(i);
    }

    // One code point (a surrogate pair counts as one, as a Go rune does).
    static int Rune(string s, int at, out int width) {
        if (char.IsHighSurrogate(s[at]) && at + 1 < s.Length && char.IsLowSurrogate(s[at + 1])) {
            width = 2; return char.ConvertToUtf32(s[at], s[at + 1]);
        }
        width = 1; return s[at];
    }

    static bool MatchChunk(string chunk, string s, out string rest) {
        bool failed = false;
        int ci = 0, si = 0;
        while (ci < chunk.Length) {
            if (!failed && si >= s.Length) failed = true;
            char c = chunk[ci];
            if (c == '[') {
                int r = 0, w;
                if (!failed) { r = Rune(s, si, out w); si += w; }
                ci++;
                bool negated = false;
                if (ci < chunk.Length && chunk[ci] == '^') { negated = true; ci++; }
                bool match = false; int nrange = 0;
                while (true) {
                    if (ci < chunk.Length && chunk[ci] == ']' && nrange > 0) { ci++; break; }
                    int lo = GetEsc(chunk, ref ci), hi = lo;
                    if (chunk[ci] == '-') { ci++; hi = GetEsc(chunk, ref ci); }
                    if (lo <= r && r <= hi) match = true;
                    nrange++;
                }
                if (match == negated) failed = true;
            } else if (c == '?') {
                if (!failed) {
                    if (s[si] == '/') failed = true;
                    int w; Rune(s, si, out w); si += w;
                }
                ci++;
            } else {
                if (c == '\\') { ci++; if (ci >= chunk.Length) throw new BadPattern(); }
                if (!failed) { if (chunk[ci] != s[si]) failed = true; si++; }
                ci++;
            }
        }
        rest = failed ? "" : s.Substring(si);
        return !failed;
    }

    static int GetEsc(string chunk, ref int ci) {
        if (ci >= chunk.Length || chunk[ci] == '-' || chunk[ci] == ']') throw new BadPattern();
        if (chunk[ci] == '\\') { ci++; if (ci >= chunk.Length) throw new BadPattern(); }
        int w; int r = Rune(chunk, ci, out w);
        ci += w;
        if (ci >= chunk.Length) throw new BadPattern();
        return r;
    }
}
