/* MODIFIED BY EVERPURE.
 *
 * Source: github.com/Cyberax/go-nfs-client, commit
 * eeba7350de5b260f1c52f52bdd2ea1cb9932d517 (2021-11-02), Apache-2.0.
 * Copyright 2020 Aleksei Besogonov.
 *
 * Modification: package renamed from "internal" to "xdr". No other change.
 *
 * This file is hand-written upstream, NOT generated, and is not reproduced by
 * `make regen-xdr`. nfs4.x uses uint32_t, uint64_t, and int64_t without ever
 * declaring them and they are not goxdr builtins; these aliases are where they
 * come from. Deleting this file makes the package fail to compile in a way that
 * reads as a generator bug.
 */

package xdr

//goland:noinspection GoSnakeCaseUsage
type Uint32_t = uint32

//goland:noinspection GoSnakeCaseUsage
type Uint64_t = uint64

//goland:noinspection GoSnakeCaseUsage
type Int64_t = int64

//goland:noinspection GoSnakeCaseUsage
type XDR_Uint32_t = *XdrUint32

//goland:noinspection GoSnakeCaseUsage
type XdrType_Uint32_t = XdrType_uint32

//goland:noinspection GoSnakeCaseUsage
type XDR_Uint64_t = *XdrUint64

//goland:noinspection GoSnakeCaseUsage
type XdrType_Uint64_t = XdrType_uint64

//goland:noinspection GoSnakeCaseUsage
type XdrType_Int64_t = XdrType_int64

//goland:noinspection GoSnakeCaseUsage
type XDR_Int64_t = *XdrInt64

func MinUint64(i1, i2 uint64) uint64 {
	if i1 < i2 {
		return i1
	}
	return i2
}
