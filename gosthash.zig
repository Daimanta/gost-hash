const std = @import("std");
const mem = std.mem;
const assert = @import("std").debug.assert;

var gost_sbox_1: [256]u32 = undefined;
var gost_sbox_2: [256]u32 = undefined;
var gost_sbox_3: [256]u32 = undefined;
var gost_sbox_4: [256]u32 = undefined;

const sbox: [8][16]u32 =
    .{ .{ 4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3 }, .{ 14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9 }, .{ 5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11 }, .{ 7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3 }, .{ 6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2 }, .{ 4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14 }, .{ 13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12 }, .{ 1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12 } };

const SUM_INT_WIDTH = 8;
const HASH_U32_SIZE = 8;
const HASH_BYTE_SIZE = HASH_U32_SIZE * 4;
const HASH_BIT_SIZE = HASH_BYTE_SIZE * 8;

const GostHashCtx = struct {
    sum: [SUM_INT_WIDTH]u32,
    hash: [SUM_INT_WIDTH]u32,
    len: [SUM_INT_WIDTH]u32,
    partial: [HASH_BYTE_SIZE]u8,
    partial_bytes: usize,

    pub fn reset() void {
        .sum = .{0} ** 8;
        .hash = .{0} ** 8;
        .len = .{0} ** 8;
        .partial = .{0} ** 8;
        .partial_bytes = 0;
    }
};

fn gost_encrypt_round(k1: u32, k2: u32, t: *usize, l: *u32, r: *u32) void {
    t.* = (k1) +% r.*;
    l.* ^= gost_sbox_1[t.* & 0xff] ^ gost_sbox_2[(t.* >> 8) & 0xff] ^ gost_sbox_3[(t.* >> 16) & 0xff] ^ gost_sbox_4[t.* >> 24];
    t.* = (k2) +% l.*;
    r.* ^= gost_sbox_1[t.* & 0xff] ^ gost_sbox_2[(t.* >> 8) & 0xff] ^ gost_sbox_3[(t.* >> 16) & 0xff] ^ gost_sbox_4[t.* >> 24];
}

fn gost_encrypt(key: [8]u32, t: *usize, l: *u32, r: *u32) void {
    gost_encrypt_round(key[0], key[1], t, l, r);
    gost_encrypt_round(key[2], key[3], t, l, r);
    gost_encrypt_round(key[4], key[5], t, l, r);
    gost_encrypt_round(key[6], key[7], t, l, r);
    gost_encrypt_round(key[0], key[1], t, l, r);
    gost_encrypt_round(key[2], key[3], t, l, r);
    gost_encrypt_round(key[4], key[5], t, l, r);
    gost_encrypt_round(key[6], key[7], t, l, r);
    gost_encrypt_round(key[0], key[1], t, l, r);
    gost_encrypt_round(key[2], key[3], t, l, r);
    gost_encrypt_round(key[4], key[5], t, l, r);
    gost_encrypt_round(key[6], key[7], t, l, r);
    gost_encrypt_round(key[7], key[6], t, l, r);
    gost_encrypt_round(key[5], key[4], t, l, r);
    gost_encrypt_round(key[3], key[2], t, l, r);
    gost_encrypt_round(key[1], key[0], t, l, r);
    t.* = r.*;
    r.* = l.*;
    l.* = @truncate(u32, t.*);
}

// initialize the lookup tables
fn gosthash_init() void {
    var a: usize = 0;
    var b: usize = 0;
    var i: usize = 0;

    var ax: u32 = undefined;
    var bx: u32 = undefined;
    var cx: u32 = undefined;
    var dx: u32 = undefined;

    i = 0;
    a = 0;
    while (a < 16) : (a += 1) {
        ax = sbox[1][a] << 15;
        bx = sbox[3][a] << 23;
        cx = sbox[5][a];
        cx = (cx >> 1) | (cx << 31);
        dx = sbox[7][a] << 7;

        b = 0;
        while (b < 16) : (b += 1) {
            gost_sbox_1[i] = ax | (sbox[0][b] << 11);
            gost_sbox_2[i] = bx | (sbox[2][b] << 19);
            gost_sbox_3[i] = cx | (sbox[4][b] << 27);
            gost_sbox_4[i] = dx | (sbox[6][b] << 3);
            i += 1;
        }
    }
}

//"chi" compression function. the result is stored over h
fn gosthash_compress(h: *[SUM_INT_WIDTH]u32, m: *[SUM_INT_WIDTH]u32) void {
    var i: usize = 0;
    var l: u32 = undefined;
    var r: u32 = undefined;
    var t: usize = undefined;
    var key: [8]u32 = undefined;
    var u: [8]u32 = undefined;
    var v: [8]u32 = undefined;
    var w: [8]u32 = undefined;
    var s: [8]u32 = undefined;

    mem.copy(u32, &u, h[0..HASH_U32_SIZE]);
    mem.copy(u32, &v, m[0..HASH_U32_SIZE]);
    //@memcpy(&u, h, HASH_BYTE_SIZE);
    //@memcpy(&v, m, HASH_BYTE_SIZE);

    while (i < 8) : (i += 2) {
        w[0] = u[0] ^ v[0]; // w = u xor v */
        w[1] = u[1] ^ v[1];
        w[2] = u[2] ^ v[2];
        w[3] = u[3] ^ v[3];
        w[4] = u[4] ^ v[4];
        w[5] = u[5] ^ v[5];
        w[6] = u[6] ^ v[6];
        w[7] = u[7] ^ v[7];

        // P-Transformation */

        key[0] = (w[0] & 0x000000ff) | ((w[2] & 0x000000ff) << 8) |
            ((w[4] & 0x000000ff) << 16) | ((w[6] & 0x000000ff) << 24);
        key[1] = ((w[0] & 0x0000ff00) >> 8) | (w[2] & 0x0000ff00) |
            ((w[4] & 0x0000ff00) << 8) | ((w[6] & 0x0000ff00) << 16);
        key[2] = ((w[0] & 0x00ff0000) >> 16) | ((w[2] & 0x00ff0000) >> 8) |
            (w[4] & 0x00ff0000) | ((w[6] & 0x00ff0000) << 8);
        key[3] = ((w[0] & 0xff000000) >> 24) | ((w[2] & 0xff000000) >> 16) |
            ((w[4] & 0xff000000) >> 8) | (w[6] & 0xff000000);
        key[4] = (w[1] & 0x000000ff) | ((w[3] & 0x000000ff) << 8) |
            ((w[5] & 0x000000ff) << 16) | ((w[7] & 0x000000ff) << 24);
        key[5] = ((w[1] & 0x0000ff00) >> 8) | (w[3] & 0x0000ff00) |
            ((w[5] & 0x0000ff00) << 8) | ((w[7] & 0x0000ff00) << 16);
        key[6] = ((w[1] & 0x00ff0000) >> 16) | ((w[3] & 0x00ff0000) >> 8) |
            (w[5] & 0x00ff0000) | ((w[7] & 0x00ff0000) << 8);
        key[7] = ((w[1] & 0xff000000) >> 24) | ((w[3] & 0xff000000) >> 16) |
            ((w[5] & 0xff000000) >> 8) | (w[7] & 0xff000000);

        r = h[i]; // encriphering transformation */
        l = h[i + 1];
        gost_encrypt(key, &t, &l, &r);

        s[i] = r;
        s[i + 1] = l;

        if (i == 6) break;

        l = u[0] ^ u[2]; // U = A(U) */
        r = u[1] ^ u[3];
        u[0] = u[2];
        u[1] = u[3];
        u[2] = u[4];
        u[3] = u[5];
        u[4] = u[6];
        u[5] = u[7];
        u[6] = l;
        u[7] = r;

        if (i == 2) // Constant C_3 */
        {
            u[0] ^= 0xff00ff00;
            u[1] ^= 0xff00ff00;
            u[2] ^= 0x00ff00ff;
            u[3] ^= 0x00ff00ff;
            u[4] ^= 0x00ffff00;
            u[5] ^= 0xff0000ff;
            u[6] ^= 0x000000ff;
            u[7] ^= 0xff00ffff;
        }

        l = v[0]; // V = A(A(V)) */
        r = v[2];
        v[0] = v[4];
        v[2] = v[6];
        v[4] = l ^ r;
        v[6] = v[0] ^ r;
        l = v[1];
        r = v[3];
        v[1] = v[5];
        v[3] = v[7];
        v[5] = l ^ r;
        v[7] = v[1] ^ r;
    }

    // 12 rounds of the LFSR (computed from a product matrix) and xor in M */

    u[0] = m[0] ^ s[6];
    u[1] = m[1] ^ s[7];
    u[2] = m[2] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xffff) ^
        (s[1] & 0xffff) ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[6] ^ (s[6] << 16) ^
        (s[7] & 0xffff0000) ^ (s[7] >> 16);
    u[3] = m[3] ^ (s[0] & 0xffff) ^ (s[0] << 16) ^ (s[1] & 0xffff) ^
        (s[1] << 16) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16) ^
        (s[3] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^
        (s[7] << 16) ^ (s[7] >> 16);
    u[4] = m[4] ^
        (s[0] & 0xffff0000) ^ (s[0] << 16) ^ (s[0] >> 16) ^
        (s[1] & 0xffff0000) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16) ^
        (s[3] << 16) ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[6] << 16) ^
        (s[6] >> 16) ^ (s[7] & 0xffff) ^ (s[7] << 16) ^ (s[7] >> 16);
    u[5] = m[5] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xffff0000) ^
        (s[1] & 0xffff) ^ s[2] ^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16) ^
        (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[6] << 16) ^
        (s[6] >> 16) ^ (s[7] & 0xffff0000) ^ (s[7] << 16) ^ (s[7] >> 16);
    u[6] = m[6] ^ s[0] ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[3] ^ (s[3] >> 16) ^
        (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16) ^ s[6] ^
        (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] << 16);
    u[7] = m[7] ^ (s[0] & 0xffff0000) ^ (s[0] << 16) ^ (s[1] & 0xffff) ^
        (s[1] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ s[4] ^ (s[4] >> 16) ^
        (s[5] << 16) ^ (s[5] >> 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^
        (s[7] << 16) ^ (s[7] >> 16);

    // 16 * 1 round of the LFSR and xor in H */

    v[0] = h[0] ^ (u[1] << 16) ^ (u[0] >> 16);
    v[1] = h[1] ^ (u[2] << 16) ^ (u[1] >> 16);
    v[2] = h[2] ^ (u[3] << 16) ^ (u[2] >> 16);
    v[3] = h[3] ^ (u[4] << 16) ^ (u[3] >> 16);
    v[4] = h[4] ^ (u[5] << 16) ^ (u[4] >> 16);
    v[5] = h[5] ^ (u[6] << 16) ^ (u[5] >> 16);
    v[6] = h[6] ^ (u[7] << 16) ^ (u[6] >> 16);
    v[7] = h[7] ^ (u[0] & 0xffff0000) ^ (u[0] << 16) ^ (u[7] >> 16) ^
        (u[1] & 0xffff0000) ^ (u[1] << 16) ^ (u[6] << 16) ^ (u[7] & 0xffff0000);

    // 61 rounds of LFSR, mixing up h (computed from a product matrix) */

    h[0] = (v[0] & 0xffff0000) ^ (v[0] << 16) ^ (v[0] >> 16) ^ (v[1] >> 16) ^
        (v[1] & 0xffff0000) ^ (v[2] << 16) ^ (v[3] >> 16) ^ (v[4] << 16) ^
        (v[5] >> 16) ^ v[5] ^ (v[6] >> 16) ^ (v[7] << 16) ^ (v[7] >> 16) ^
        (v[7] & 0xffff);
    h[1] = (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xffff0000) ^ (v[1] & 0xffff) ^
        v[2] ^ (v[2] >> 16) ^ (v[3] << 16) ^ (v[4] >> 16) ^ (v[5] << 16) ^
        (v[6] << 16) ^ v[6] ^ (v[7] & 0xffff0000) ^ (v[7] >> 16);
    h[2] = (v[0] & 0xffff) ^ (v[0] << 16) ^ (v[1] << 16) ^ (v[1] >> 16) ^
        (v[1] & 0xffff0000) ^ (v[2] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^
        (v[5] >> 16) ^ v[6] ^ (v[6] >> 16) ^ (v[7] & 0xffff) ^ (v[7] << 16) ^
        (v[7] >> 16);
    h[3] = (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xffff0000) ^
        (v[1] & 0xffff0000) ^ (v[1] >> 16) ^ (v[2] << 16) ^ (v[2] >> 16) ^ v[2] ^
        (v[3] << 16) ^ (v[4] >> 16) ^ v[4] ^ (v[5] << 16) ^ (v[6] << 16) ^
        (v[7] & 0xffff) ^ (v[7] >> 16);
    h[4] = (v[0] >> 16) ^ (v[1] << 16) ^ v[1] ^ (v[2] >> 16) ^ v[2] ^
        (v[3] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ (v[5] >> 16) ^
        v[5] ^ (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16);
    h[5] = (v[0] << 16) ^ (v[0] & 0xffff0000) ^ (v[1] << 16) ^ (v[1] >> 16) ^
        (v[1] & 0xffff0000) ^ (v[2] << 16) ^ v[2] ^ (v[3] >> 16) ^ v[3] ^
        (v[4] << 16) ^ (v[4] >> 16) ^ v[4] ^ (v[5] << 16) ^ (v[6] << 16) ^
        (v[6] >> 16) ^ v[6] ^ (v[7] << 16) ^ (v[7] >> 16) ^ (v[7] & 0xffff0000);
    h[6] = v[0] ^ v[2] ^ (v[2] >> 16) ^ v[3] ^ (v[3] << 16) ^ v[4] ^
        (v[4] >> 16) ^ (v[5] << 16) ^ (v[5] >> 16) ^ v[5] ^ (v[6] << 16) ^
        (v[6] >> 16) ^ v[6] ^ (v[7] << 16) ^ v[7];
    h[7] = v[0] ^ (v[0] >> 16) ^ (v[1] << 16) ^ (v[1] >> 16) ^ (v[2] << 16) ^
        (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ v[4] ^ (v[5] >> 16) ^ v[5] ^
        (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16) ^ v[7];
}

fn gosthash_reset(ctx: *GostHashCtx) void {
    ctx.sum = .{0} ** SUM_INT_WIDTH;
    ctx.hash = .{0} ** SUM_INT_WIDTH;
    ctx.len = .{0} ** SUM_INT_WIDTH;
    ctx.partial = .{0} ** HASH_BYTE_SIZE;
    ctx.partial_bytes = 0;
}

// Mix in a 32-byte chunk ("stage 3")
fn gosthash_bytes(ctx: *GostHashCtx, buf: []u8, bits: usize) void {
    var i: usize = 0;
    var j: usize = 0;
    var a: u32 = undefined;
    var b: u32 = undefined;
    var c: u32 = 0;
    var m: [8]u32 = undefined;

    // convert bytes to a long words and compute the sum */

    while (i < 8) : (i += 1) {
        a = buf[j] |
            (@as(u32, buf[j + 1]) << 8) |
            (@as(u32, buf[j + 2]) << 16) |
            (@as(u32, buf[j + 3]) << 24);
        j += 4;
        m[i] = a;
        b = ctx.sum[i];
        c = a + c + ctx.sum[i];
        ctx.sum[i] = c;
        if ((c < a) or (c < b)) {
            c = 1;
        } else {
            c = 0;
        }
    }

    // compress */

    gosthash_compress(&ctx.hash, &m);

    // a 64-bit counter should be sufficient */

    ctx.len[0] += @truncate(u32, bits);
    if (ctx.len[0] < bits) {
        ctx.len[1] += 1;
    }
}

//Mix in len bytes of data for the given buffer.
fn gosthash_update(ctx: *GostHashCtx, buf: []u8, len: usize) void {
    var i: usize = ctx.partial_bytes;
    var j: usize = 0;
    while (i < 32 and j < len) {
        ctx.partial[i] = buf[j];
        i += 1;
        j += 1;
    }

    if (i < 32) {
        ctx.partial_bytes = i;
        return;
    }
    gosthash_bytes(ctx, ctx.partial[0..], HASH_BIT_SIZE);

    while ((j + 32) < len) {
        gosthash_bytes(ctx, buf[j..], HASH_BIT_SIZE);
        j += 32;
    }

    i = 0;
    while (j < len) {
        ctx.partial[i] = buf[j];
        i += 1;
        j += 1;
    }
    ctx.partial_bytes = i;
}

// Compute and save the 32-byte digest. */
fn gosthash_final(ctx: *GostHashCtx, digest: *[HASH_BYTE_SIZE]u8) void {
    var i: usize = 0;
    var j: usize = 0;
    var a: u32 = undefined;

    // adjust and mix in the last chunk */
    if (ctx.partial_bytes > 0) {
        var it: usize = ctx.partial_bytes;
        while (it < ctx.partial.len) : (it += 1) {
            ctx.partial[it] = 0;
        }
        gosthash_bytes(ctx, ctx.partial[0..], ctx.partial_bytes << 3);
    }

    // mix in the length and the sum */
    gosthash_compress(&ctx.hash, &ctx.len);
    gosthash_compress(&ctx.hash, &ctx.sum);

    // convert the output to bytes */
    while (i < 8) : (i += 1) {
        a = ctx.hash[i];
        digest[j] = @truncate(u8, a);
        digest[j + 1] = @truncate(u8, a >> 8);
        digest[j + 2] = @truncate(u8, a >> 16);
        digest[j + 3] = @truncate(u8, a >> 24);
        j += 4;
    }
}

fn digest_to_hex_string(digest: *[HASH_BYTE_SIZE]u8, string: *[2 * HASH_BYTE_SIZE]u8) void {
    var range: [16]u8 = .{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    var i: usize = 0;
    while (i < digest.len) : (i += 1) {
        var upper: u8 = digest[i] >> 4;
        var lower: u8 = digest[i] & 15;

        string[2 * i] = range[upper];
        string[(2 * i) + 1] = range[lower];
    }
}

test "gosthash_init" {
    gosthash_init();
}

test "reset_struct" {
    var hash_struct: GostHashCtx = undefined;
    gosthash_reset(&hash_struct);
}

test "empty string" {
    gosthash_init();
    var hash_struct: GostHashCtx = undefined;
    gosthash_reset(&hash_struct);

    var empty_block: []u8 = &.{};
    gosthash_update(&hash_struct, empty_block, 0);

    var digest: [32]u8 = .{0} ** 32;
    gosthash_final(&hash_struct, &digest);

    var hash_string: [64]u8 = undefined;
    digest_to_hex_string(&digest, &hash_string);
    try std.io.getStdOut().writer().print("\n{s}", .{hash_string});
    assert(mem.eql(u8, hash_string[0..], "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d"));
}
