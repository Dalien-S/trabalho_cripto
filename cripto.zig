const std = @import("std");
const aes = std.crypto.core.aes;
const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
    @cInclude("openssl/err.h");
    @cInclude("vectorized_dgenc.h");
});

pub const Block = @Vector(16, u32);
pub const RsaOutputBlock = @Vector(64, u32);
pub const zero_block = Block{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

// [0, 1, 2, ..., 15]
const iv: []const u8 = iv: {
    var res: []const u8 = &.{};
    for (0..16) |i| {
        res = res ++ .{i};
    }
    break :iv res;
};

pub const Aes = struct {
    pub fn encrypt(
        message: []const Block,
        key: []const Block,
        output: []Block,
    ) void {
        const msg = std.mem.sliceAsBytes(message);
        const k: [32]u8 = std.mem.sliceAsBytes(key)[0..32].*;
        const out = std.mem.sliceAsBytes(output);

        var cipher = aes.Aes256.initEnc(k);
        var i: usize = 0;
        while (i < msg.len) : (i += 16) {
            cipher.encrypt(
                @ptrCast(out[i .. i + 16].ptr),
                @ptrCast(msg[i .. i + 16].ptr),
            );
        }
    }

    pub fn decrypt(
        message: []const Block,
        key: []const Block,
        output: []Block,
    ) void {
        const msg = std.mem.sliceAsBytes(message);
        const k = std.mem.sliceAsBytes(key)[0..32].*;
        const out = std.mem.sliceAsBytes(output);

        var cipher = aes.Aes256.initDec(k);
        var i: usize = 0;
        while (i < msg.len) : (i += 16) {
            cipher.decrypt(
                @ptrCast(out[i .. i + 16].ptr),
                @ptrCast(msg[i .. i + 16].ptr),
            );
        }
    }
};

pub const Rsa = struct {
    var rsa_key: ?*c.EVP_PKEY = null;
    var rsa_ctx: ?*c.EVP_PKEY_CTX = null;

    pub fn setup() !void {
        try generateRsaKey();
        rsa_ctx = c.EVP_PKEY_CTX_new(rsa_key.?, null) orelse
            return error.CtxCreation;
    }

    pub fn delete() !void {
        c.EVP_PKEY_CTX_free(rsa_ctx);
    }

    pub fn encrypt(
        msg: []const Block,
        result: []RsaOutputBlock,
    ) !void {
        if (c.EVP_PKEY_encrypt_init(rsa_ctx) != 1) return error.EncryptionInit;
        var size: usize = 0;
        for (msg, 0..) |*block, i| {
            const r1 = c.EVP_PKEY_encrypt(
                rsa_ctx,
                null,
                &size,
                @ptrCast(@alignCast(block)),
                @sizeOf(Block),
            );
            if (r1 != 1) {
                const err = c.ERR_get_error();
                std.debug.print("first encrypt: {}: {s}\n", .{
                    r1,
                    std.mem.span(c.ERR_error_string(err, null)),
                });
            }

            const r2 = c.EVP_PKEY_encrypt(
                rsa_ctx,
                @ptrCast(@alignCast(&result[i])),
                &size,
                @ptrCast(@alignCast(block)),
                @sizeOf(Block),
            );
            if (r2 != 1) {
                const err = c.ERR_get_error();
                std.debug.print("second encrypt: {}: {s}\n", .{
                    r2,
                    std.mem.span(c.ERR_error_string(err, null)),
                });
            }
        }
    }

    comptime {
        if (@sizeOf(RsaOutputBlock) != 256 or @sizeOf(Block) != 64) {
            @compileError(
                std.fmt.comptimePrint("@sizeOf(Block) == {}\n@sizeOf(RsaOutputBlock) == {}\n", .{
                    @sizeOf(Block),
                    @sizeOf(RsaOutputBlock),
                }),
            );
        }
    }

    pub fn decrypt(
        msg: []const RsaOutputBlock,
        result: []Block,
    ) !void {
        if (c.EVP_PKEY_decrypt_init(rsa_ctx) != 1) return;
        var size: usize = 0;
        for (msg, 0..) |*block, i| {
            const r1 = c.EVP_PKEY_decrypt(
                rsa_ctx,
                null,
                &size,
                @ptrCast(@alignCast(block)),
                @sizeOf(RsaOutputBlock),
            );
            if (r1 != 1) {
                const err = c.ERR_get_error();
                std.debug.print("first decrypt: {}: {s}\n", .{
                    r1,
                    std.mem.span(c.ERR_error_string(err, null)),
                });
            }

            const r2 = c.EVP_PKEY_decrypt(
                rsa_ctx,
                @ptrCast(@alignCast(&result[i])),
                &size,
                @ptrCast(@alignCast(block)),
                @sizeOf(RsaOutputBlock),
            );
            if (r2 != 1) {
                const err = c.ERR_get_error();
                std.debug.print("second decrypt: {}: {s}\n", .{
                    r2,
                    std.mem.span(c.ERR_error_string(err, null)),
                });
            }
        }
    }

    pub fn generateRsaKey() !void {
        const ctx = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_RSA, null) orelse return error.OpenSSL;
        defer c.EVP_PKEY_CTX_free(ctx);

        if (c.EVP_PKEY_keygen_init(ctx) != 1) return error.OpenSSL;
        if (c.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) != 1) return error.OpenSSL;

        var key: ?*c.EVP_PKEY = null;
        if (c.EVP_PKEY_keygen(ctx, &key) != 1) return error.OpenSSL;

        rsa_key = key orelse return error.OpenSSL;
    }
};

pub const DGEnc = struct {
    const shuffles: [4]Block = .{
        Block{
            15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        },
        Block{
            7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
        },
        Block{
            3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
        },
        Block{
            1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14,
        },
    };

    pub fn encrypt(
        text: []const Block,
        key: []const Block,
        result: []Block,
    ) void {
        const mask: Block = generateMask(key);
        const reduced_mask = @reduce(.Add, mask);

        for (text, 0..) |block, i| {
            const xored = block ^ mask;
            const reduced = @reduce(.Add, xored);
            const red_xor_mask = reduced ^ reduced_mask;
            const res = switch (red_xor_mask & 3) {
                0 => @shuffle(u32, xored, undefined, shuffles[0]),
                1 => @shuffle(u32, xored, undefined, shuffles[1]),
                2 => @shuffle(u32, xored, undefined, shuffles[2]),
                3 => @shuffle(u32, xored, undefined, shuffles[3]),
                else => unreachable,
            };
            result[i] = res;
        }
    }

    pub fn decrypt(
        text: []const Block,
        key: []const Block,
        result: []Block,
    ) void {
        const mask: Block = generateMask(key);
        const reduced_mask = @reduce(.Add, mask);

        for (text, 0..) |block, i| {
            const reduced = @reduce(.Add, block);
            const red_xor_mask = reduced ^ reduced_mask;
            const res = switch (red_xor_mask & 3) {
                0 => @shuffle(u32, block, undefined, shuffles[0]),
                1 => @shuffle(u32, block, undefined, shuffles[1]),
                2 => @shuffle(u32, block, undefined, shuffles[2]),
                3 => @shuffle(u32, block, undefined, shuffles[3]),
                else => unreachable,
            };
            const xored = res ^ mask;
            result[i] = xored;
        }
    }

    inline fn generateMask(key: []const Block) Block {
        var res: Block = zero_block;
        for (key) |item| {
            res ^= item;
        }
        return res;
    }
};

pub const VectorialDGEnc = struct {
    pub fn encrypt(
        msg: []const Block,
        key: []const Block,
        result: []Block,
    ) void {
        c.vdgencEncrypt(
            @ptrCast(msg.ptr),
            @ptrCast(key.ptr),
            @ptrCast(result.ptr),
            msg.len,
            key.len,
        );
    }

    pub fn decrypt(
        msg: []const Block,
        key: []const Block,
        result: []Block,
    ) void {
        c.vdgencDecrypt(
            @ptrCast(msg.ptr),
            @ptrCast(key.ptr),
            @ptrCast(result.ptr),
            msg.len,
            key.len,
        );
    }
};
