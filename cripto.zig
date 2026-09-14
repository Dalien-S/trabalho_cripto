const std = @import("std");
const c = @cImport({
    @cInclude("openssl/aes.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
});

pub const Block = @Vector(16, u32);
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
    pub fn encrypt(message: []const Block, key: []const Block, output: []Block) void {
        const msg = std.mem.sliceAsBytes(message);
        const k = std.mem.sliceAsBytes(key)[0..32];
        const out = std.mem.sliceAsBytes(output);
        // AES-256 requires a 32-byte key.
        std.debug.assert(k.len == 32);

        const ctx = c.EVP_CIPHER_CTX_new() orelse unreachable;
        _ = c.EVP_CIPHER_CTX_set_padding(ctx, 0);
        defer c.EVP_CIPHER_CTX_free(ctx);

        var written: c_int = 0;
        var final_written: c_int = 0;

        _ = c.EVP_EncryptInit_ex(ctx, c.EVP_aes_256_cbc(), null, k.ptr, iv.ptr);
        _ = c.EVP_EncryptUpdate(ctx, out.ptr, &written, msg.ptr, @intCast(msg.len));
        _ = c.EVP_EncryptFinal_ex(ctx, out.ptr + @as(usize, @intCast(written)), &final_written);
    }

    pub fn decrypt(message: []const Block, key: []const Block, output: []Block) void {
        const msg = std.mem.sliceAsBytes(message);
        const k = std.mem.sliceAsBytes(key)[0..32];
        const out = std.mem.sliceAsBytes(output);

        const ctx = c.EVP_CIPHER_CTX_new() orelse unreachable;
        _ = c.EVP_CIPHER_CTX_set_padding(ctx, 0);
        defer c.EVP_CIPHER_CTX_free(ctx);

        var written: c_int = 0;
        var final_written: c_int = 0;

        _ = c.EVP_DecryptInit_ex(ctx, c.EVP_aes_256_cbc(), null, k.ptr, iv.ptr);
        _ = c.EVP_DecryptUpdate(ctx, out.ptr, &written, msg.ptr, @intCast(msg.len));
        _ = c.EVP_DecryptFinal_ex(ctx, out.ptr + @as(usize, @intCast(written)), &final_written);
    }
};

pub const Rsa = struct {
    var rsa_key: ?*c.EVP_PKEY = null;

    pub fn encrypt(msg: []const u8, _: []const u8) []const u8 {
        if (rsa_key == null) generateRsaKey() catch return &.{};

        const ctx = c.EVP_PKEY_CTX_new(rsa_key.?, null) orelse return &.{};
        defer c.EVP_PKEY_CTX_free(ctx);

        if (c.EVP_PKEY_encrypt_init(ctx) != 1) return &.{};
        if (c.EVP_PKEY_CTX_set_rsa_padding(ctx, c.RSA_PKCS1_OAEP_PADDING) != 1) return &.{};

        var size: usize = 0;
        if (c.EVP_PKEY_encrypt(ctx, null, &size, msg.ptr, msg.len) != 1) return &.{};

        const result = std.heap.page_allocator.alloc(u8, size) catch return &.{};
        errdefer std.heap.page_allocator.free(result);

        if (c.EVP_PKEY_encrypt(ctx, result.ptr, &size, msg.ptr, msg.len) != 1) return &.{};

        return result[0..size];
    }

    pub fn decrypt(msg: []const u8, _: []const u8) []const u8 {
        const key = rsa_key orelse return &.{};

        const ctx = c.EVP_PKEY_CTX_new(key, null) orelse return &.{};
        defer c.EVP_PKEY_CTX_free(ctx);

        if (c.EVP_PKEY_decrypt_init(ctx) != 1) return &.{};
        if (c.EVP_PKEY_CTX_set_rsa_padding(ctx, c.RSA_PKCS1_OAEP_PADDING) != 1) return &.{};

        var size: usize = 0;
        if (c.EVP_PKEY_decrypt(ctx, null, &size, msg.ptr, msg.len) != 1)
            return &.{};

        const result = std.heap.page_allocator.alloc(u8, size) catch return &.{};
        errdefer std.heap.page_allocator.free(result);

        if (c.EVP_PKEY_decrypt(ctx, result.ptr, &size, msg.ptr, msg.len) != 1)
            return &.{};

        return result[0..size];
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
            const shuffle1 = @shuffle(u32, xored, undefined, Block{
                3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
            });
            const shuffle2 = @shuffle(u32, xored, undefined, Block{
                1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14,
            });
            const res = if (red_xor_mask & 1 != 0) shuffle1 else shuffle2;
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
            const shuffle1 = @shuffle(u32, block, undefined, Block{
                3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
            });
            const shuffle2 = @shuffle(u32, block, undefined, Block{
                1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14,
            });
            const res = if (red_xor_mask & 1 != 0) shuffle1 else shuffle2;
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

// pub const VectorialDGEnc = struct {
//     const c = @cImport({
//         @cInclude("vectorized_dgenc.h");
//     });
//     pub fn encrypt(
//         msg: []const Block,
//         key: []const Block,
//         result: []Block,
//     ) void {
//         c.vdgencEncrypt(
//             @ptrCast(msg.ptr),
//             @ptrCast(key.ptr),
//             @ptrCast(result.ptr),
//         );
//     }

//     pub fn decrypt(
//         msg: []const Block,
//         key: []const Block,
//         result: []Block,
//     ) void {
//         c.vdgencDecrypt(
//             @ptrCast(msg.ptr),
//             @ptrCast(key.ptr),
//             @ptrCast(result.ptr),
//         );
//     }
// };

// interface
pub const Encryption = struct {
    ptr: *anyopaque,
    vtab: *const struct {
        encrypt: *const fn ([]const Block, []const Block, []Block) void,
        decrypt: *const fn ([]const Block, []const Block, []Block) void,
    },

    pub fn init(raw: anytype) Encryption {
        const T = @TypeOf(raw);
        const info = @typeInfo(T);
        if (info != .pointer or info.pointer.is_const) {
            @compileError(std.fmt.comptimePrint("Interface Encryption expects a pointer to non-const, got: {any}\n", .{T}));
        }

        const v = struct {
            pub fn encrypt(
                msg: []const Block,
                key: []const Block,
                result: []Block,
            ) void {
                return info.pointer.child.encrypt(msg, key, result);
            }
            pub fn decrypt(
                msg: []const Block,
                key: []const Block,
                result: []Block,
            ) void {
                return info.pointer.child.decrypt(msg, key, result);
            }
        };

        return .{
            .ptr = @ptrCast(@alignCast(raw)),
            .vtab = &.{
                .encrypt = v.encrypt,
                .decrypt = v.decrypt,
            },
        };
    }

    pub fn encrypt(
        self: *Encryption,
        msg: []const Block,
        key: []const Block,
        result: []Block,
    ) void {
        return self.vtab.encrypt(msg, key, result);
    }
    pub fn decrypt(
        self: *Encryption,
        msg: []const Block,
        key: []const Block,
        result: []Block,
    ) void {
        return self.vtab.decrypt(msg, key, result);
    }
};
