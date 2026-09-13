const std = @import("std");
const c = @cImport({
    @cInclude("openssl/aes.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
});

// [0, 1, 2, ..., 15]
const iv: []const u8 = iv: {
    var res: []const u8 = &.{};
    for (0..16) |i| {
        res = res ++ .{i};
    }
    break :iv res;
};

pub const Aes = struct {
    pub fn encrypt(msg: []const u8, key: []const u8) []const u8 {
        // AES-256 requires a 32-byte key.
        std.debug.assert(key.len == 32);

        // CBC + PKCS#7 padding means the ciphertext is always
        // at least one byte-block larger than the message.
        const output_len = ((msg.len / 16) + 1) * 16;
        const ciphertext = std.heap.page_allocator.alloc(u8, output_len) catch unreachable;

        const ctx = c.EVP_CIPHER_CTX_new() orelse unreachable;
        defer c.EVP_CIPHER_CTX_free(ctx);

        var written: c_int = 0;
        var final_written: c_int = 0;

        _ = c.EVP_EncryptInit_ex(ctx, c.EVP_aes_256_cbc(), null, key.ptr, iv.ptr);
        _ = c.EVP_EncryptUpdate(ctx, ciphertext.ptr, &written, msg.ptr, @intCast(msg.len));
        _ = c.EVP_EncryptFinal_ex(ctx, ciphertext.ptr + @as(usize, @intCast(written)), &final_written);

        return ciphertext[0..@intCast(written + final_written)];
    }

    pub fn decrypt(msg: []const u8, key: []const u8) []const u8 {
        std.debug.assert(key.len == 32);
        std.debug.assert(msg.len % 16 == 0);

        // Decrypted output can never be larger than the ciphertext.
        const plaintext = std.heap.page_allocator.alloc(u8, msg.len) catch unreachable;

        const ctx = c.EVP_CIPHER_CTX_new() orelse unreachable;
        defer c.EVP_CIPHER_CTX_free(ctx);

        var written: c_int = 0;
        var final_written: c_int = 0;

        _ = c.EVP_DecryptInit_ex(ctx, c.EVP_aes_256_cbc(), null, key.ptr, iv.ptr);
        _ = c.EVP_DecryptUpdate(ctx, plaintext.ptr, &written, msg.ptr, @intCast(msg.len));
        _ = c.EVP_DecryptFinal_ex(ctx, plaintext.ptr + @as(usize, @intCast(written)), &final_written);

        return plaintext[0..@intCast(written + final_written)];
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
    pub fn encrypt(msg: []const u8, key: []const u8) []const u8 {
        std.debug.print("msg: '{s}', key: '{s}'\n", .{ msg, key });
        return msg;
    }
    pub fn decrypt(msg: []const u8, key: []const u8) []const u8 {
        std.debug.print("msg: '{s}', key: '{s}'\n", .{ msg, key });
        return msg;
    }
};

// interface
pub const Encryption = struct {
    ptr: *anyopaque,
    vtab: *const struct {
        encrypt: *const fn ([]const u8, []const u8) []const u8,
        decrypt: *const fn ([]const u8, []const u8) []const u8,
    },

    pub fn init(raw: anytype) Encryption {
        const T = @TypeOf(raw);
        const info = @typeInfo(T);
        if (info != .pointer or info.pointer.is_const) {
            @compileError(std.fmt.comptimePrint("Interface Encryption expects a pointer to non-const, got: {any}\n", .{T}));
        }

        const v = struct {
            pub fn encrypt(msg: []const u8, key: []const u8) []const u8 {
                return info.pointer.child.encrypt(msg, key);
            }
            pub fn decrypt(msg: []const u8, key: []const u8) []const u8 {
                return info.pointer.child.decrypt(msg, key);
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

    pub fn encrypt(self: *Encryption, msg: []const u8, key: []const u8) []const u8 {
        return self.vtab.encrypt(msg, key);
    }
    pub fn decrypt(self: *Encryption, msg: []const u8, key: []const u8) []const u8 {
        return self.vtab.decrypt(msg, key);
    }
};
