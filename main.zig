const std = @import("std");
const c = @cImport({
    @cInclude("openssl/aes.h");
    @cInclude("openssl/rsa.h");
});

const Io = std.Io;
const File = Io.File;

const my_key = "This is a very secure key";
const text = "Text";

const key: [32]u8 = [_]u8{0} ** 32;

fn getMmappedFile(io: std.Io, file: Io.File) !Io.File.MemoryMap {
    return try file.createMemoryMap(io, .{ .len = try file.length(io) });
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const args = init.minimal.args;

    const filename = std.mem.span(args.vector[1]);
    std.debug.print("filename: {s}\n", .{filename});

    // TODO:
    // var aes_key: c.AES_KEY = undefined;
    //
    // if (c.AES_set_encrypt_key(&my_key, 256, &aes_key) != 0) {
    //     return error.InvalidKey;
    // }

    var file = try Io.Dir.cwd().openFile(io, filename, .{ .mode = .read_write });
    var mmap = try getMmappedFile(io, file);
    try mmap.read(io);
    defer {
        mmap.write(io) catch {};
        mmap.destroy(io);
        file.close(io);
    }

    std.debug.print("file contents: {s}\n", .{mmap.memory});
}
