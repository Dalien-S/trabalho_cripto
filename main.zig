const std = @import("std");
const Io = std.Io;
const File = Io.File;

const cripto = @import("cripto.zig");

const txt = "This message is going to be encrypted" ++ [_]u8{0};
const message = txt ++ [_]u8{'-'} ** (16 - (@rem(txt.len, 16)));

// const key: [32]u8 = [_]u8{0} ** 32;

fn getMmappedFile(io: std.Io, file: Io.File) !Io.File.MemoryMap {
    return try file.createMemoryMap(io, .{ .len = try file.length(io) });
}

pub fn main(init: std.process.Init) !void {
    _ = init;
    var dgenc = cripto.DGEnc{};
    var aes = cripto.Aes{};
    var rsa = cripto.Rsa{};
    var inters = [_]struct { []const u8, cripto.Encryption }{
        .{ "aes", .init(&aes) },
        .{ "rsa", .init(&rsa) },
        .{ "dgenc", .init(&dgenc) },
    };

    const key = [_]u8{ 'k', 'e', 'y' } ++ [_]u8{0} ** 29;

    for (&inters) |*inter| {
        std.debug.print("{s}:\n", .{inter[0]});
        const encrypted = inter[1].encrypt(message, &key);
        const decrypted = inter[1].decrypt(encrypted, &key);
        std.debug.print("original message => {s}\n", .{message});
        std.debug.print("result from encryption => {s}\n", .{encrypted});
        std.debug.print("result from decryption => {s}\n\n", .{decrypted});

        std.debug.assert(std.mem.eql(u8, message, decrypted));
    }
}

// test "mmap" {
//     const io = init.io;
//     const args = init.minimal.args;
//
//     const filename = std.mem.span(args.vector[1]);
//     std.debug.print("filename: {s}\n", .{filename});
//
//     var file = try Io.Dir.cwd().openFile(io, filename, .{ .mode = .read_write });
//     var mmap = try getMmappedFile(io, file);
//     try mmap.read(io);
//     defer {
//         mmap.write(io) catch {};
//         mmap.destroy(io);
//         file.close(io);
//     }
//
//     std.debug.print("file contents: {s}\n", .{mmap.memory});
// }
