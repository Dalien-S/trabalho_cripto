const std = @import("std");
const Io = std.Io;
const File = Io.File;

const cripto = @import("cripto.zig");

const txt = "This message is going to be encrypted" ++ [_]u8{0};
const message = txt ++ [_]u8{'-'} ** (16 - (@rem(txt.len, 16)));

fn getMmappedFile(io: std.Io, file: Io.File) !Io.File.MemoryMap {
    return try file.createMemoryMap(io, .{ .len = try file.length(io), .offset = 0 });
}

fn testEncryptions(msg: []const cripto.Block, key: []const cripto.Block) void {
    var dgenc = cripto.DGEnc{};
    var aes = cripto.Aes{};
    // var rsa = cripto.Rsa{};
    var inters = [_]struct { []const u8, cripto.Encryption }{
        .{ "aes", .init(&aes) },
        // .{ "rsa", .init(&rsa) },
        .{ "dgenc", .init(&dgenc) },
    };
    const result: []cripto.Block = std.heap.page_allocator.alloc(
        cripto.Block,
        msg.len,
    ) catch &.{};
    const dec_result: []cripto.Block = std.heap.page_allocator.alloc(
        cripto.Block,
        msg.len,
    ) catch &.{};

    for (&inters) |*inter| {
        std.debug.print("trying {s}:\n", .{inter[0]});
        inter[1].encrypt(msg, key, result);
        inter[1].decrypt(result, key, dec_result);
        if (!std.mem.eql(cripto.Block, msg, dec_result)) {
            std.debug.print("{s} failed\n", .{inter[0]});
            std.debug.print("original message => {s}\n", .{
                std.mem.sliceAsBytes(msg),
            });
            std.debug.print("original message(bytes) => {x}\n", .{
                std.mem.sliceAsBytes(msg),
            });
            std.debug.print("key => {s}\n", .{
                std.mem.sliceAsBytes(key),
            });
            std.debug.print("key(bytes) => {x}\n", .{
                std.mem.sliceAsBytes(key),
            });
            std.debug.print(
                "result from encryption(bytes) => {x}\n",
                .{std.mem.sliceAsBytes(result)},
            );
            std.debug.print(
                "result from decryption(bytes) => {x}\n\n",
                .{std.mem.sliceAsBytes(dec_result)},
            );
        } else {
            std.debug.print("Worked!\n", .{});
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const args = init.minimal.args;

    const filename = std.mem.span(args.vector[1]);
    std.debug.print("filename: {s}\n", .{filename});

    var file = try Io.Dir.cwd().openFile(io, filename, .{ .mode = .read_write });
    defer file.close(io);
    const size = try file.length(io);
    var count = size / @sizeOf(cripto.Block);
    if (size % @sizeOf(cripto.Block) != 0) {
        count += 1;
    }
    const text = try std.heap.page_allocator.alignedAlloc(
        cripto.Block,
        null,
        count,
    );
    @memset(text, cripto.Block{ 0, 0, 0, 0, 0, 0, 0, 0 });
    const bytes = std.mem.sliceAsBytes(text);
    _ = try file.readPositionalAll(io, bytes, 0);

    const key: [9]cripto.Block = comptime blk: {
        const key_text =
            \\ As armas e os barões assinalados
            \\ Que da Ocidental praia Lusitana,
            \\ Por mares nunca dantes navegados
            \\ Passaram ainda além da Taprobana,
            \\ Em perigos e guerras esforçados
            \\ Mais do que prometia a força humana
            \\ E entre gente remota edificaram
            \\ Novo Reino, que tanto sublimaram
        ;
        var words = [_]cripto.Block{cripto.Block{ 0, 0, 0, 0, 0, 0, 0, 0 }} ** 9;
        const key_bytes = std.mem.sliceAsBytes(words[0..]);
        @memcpy(key_bytes[0..key_text.len], key_text);
        break :blk words;
    };

    testEncryptions(text, @ptrCast(@alignCast(&key)));
    // testEncryptions(message, &key);
}
