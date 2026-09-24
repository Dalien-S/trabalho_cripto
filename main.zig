const std = @import("std");
const Io = std.Io;
const File = Io.File;
const Timestamp = Io.Timestamp;
const Duration = Io.Duration;
const Clock = Io.Clock;
const ArrayList = std.ArrayList;

const cripto = @import("cripto.zig");

const txt = "This message is going to be encrypted" ++ [_]u8{0};
const message = txt ++ [_]u8{'-'} ** (16 - (@rem(txt.len, 16)));

const ResultTimes = struct {
    encryption_used: []const u8,
    decryption_times: ArrayList(struct {
        filesize: usize,
        decryption_time: i96,
    }), // nanoseconds
};

fn getPaddedText(io: std.Io, file: Io.File) ![]cripto.Block {
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

    @memset(
        text,
        cripto.zero_block,
    );

    const bytes = std.mem.sliceAsBytes(text);
    _ = try file.readPositionalAll(io, bytes, 0);

    return text;
}

fn testEncryptionsTime(
    io: std.Io,
    encryptions: []cripto.Encryption,
    key: []const cripto.Block,
    filenames: []const []const u8,
    number_of_runs: usize,
    clock_type: Clock,
) ![]ResultTimes {
    var results = try std.heap.page_allocator.alloc(ResultTimes, encryptions.len);
    for (results, encryptions) |*result, encryption| {
        result.* = .{
            .encryption_used = encryption.name(),
            .decryption_times = .empty,
        };
    }

    for (filenames) |filename| {
        var file = try Io.Dir.cwd().openFile(io, filename, .{ .mode = .read_write });
        defer file.close(io);

        const text: []cripto.Block = try getPaddedText(io, file);
        const encrypted: []cripto.Block = try std.heap.page_allocator.alloc(cripto.Block, text.len);
        const decrypted: []cripto.Block = try std.heap.page_allocator.alloc(cripto.Block, text.len);
        defer std.heap.page_allocator.free(text);
        defer std.heap.page_allocator.free(encrypted);
        defer std.heap.page_allocator.free(decrypted);

        for (encryptions, 0..) |*encryption, i| {
            std.log.debug("running {s}\n", .{encryption.name()});
            encryption.encrypt(text, key, encrypted);
            const average: i96 = avg: {
                var total: i96 = 0;
                var highest_duration: i96 = 0;
                var lowest_duration: i96 = std.math.maxInt(i96);

                for (0..number_of_runs + 2) |_| {
                    const start = Timestamp.now(io, clock_type);
                    encryption.decrypt(encrypted, key, decrypted);
                    const end = Timestamp.now(io, clock_type);
                    const duration = Timestamp.durationTo(start, end).toNanoseconds();
                    if (duration > highest_duration) {
                        highest_duration = duration;
                    }
                    if (duration < lowest_duration) {
                        lowest_duration = duration;
                    }
                    total += duration;

                    if (!std.mem.eql(cripto.Block, text, decrypted)) {
                        std.debug.print("{s} decryption failed!\n", .{encryption.name()});
                        return error.DecryptionFailed;
                    }
                }

                const normalized_time = total - highest_duration - lowest_duration;
                break :avg @divTrunc(normalized_time, @as(i96, @intCast(number_of_runs)));
            };

            try results[i].decryption_times.append(std.heap.page_allocator, .{
                .filesize = try file.length(io),
                .decryption_time = average,
            });
        }
    }

    return results;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.arena.allocator();

    var used_encryptions = ArrayList(cripto.Encryption).empty;
    defer used_encryptions.clearAndFree(allocator);

    var args_iter = init.minimal.args.iterate();
    _ = args_iter.next();
    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "dgenc")) {
            try used_encryptions.append(allocator, .init(@constCast(&cripto.DGEnc{})));
        } else if (std.mem.eql(u8, arg, "vecdgenc")) {
            try used_encryptions.append(allocator, .init(@constCast(&cripto.VectorialDGEnc{})));
        } else if (std.mem.eql(u8, arg, "aes")) {
            try used_encryptions.append(allocator, .init(@constCast(&cripto.Aes{})));
        } else if (std.mem.eql(u8, arg, "rsa")) {
            try used_encryptions.append(allocator, .init(@constCast(&cripto.Rsa{})));
        } else {
            std.debug.print("Unknown argument {s}, please use one of the following: \n", .{arg});
            std.debug.print("dgenc, vecdgenc, aes, rsa\n", .{});
        }
    }

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
        var words = [_]cripto.Block{cripto.zero_block} ** 9;
        const key_bytes = std.mem.sliceAsBytes(words[0..]);
        @memcpy(key_bytes[0..key_text.len], key_text);
        break :blk words;
    };

    const results = try testEncryptionsTime(
        io,
        used_encryptions.items,
        @ptrCast(@alignCast(&key)),
        &.{
            "akatsuki.txt",
            "13-sonetos.txt",
            "os-lusiadas-cantos-i-v.txt",
            "les-miserables.txt",
        },
        100,
        .cpu_process,
    );
    defer std.heap.page_allocator.free(results);

    for (results) |result| {
        std.debug.print("result: {s}\n", .{result.encryption_used});
        for (result.decryption_times.items, 0..) |time, i| {
            std.debug.print("{d}: {any}\n", .{ i, time });
        }
    }
}
