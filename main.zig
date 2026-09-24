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

fn testNormal(
    io: std.Io,
    msg: []const cripto.Block,
    key: []const cripto.Block,
    comptime module: type,
    comptime name: []const u8,
) !void {
    const encrypted = try std.heap.page_allocator.alloc(cripto.Block, msg.len);
    const decrypted = try std.heap.page_allocator.alloc(cripto.Block, msg.len);
    defer std.heap.page_allocator.free(encrypted);
    defer std.heap.page_allocator.free(decrypted);

    const e_start = Timestamp.now(io, .cpu_process);
    module.encrypt(msg, key, encrypted);
    const e_end = Timestamp.now(io, .cpu_process);
    const e_duration = Timestamp.durationTo(e_start, e_end).toNanoseconds();
    std.debug.print("{s} encryption: {}\n", .{ name, e_duration });

    const d_start = Timestamp.now(io, .cpu_process);
    module.decrypt(encrypted, key, decrypted);
    const d_end = Timestamp.now(io, .cpu_process);
    const d_duration = Timestamp.durationTo(d_start, d_end).toNanoseconds();
    std.debug.print("{s} decryption: {}\n", .{ name, d_duration });

    if (!std.mem.eql(cripto.Block, decrypted, msg)) {
        std.debug.print("{s} FAIL!\n", .{name});
    }
}

fn testRsa(io: std.Io, msg: []const cripto.Block) !void {
    const encrypted = try std.heap.page_allocator.alloc(cripto.RsaOutputBlock, msg.len);
    const decrypted = try std.heap.page_allocator.alloc(cripto.Block, msg.len);
    defer std.heap.page_allocator.free(encrypted);
    defer std.heap.page_allocator.free(decrypted);

    const e_start = Timestamp.now(io, .cpu_process);
    cripto.Rsa.encrypt(msg, encrypted);
    const e_end = Timestamp.now(io, .cpu_process);
    const e_duration = Timestamp.durationTo(e_start, e_end).toNanoseconds();
    std.debug.print("rsa encryption: {}\n", .{e_duration});

    const d_start = Timestamp.now(io, .cpu_process);
    cripto.Rsa.decrypt(encrypted, decrypted);
    const d_end = Timestamp.now(io, .cpu_process);
    const d_duration = Timestamp.durationTo(d_start, d_end).toNanoseconds();
    std.debug.print("rsa decryption: {}\n", .{d_duration});

    if (!std.mem.eql(cripto.Block, decrypted, msg)) {
        std.debug.print("rsa FAIL!\n", .{});
    }
}

fn testEncryptionsTime(io: std.Io, key: []const cripto.Block, filenames: []const []const u8, options: struct {
    runAes: bool,
    runRsa: bool,
    runDgenc: bool,
    runVdgenc: bool,
    proper: bool,
}) !void {
    const numberOfRuns: usize = if (options.proper) 30 else 1;
    for (filenames) |filename| {
        var file = try Io.Dir.cwd().openFile(io, filename, .{ .mode = .read_write });
        defer file.close(io);

        const msg: []cripto.Block = try getPaddedText(io, file);
        defer std.heap.page_allocator.free(msg);

        if (options.runAes) {
            for (0..numberOfRuns) |_| {
                try testNormal(io, msg, key, cripto.Aes, "aes");
            }
        }
        if (options.runRsa) {
            for (0..numberOfRuns) |_| {
                try testRsa(io, msg);
            }
        }
        if (options.runDgenc) {
            for (0..numberOfRuns) |_| {
                try testNormal(io, msg, key, cripto.DGEnc, "dgenc");
            }
        }
        if (options.runVdgenc) {
            for (0..numberOfRuns) |_| {
                try testNormal(io, msg, key, cripto.VectorialDGEnc, "vdgenc");
            }
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var runAes: bool = false;
    var runRsa: bool = false;
    var runDgenc: bool = false;
    var runVdgenc: bool = false;
    var proper: bool = false;

    var args_iter = init.minimal.args.iterate();
    _ = args_iter.next();
    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "dgenc")) {
            runDgenc = true;
        } else if (std.mem.eql(u8, arg, "vecdgenc")) {
            runVdgenc = true;
        } else if (std.mem.eql(u8, arg, "aes")) {
            runAes = true;
        } else if (std.mem.eql(u8, arg, "rsa")) {
            runRsa = true;
        } else if (std.mem.eql(u8, arg, "--proper")) {
            proper = true;
        } else {
            std.debug.print("Unknown argument {s}, please use one of the following: \n", .{arg});
            std.debug.print("dgenc, vecdgenc, aes, rsa, --proper\n", .{});
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

    try testEncryptionsTime(
        io,
        @ptrCast(@alignCast(&key)),
        &.{
            "akatsuki.txt",
            "13-sonetos.txt",
            "os-lusiadas-cantos-i-v.txt",
            "les-miserables.txt",
        },
        .{
            .runAes = runAes,
            .runRsa = runRsa,
            .runDgenc = runDgenc,
            .runVdgenc = runVdgenc,
            .proper = proper,
        },
    );
}
