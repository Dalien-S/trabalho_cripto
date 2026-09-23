const std = @import("std");

pub fn build(b: *std.Build) void {
    b.resolveInstallPrefix(b.pathFromRoot("."), .{});

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "cripto",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    exe.root_module.addIncludePath(b.path("."));
    // exe.root_module.addCSourceFile(.{
    //     .file = b.path("vectorized_dgenc.c"),
    //     .flags = &.{
    //         "-mavx512f",
    //         "-mavx512bw",
    //         "-march=native",
    //     },
    // });
    exe.root_module.addObjectFile(b.path("vectorized_dgenc.o"));

    exe.root_module.linkSystemLibrary("ssl", .{});
    exe.root_module.linkSystemLibrary("crypto", .{});

    // b.installArtifact(exe);
    const install = b.addInstallArtifact(exe, .{
        .dest_dir = .{ .override = .prefix },
    });

    b.getInstallStep().dependOn(&install.step);

    // rule for running
    const run_exe = b.addRunArtifact(exe);
    const run_step = b.step("run", "Run the main program");
    run_step.dependOn(&run_exe.step);
}
