const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode : std.builtin.Mode =  b.standardReleaseOptions();

    // main
    {
        const exe = b.addExecutable("nand2tetris", "src/main.zig");
        exe.addPackagePath("mecha", "deps/mecha/mecha.zig");
        exe.setTarget(target);
        exe.setBuildMode(mode);
        exe.install();

        const run_cmd = exe.run();
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("run", "Run the app");
        run_step.dependOn(&run_cmd.step);
    }
    {
        // assembler
        const exe = b.addExecutable("nand2tetris", "src/assembler.zig");
        exe.addPackagePath("mecha", "deps/mecha/mecha.zig");
        exe.setTarget(target);
        exe.setBuildMode(mode);
        exe.install();

        const run_cmd = exe.run();
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("assembler", "Run the assembler");
        run_step.dependOn(&run_cmd.step);
    }

    // test
    {
        const test_step = b.step("test", "Run the tests");
        const path1 : []const u8 = "src/hasm.zig";
        const path2 : []const u8 = "src/hvm.zig";
        addTests(b, test_step, path1, target, mode);
        addTests(b, test_step, path2, target, mode);
    }
}

pub fn addTests(b: *std.build.Builder,
    test_step : *std.build.Step,
    path : []const u8,
    target : std.build.Target,
    mode : std.builtin.Mode,
) void {
    const tests = b.addTest(path);
    tests.addPackagePath("mecha", "deps/mecha/mecha.zig");
    tests.setTarget(target);
    tests.setBuildMode(mode);
    test_step.dependOn(&tests.step);
}


