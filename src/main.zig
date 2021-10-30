const std = @import("std");
const hasm = @import("hasm.zig");
var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() anyerror!void {
    defer {
        const leaked = gpa.deinit();
        if (leaked) std.testing.expect(false) catch @panic("Memory problem");
    }

    const allocator : *std.mem.Allocator = &gpa.allocator;
    // const path = "/home/jan/nand2tetris/examples/add.asm";
    // const path  ="/home/jan/nand2tetris/projects/06/pong/Pong.asm";
    const path = "/home/jan/projects/LearnZig/nand2tetris/testdata/Prog.asm";
    const instrs = try hasm.parseFileAbsolute(allocator, path);
    defer {
        for (instrs.items) |instr| {
            instr.free(allocator);
        }
        instrs.deinit();
    }
    const instrs_lowered = try hasm.resolveSymbols(allocator, instrs);
    const stdout = std.io.getStdOut().writer();
    var linum : u64 = 0;
    for (instrs_lowered.items) |instr| {
        var mach = try instr.machineCode();
        try stdout.print("{d: >5} ", .{linum});
        try hasm.printMachineInstr(stdout, mach);
        try stdout.print("   // {}\n", .{instr});
        linum += 1;
    }
    for (instrs_lowered.items) |instr| {
        var mach = try instr.machineCode();
        try stdout.print("try testAsm2Hack(test_allocator, \"{}\", 0b{b:0>16};)\n", .{instr, mach});
        linum += 1;
    }
    defer {
        instrs_lowered.deinit();
    }
}
