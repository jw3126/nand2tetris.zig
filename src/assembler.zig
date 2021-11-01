const std = @import("std");
const hasm = @import("hasm.zig");
var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() anyerror!void {
    defer {
        const leaked = gpa.deinit();
        if (leaked) std.testing.expect(false) catch @panic("Memory problem");
    }

    const allocator : *std.mem.Allocator = &gpa.allocator;
    const path_asm = "/home/jan/projects/LearnZig/nand2tetris/testdata/Prog.asm";
    const path_out = "/tmp/Prog.hack";
    std.log.info("in: {s}\nout: {s}", .{path_asm, path_out});
    try hasm.assembleFileAbsolute(allocator, path_asm, path_out);
}
