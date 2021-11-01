const std = @import("std");
const hasm = @import("hasm.zig");
var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() anyerror!void {
    defer {
        const leaked = gpa.deinit();
        if (leaked) std.testing.expect(false) catch @panic("Memory problem");
    }

    const allocator : *std.mem.Allocator = &gpa.allocator;
    // const path_asm = "/home/jan/nand2tetris/projects/06/max/Max.asm";
    // const path_out = "/home/jan/nand2tetris/projects/06/max/Max.hack";
    const path_asm = "/home/jan/nand2tetris/projects/06/pong/Pong.asm";
    const path_out = "/home/jan/nand2tetris/projects/06/pong/Pong.hack";
    std.log.info("in: {s}\nout: {s}", .{path_asm, path_out});
    try hasm.assembleFileAbsolute(allocator, path_asm, path_out);
}
