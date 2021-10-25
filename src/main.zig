const std = @import("std");
const hasm = @import("hasm.zig");
var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() anyerror!void {
    defer {
        const leaked = gpa.deinit();
        if (leaked) std.testing.expect(false) catch @panic("Memory problem");
    }

    const allocator : *std.mem.Allocator = &gpa.allocator;
    const path = "/home/jan/nand2tetris/examples/add.asm";
    _ = try hasm.parseFileAbsolute(allocator, path);
}
