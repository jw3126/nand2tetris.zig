const std = @import("std");
const hasm = @import("hasm.zig");
var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() anyerror!void {
    defer {
        const leaked = gpa.deinit();
        if (leaked) std.testing.expect(false) catch @panic("Memory problem");
    }

    const allocator : *std.mem.Allocator = &gpa.allocator;
    const stdout = std.io.getStdOut().writer();
    const path = "/home/jan/nand2tetris/examples/add.asm";
    const toks = try hasm.tokenizeFileAbsolute(allocator, path);
    defer hasm.freeTokens(allocator, toks);
    for (toks.items) |tok| {
        try hasm.printToken(stdout, tok);
    }
    try stdout.print("\n", .{});
}
