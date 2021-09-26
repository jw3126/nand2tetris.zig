const std = @import("std");
const ArrayList = std.ArrayList;
const m = @import("mecha");
const testing = std.testing;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator : *std.mem.Allocator = &gpa.allocator;

const spaces_or_tabs = m.discard(
    m.many(
        m.ascii.char(' '), .{.collect=false}
    )
);

const start_comment = m.string("//");
const stop_comment = m.ascii.char('\n'); // TODO eof
const body_comment = m.many(m.ascii.not(stop_comment), .{});
const comment = m.combine(
    .{start_comment, body_comment, stop_comment}
);
const integer = m.int(u16, .{.base=10, .parse_sign=false});

fn isAlphaNum(x : u8) bool {
    return (('0' <= x) and (x<= '9')) or isAlpha(x);
}
fn isAlpha(x : u8) bool {
    if (('a' <= x) and (x<= 'z')) {return true;}
    if (('A' <= x) and (x<= 'Z')) {return true;}
    if (x == '_') {return true;}
    return false;
}
const char_alphanum = m.ascii.wrap(isAlphaNum);
const char_alpha = m.ascii.wrap(isAlpha);
const alphanum = m.many(char_alphanum, .{.min=1,.collect=true});
const whitespace_comment = m.combine(.{spaces_or_tabs, comment});
const identifier = m.asStr(m.combine(
        .{char_alpha, m.many(char_alphanum, .{.collect=false})}
));
const set_addr_name = m.combine(.{m.ascii.char('@'), identifier} );
const set_addr_addr = m.combine(.{m.ascii.char('@'), integer});
const def_label = m.combine(.{
    m.ascii.char('('),
    identifier,
    m.ascii.char(')'),
    }
);

test "set_addr" {
    const test_allocator = testing.allocator;
    var res = try set_addr_name(test_allocator, "@foo ");
    try testing.expect(std.mem.eql(u8, res.value, "foo"));

    res = try set_addr_name(test_allocator, "@R12");
    try testing.expect(std.mem.eql(u8, res.value, "R12"));

    try expectError(set_addr_name(test_allocator, "asdf"), m.Error.ParserFailed);
    try expectError(set_addr_name(test_allocator, "@13123"), m.Error.ParserFailed);
    var resi = try set_addr_addr(test_allocator, "@13123");
    try testing.expectEqual(resi.value, 13123);

    try expectError(set_addr_name(test_allocator, "@?a"), m.Error.ParserFailed);
    try expectError(set_addr_addr(test_allocator, "@?a"), m.Error.ParserFailed);
    try expectError(set_addr_name(test_allocator, "@"), m.Error.ParserFailed);
    try expectError(set_addr_addr(test_allocator, "@"), m.Error.ParserFailed);
}

test "def_label" {
    const test_allocator = testing.allocator;
    var res = try def_label(test_allocator, "(asdf)");
    try testing.expect(std.mem.eql(u8, res.value, "asdf"));


}

pub fn main() anyerror!void {
    defer {
        const leaked = gpa.deinit();
        if (leaked) std.testing.expect(false) catch @panic("Memory problem");
    }
    std.log.info("hello", .{});
    // std.log.info("{s}", .{val.value});
}

test "char_alphanum" {
    const test_allocator = testing.allocator;
    var res = try char_alphanum(test_allocator, "0");
    try testing.expectEqual(res.value, '0');
    res = try char_alphanum(test_allocator, "9");
    try testing.expectEqual(res.value, '9');
    res = try char_alphanum(test_allocator, "4");
    try testing.expectEqual(res.value, '4');
    res = try char_alphanum(test_allocator, "a");
    try testing.expectEqual(res.value, 'a');
    res = try char_alphanum(test_allocator, "D");
    try testing.expectEqual(res.value, 'D');
    try expectError(char_alphanum(test_allocator, "?"), m.Error.ParserFailed);
}

test "char_alphanum" {
    const test_allocator = testing.allocator;
    var res = try char_alphanum(test_allocator, "0");
    try testing.expectEqual(res.value, '0');
    res = try char_alphanum(test_allocator, "9");
    try testing.expectEqual(res.value, '9');
    res = try char_alphanum(test_allocator, "4");
    try testing.expectEqual(res.value, '4');
    res = try char_alphanum(test_allocator, "a");
    try testing.expectEqual(res.value, 'a');
    res = try char_alphanum(test_allocator, "D");
    try testing.expectEqual(res.value, 'D');
    try expectError(char_alphanum(test_allocator, "?"), m.Error.ParserFailed);
}

fn expectError(res : anytype, err_expected : anyerror) anyerror!void {
    if (res) |value| {_=value;unreachable;} else |err| {
        try std.testing.expect(err == err_expected);
        return;
    }
}

test "comment" {
    const test_allocator = testing.allocator;
    const val = try comment(test_allocator, "//lala\n\n");
    defer test_allocator.free(val.value);
    try testing.expect(std.mem.eql(u8, val.value, "lala"));
}

const Register = enum {A,D,M};
const Jump = enum {
    J00,
    JGT,
    JEQ,
    JGE,
    JLT,
    JNE,
    JLE,
    JMP,
};

const Comp = union(enum) {
    zero,
    one,
    neg_one,
    not  : Register,
    neg  : Register,
    copy : Register,
    inc  : Register,
    dec  : Register,

    DpulsA,
    DminusA,
    AminusD,
    DandA,
    DorA,
    DplusM,
    DminusM,
    MminusD,
    DandM,
    DorM,
};

//const CInstr = struct

const CST = union(enum) {
    comment   : ArrayList(u8),
    A_addr    : u16,
    A_name    : ArrayList(u8),
    C         : struct {destA : bool, destD :bool, destM :bool, comp : Comp, jump : Jump},
    def_label : ArrayList(u8),
};

// @R0
// D=M
//
// @R1
// D=D+M
//
// @R2
// M = D
//
// @6
// 0;JMP
// jan@jantop:~/nand2tetris/examples$ ls
// add.asm  loop.asm
// jan@jantop:~/nand2tetris/examples$ cat loop.asm
// // infinite loop
//
// @R0
// M = M +1
//
// @0
// 0;JMP
