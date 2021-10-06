const std = @import("std");
const m = @import("mecha");
const testing = std.testing;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator : *std.mem.Allocator = &gpa.allocator;

const spaces_or_tabs = m.discard(
    m.many(
        m.ascii.char(' '), .{.collect=false}
    )
);

fn mkComment(content : [] const u8) Token {
    return Token{.comment=content};
}
const start_comment = m.string("//");
const stop_comment = m.ascii.char('\n'); // TODO eof
const body_comment = m.many(m.ascii.not(stop_comment), .{});
const comment : m.Parser(Token) = m.map(Token,
    mkComment,
    m.combine(
        .{start_comment, body_comment, stop_comment}
    ),
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
const identifier : m.Parser([]const u8) = m.asStr(m.combine(
        .{char_alpha, m.many(char_alphanum, .{.collect=false})}
));
fn mktok_A_name(res : []const u8) Token {return .{.A_name=res};}
const set_addr_name : m.Parser(Token) =
    m.map(Token, mktok_A_name,
        m.combine(.{m.ascii.char('@'), identifier} )
);

fn mktok_A_addr(addr : u16) Token {return .{.A_addr = addr};}
const set_addr_addr : m.Parser(Token) =
    m.map(Token, mktok_A_addr,
        m.combine(.{m.ascii.char('@'), integer})
);

const def_label = m.combine(.{
    m.ascii.char('('),
    identifier,
    m.ascii.char(')'),
    }
);

fn isSingleChar(x : u8) bool {
    return switch(x) {
        'A' => true,
        'M' => true,
        'D' => true,
        ';' => true,
        '=' => true,
        '+' => true,
        '-' => true,
        else => false,
    };
}

fn mktok_singlechar(res : u8) Token {
    return switch(res) {
        'A' => .{.register  = Register.A},
        'M' => .{.register  = Register.M},
        'D' => .{.register  = Register.D},
        ';' => .{.semicolon = .{}},
        '=' => .{.eq        = .{}},
        '+' => .{.plus      = .{}},
        '-' => .{.minus     = .{}},
        else => {unreachable;}
    };
}
const singelechar_token : m.Parser(Token) = m.map(Token, mktok_singlechar,
    m.ascii.wrap(isSingleChar));

test "singelechar_token" {
    const test_allocator = testing.allocator;
    var res : Token = (try singelechar_token(test_allocator, "M")).value;
    try testing.expectEqual(res, Token{.register=Register.M});
    res = (try singelechar_token(test_allocator, ";")).value;
    try testing.expectEqual(res, Token{.semicolon=.{}});
    try expectError(singelechar_token(test_allocator, "?"), m.Error.ParserFailed);
    try expectError(singelechar_token(test_allocator, "m"), m.Error.ParserFailed);
}

test "set_addr" {
    const test_allocator = testing.allocator;
    const s = @as([]const u8, "ho");
    var res : Token = mktok_A_name(s);
    try testing.expect(std.mem.eql(u8, res.A_name, "ho"));

    res = (try set_addr_name(test_allocator, "@foo")).value;
    try testing.expect(std.mem.eql(u8, res.A_name, "foo"));

    res = (try set_addr_name(test_allocator, "@foo ")).value;
    try testing.expect(std.mem.eql(u8, res.A_name, "foo"));

    res = (try set_addr_name(test_allocator, "@lol123//some comment")).value;
    try testing.expect(std.mem.eql(u8, res.A_name, "lol123"));

    var res2 : m.Result(Token) = try set_addr_addr(test_allocator, "@123");
    try testing.expectEqual(res2.value.A_addr, 123);

    res2 = try set_addr_addr(test_allocator, "@123//");
    try testing.expectEqual(res2.value.A_addr, 123);
//    try testing.expect(std.mem.eql(u8, res.value, "foo"));
//
//    res = try set_addr_name(test_allocator, "@R12");
//    try testing.expect(std.mem.eql(u8, res.value, "R12"));
//
//    try expectError(set_addr_name(test_allocator, "asdf"), m.Error.ParserFailed);
//    try expectError(set_addr_name(test_allocator, "@13123"), m.Error.ParserFailed);
//    var resi = try set_addr_addr(test_allocator, "@13123");
//    try testing.expectEqual(resi.value, 13123);
//
//    try expectError(set_addr_name(test_allocator, "@?a"), m.Error.ParserFailed);
//    try expectError(set_addr_addr(test_allocator, "@?a"), m.Error.ParserFailed);
//    try expectError(set_addr_name(test_allocator, "@"), m.Error.ParserFailed);
//    try expectError(set_addr_addr(test_allocator, "@"), m.Error.ParserFailed);
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
    defer test_allocator.free(val.value.comment);
    try testing.expect(std.mem.eql(u8, val.value.comment, "lala"));
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

const Token = union(enum) {
    comment   : []const u8,
    A_addr    : u16,
    A_name    : []const u8,
    def_label : []const u8,
    register  : Register,
    semicolon : void,
    jump      : Jump,
    eq        : void,
    plus      : void,
    minus     : void,
};

//const CInstr = struct

const CST = union(enum) {
    comment   : []u8,
    A_addr    : u16,
    A_name    : []u8,
    C         : struct {destA : bool, destD :bool, destM :bool, comp : Comp, jump : Jump},
    def_label : []u8,
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
