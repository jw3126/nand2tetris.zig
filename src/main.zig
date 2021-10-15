const std = @import("std");
const m = @import("mecha");
const testing = std.testing;
const Allocator = std.mem.Allocator;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

//const spaces_or_tabs = m.discard(
//    m.many(
//        m.ascii.char(' '), .{.collect=false}
//    )
//);

const spaces_or_tabs = m.discard(
    m.many(m.ascii.space, .{.collect=false})
);

fn mkComment(content : [] const u8) Token {
    const ret = Token{.comment=content};
    return ret;
}
const start_comment = m.string("//");
const stop_comment = m.oneOf(.{m.ascii.char('\n'), m.eos});
const body_comment = m.many(m.ascii.not(stop_comment), .{.collect=true});
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
//const alphanum = m.many(char_alphanum, .{.min=1,.collect=false});
const whitespace_comment = m.combine(.{spaces_or_tabs, comment});

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

const identifier : m.Parser([]const u8) = m.asStr(m.combine(
        .{char_alpha, m.many(char_alphanum, .{.collect=false})}
));
test "identifier" {
    const test_allocator = testing.allocator;
    var res = (try identifier(test_allocator, "hello"));
    try testing.expect(std.mem.eql(u8, res.value, "hello"));

    const res1 = (try identifier(test_allocator, "R0"));

    try testing.expect(std.mem.eql(u8, res1.value, "R0"));

    const res2 = (try identifier(test_allocator, "R0\n"));
    try testing.expect(std.mem.eql(u8, res2.value, "R0"));
}


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

fn mktok_def_label(name : []const u8) Token {return .{.def_label=name};}
const def_label : m.Parser(Token) = m.combine(.{
    m.ascii.char('('),
    m.map(Token, mktok_def_label, identifier),
    m.ascii.char(')'),
    }
);

const token : m.Parser(Token) = m.combine(.{spaces_or_tabs,
    m.oneOf(.{
        comment,
        set_addr_addr,
        set_addr_name,
        def_label,
        jump,
        char_token,
    }),
});

test "token" {
    const test_allocator = testing.allocator;
    const res1 = try token(test_allocator, "0;JMP");
    try testing.expectEqual(res1.value, Token{.zero=.{}});
    const res2 = try token(test_allocator, "@R0");
    try testing.expect(std.mem.eql(u8, res2.value.A_name, "R0"));
}

const tokens = m.many(token, .{.collect=true});

test "tokens" {
    const test_allocator = testing.allocator;
    const res1 = try tokens(test_allocator, "0;JMP");
    defer test_allocator.free(res1.value);
}

fn char_token(_: *std.mem.Allocator, str :[]const u8) m.Error!m.Result(Token) {
    if (str.len == 0) {
        return m.Error.ParserFailed;
    } else {
        const c = str[0];
        const tok = switch(c) {
            'A' => Token{.register  = Register.A},
            'M' => Token{.register  = Register.M},
            'D' => Token{.register  = Register.D},
            ';' => Token{.semicolon = .{}},
            '=' => Token{.eq        = .{}},
            '+' => Token{.plus      = .{}},
            '-' => Token{.minus     = .{}},
            '0' => Token{.zero      = .{}},
            '1' => Token{.one      = .{}},
            else => {return m.Error.ParserFailed;}
        };
        return m.Result(Token){.value=tok, .rest=str[1..]};
    }
}

fn jump(_: *std.mem.Allocator, str : []const u8) m.Error!m.Result(Token) {
    if (std.mem.startsWith(u8, str, "J00")) {
        const tok : Token  = Token{ .jump=Jump.J00};
        return m.Result(Token){.value=tok, .rest=str[3..]};
    } else if (std.mem.startsWith(u8, str, "JGT")) {
        const tok : Token  = Token{ .jump=Jump.JGT};
        return m.Result(Token){.value=tok, .rest=str[3..]};
    } else if (std.mem.startsWith(u8, str, "JEQ")) {
        const tok : Token  = Token{ .jump=Jump.JEQ};
        return m.Result(Token){.value=tok, .rest=str[3..]};
    } else if (std.mem.startsWith(u8, str, "JGE")) {
        const tok : Token  = Token{ .jump=Jump.JGE};
        return m.Result(Token){.value=tok, .rest=str[3..]};
    } else if (std.mem.startsWith(u8, str, "JLT")) {
        const tok : Token  = Token{ .jump=Jump.JLT};
        return m.Result(Token){.value=tok, .rest=str[3..]};
    } else if (std.mem.startsWith(u8, str, "JNE")) {
        const tok : Token  = Token{ .jump=Jump.JNE};
        return m.Result(Token){.value=tok, .rest=str[3..]};
    } else if (std.mem.startsWith(u8, str, "JLE")) {
        const tok : Token  = Token{ .jump=Jump.JLE};
        return m.Result(Token){.value=tok, .rest=str[3..]};
    } else if (std.mem.startsWith(u8, str, "JMP")) {
        const tok : Token  = Token{ .jump=Jump.JMP};
        return m.Result(Token){.value=tok, .rest=str[3..]};
    } else {
        return m.Error.ParserFailed;
    }
}

test "jump" {
    const test_allocator = testing.allocator;
    var res : Token = (try jump(test_allocator, "JMP")).value;
    try testing.expectEqual(res, Token{ .jump=Jump.JMP});
    res = (try jump(test_allocator, "J00")).value;
    try testing.expectEqual(res, Token{ .jump=Jump.J00});
    res = (try jump(test_allocator, "JGT")).value;
    try testing.expectEqual(res, Token{ .jump=Jump.JGT});
    res = (try jump(test_allocator, "JEQ")).value;
    try testing.expectEqual(res, Token{ .jump=Jump.JEQ});
    res = (try jump(test_allocator, "JGE")).value;
    try testing.expectEqual(res, Token{ .jump=Jump.JGE});
    res = (try jump(test_allocator, "JLT")).value;
    try testing.expectEqual(res, Token{ .jump=Jump.JLT});
    try expectError(jump(test_allocator, "?"), m.Error.ParserFailed);
}

test "char_token" {
    const test_allocator = testing.allocator;
    var res : Token = (try char_token(test_allocator, "M")).value;
    try testing.expectEqual(res, Token{.register=Register.M});
    res = (try char_token(test_allocator, ";")).value;
    try testing.expectEqual(res, Token{.semicolon=.{}});
    try expectError(char_token(test_allocator, "?"), m.Error.ParserFailed);
    try expectError(char_token(test_allocator, "m"), m.Error.ParserFailed);
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

    var res3 = try set_addr_name(test_allocator, "@R0");
    try testing.expect(std.mem.eql(u8, res3.value.A_name, "R0"));
    res3 = try set_addr_name(test_allocator, "@R0\n");
    try testing.expect(std.mem.eql(u8, res3.value.A_name, "R0"));
    var tok = (try token(test_allocator, "@R0")).value;
    try testing.expect(std.mem.eql(u8, tok.A_name, "R0"));

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
    var res : m.Result(Token) = try def_label(test_allocator, "(asdf)");
    try testing.expect(std.mem.eql(u8, res.value.def_label, "asdf"));
}

pub fn tokenizeFileAbsolute(alloc: *Allocator, path : [] const u8) anyerror!std.ArrayList(Token) {
    const file = try std.fs.openFileAbsolute(path, .{.read=true});
    defer file.close();
    const reader = std.io.bufferedReader(file.reader()).reader();
    var ret = std.ArrayList(Token).init(alloc);
    var buf : [1024]u8 = undefined;
    while (try reader.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        //std.debug.print("//// Start Parsing: ~~{s}~~\n", .{line});
        var toks = (try tokens(alloc, line)).value;
        defer alloc.free(toks);
        //std.debug.print("//// Stop Parsing: ~~{s}~~\n", .{line});
        try ret.appendSlice(toks);
    }
    return ret;
}

pub fn main() anyerror!void {
    defer {
        const leaked = gpa.deinit();
        if (leaked) std.testing.expect(false) catch @panic("Memory problem");
    }

    const allocator : *Allocator = &gpa.allocator;
    const stdout = std.io.getStdOut().writer();
    const path = "/home/jan/nand2tetris/examples/add.asm";
    const toks = try tokenizeFileAbsolute(allocator, path);
    defer freeTokens(allocator, toks);
    for (toks.items) |tok| {
        try printToken(stdout, tok);
    }
    try stdout.print("\n", .{});
}


fn expectError(res : anytype, err_expected : anyerror) anyerror!void {
    if (res) |value| {_=value;unreachable;} else |err| {
        try std.testing.expect(err == err_expected);
        return;
    }
}

test "comment" {
    const test_allocator = testing.allocator;
    const res = try comment(test_allocator, "//lala\n\n");
    defer test_allocator.free(res.value.comment);
    try testing.expect(std.mem.eql(u8, res.value.comment, "lala"));

    const res2 = try comment(test_allocator, "//lala2");
    defer test_allocator.free(res2.value.comment);
    try testing.expect(std.mem.eql(u8, res2.value.comment, "lala2"));
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

fn printJump(writer : anytype, jmp : Jump) anyerror!void {
    try switch(jmp) {
        Jump.J00 => writer.print("J00", .{}),
        Jump.JGT => writer.print("JGT", .{}),
        Jump.JEQ => writer.print("JEQ", .{}),
        Jump.JGE => writer.print("JGE", .{}),
        Jump.JLT => writer.print("JLT", .{}),
        Jump.JNE => writer.print("JNE", .{}),
        Jump.JLE => writer.print("JLE", .{}),
        Jump.JMP => writer.print("JMP", .{}),
    };
}

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
    zero      : void,
    one       : void,
};

fn freeToken(alloc : *std.mem.Allocator, tok : Token) void {
    switch(tok) {
        Token.comment   =>  |s| alloc.free(s),
        //Token.A_name    =>  |s| alloc.free(s),
        //Token.def_label =>  |s| alloc.free(s),
        else => {},
    }
}

fn freeTokens(alloc: *Allocator, toks : std.ArrayList(Token)) void {
    for (toks.items) |tok| {
        freeToken(alloc, tok);
    }
    toks.deinit();
}

fn printRegister(writer : anytype, register : Register) anyerror!void {
    const c : u8 = switch(register) {
        Register.A => 'A',
        Register.D => 'D',
        Register.M => 'M',
    };
    return writer.print("{c}", .{c});
}

fn printToken(writer : anytype, tok : Token) anyerror!void {
    try switch(tok) {
        Token.comment => |com| writer.print("//{s}", .{com}),
        Token.A_addr => |addr| writer.print("@{d}", .{addr}),
        Token.A_name => |name| writer.print("@{s}", .{name}),
        Token.def_label => |name| writer.print("({s}):", .{name}),
        Token.register => |register| printRegister(writer, register),
        Token.semicolon => writer.print(";", .{}),
        Token.jump     => |jmp| printJump(writer, jmp),
        Token.eq    => writer.print("=", .{}),
        Token.plus    => writer.print("+", .{}),
        Token.minus    => writer.print("-", .{}),
        Token.zero    => writer.print("0", .{}),
        Token.one    => writer.print("1", .{}),
    };
}

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
