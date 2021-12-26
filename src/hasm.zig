const std = @import("std");
const m = @import("mecha");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

pub const spaces_or_tabs = m.discard(m.many(m.ascii.space, .{ .collect = false }));

fn mkComment(content: []const u8) Token {
    const ret = Token{ .comment = content };
    return ret;
}
const start_comment = m.string("//");
const stop_comment = m.oneOf(.{ m.ascii.char('\n'), m.eos });
const body_comment = m.many(m.ascii.not(stop_comment), .{ .collect = true });
pub const comment_str = m.combine(.{ start_comment, body_comment, stop_comment });
const comment: m.Parser(Token) = m.map(
    Token,
    mkComment,
    comment_str,
);
const integer = m.int(u16, .{ .base = 10, .parse_sign = false });

fn isAlphaNum(x: u8) bool {
    return (('0' <= x) and (x <= '9')) or isAlpha(x);
}

fn isCharIdentifier(x: u8) bool {
    if (('0' <= x) and (x <= '9')) return true;
    if (isAlpha(x)) return true;
    if (x == '.') return true;
    if (x == '$') return true;
    return false;
}
fn isAlpha(x: u8) bool {
    if (('a' <= x) and (x <= 'z')) {
        return true;
    }
    if (('A' <= x) and (x <= 'Z')) {
        return true;
    }
    if (x == '_') {
        return true;
    }
    return false;
}
const char_identifier = m.ascii.wrap(isCharIdentifier);
const char_alpha = m.ascii.wrap(isAlpha);
const whitespace_comment = m.combine(.{ spaces_or_tabs, comment });

test "char_identifier" {
    const test_allocator = testing.allocator;
    var res = try char_identifier(test_allocator, "0");
    try testing.expectEqual(res.value, '0');
    res = try char_identifier(test_allocator, "9");
    try testing.expectEqual(res.value, '9');
    res = try char_identifier(test_allocator, "4");
    try testing.expectEqual(res.value, '4');
    res = try char_identifier(test_allocator, "a");
    try testing.expectEqual(res.value, 'a');
    res = try char_identifier(test_allocator, "D");
    try testing.expectEqual(res.value, 'D');
    try expectError(char_identifier(test_allocator, "?"), m.Error.ParserFailed);
}

const identifier_unsafe: m.Parser([]const u8) = m.asStr(m.combine(.{ char_alpha, m.many(char_identifier, .{ .collect = false }) }));

pub fn identifier(alloc: *std.mem.Allocator, str: []const u8) m.Error!m.Result([]const u8) {
    var res_inner = try identifier_unsafe(alloc, str);
    const mem = try alloc.alloc(u8, res_inner.value.len);
    var i: u64 = 0;
    while (i < res_inner.value.len) : (i += 1) {
        mem[i] = res_inner.value[i];
    }
    res_inner.value = mem;
    return res_inner;
}

test "identifier" {
    const test_allocator = testing.allocator;
    {
        const res0 = (try identifier(test_allocator, "hello"));
        defer test_allocator.free(res0.value);
        try testing.expect(std.mem.eql(u8, res0.value, "hello"));
    }

    {
        const res1 = (try identifier(test_allocator, "R0"));
        defer test_allocator.free(res1.value);
        try testing.expect(std.mem.eql(u8, res1.value, "R0"));
    }

    {
        const res2 = (try identifier(test_allocator, "R0\n"));
        defer test_allocator.free(res2.value);
        try testing.expect(std.mem.eql(u8, res2.value, "R0"));
    }

    {
        const res3 = (try identifier(test_allocator, "screen.0\n"));
        defer test_allocator.free(res3.value);
        try testing.expect(std.mem.eql(u8, res3.value, "screen.0"));
    }

    {
        const res4 = (try identifier(test_allocator, "screen.drawrectangle$while_exp0\n"));
        defer test_allocator.free(res4.value);
        try testing.expect(std.mem.eql(u8, res4.value, "screen.drawrectangle$while_exp0"));
    }
}

fn mktok_A_name(res: []const u8) Token {
    return .{ .A_name = res };
}
const set_addr_name: m.Parser(Token) =
    m.map(Token, mktok_A_name, m.combine(.{ m.ascii.char('@'), identifier }));

fn mktok_A_addr(addr: u16) Token {
    return .{ .A_addr = addr };
}
const set_addr_addr: m.Parser(Token) =
    m.map(Token, mktok_A_addr, m.combine(.{ m.ascii.char('@'), integer }));

fn mktok_def_label(name: []const u8) Token {
    return .{ .def_label = name };
}
const def_label: m.Parser(Token) = m.combine(.{
    m.ascii.char('('),
    m.map(Token, mktok_def_label, identifier),
    m.ascii.char(')'),
});

const token: m.Parser(Token) = m.combine(.{
    spaces_or_tabs,
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
    {
        const res = try token(test_allocator, "0;JMP");
        defer res.value.free(test_allocator);
        try testing.expectEqual(res.value, Token{ .zero = .{} });
    }
    {
        const res = try token(test_allocator, "@R0");
        defer res.value.free(test_allocator);
        try testing.expect(std.mem.eql(u8, res.value.A_name, "R0"));
    }
}

const tokens = m.many(token, .{ .collect = true });

test "tokens" {
    const test_allocator = testing.allocator;
    const res1 = try tokens(test_allocator, "0;JMP");
    defer test_allocator.free(res1.value);
}

fn char_token(_: *std.mem.Allocator, str: []const u8) m.Error!m.Result(Token) {
    if (str.len == 0) {
        return m.Error.ParserFailed;
    } else {
        const c = str[0];
        const tok = switch (c) {
            'A' => Token{ .register = Register.A },
            'M' => Token{ .register = Register.M },
            'D' => Token{ .register = Register.D },
            ';' => Token{ .semicolon = .{} },
            '=' => Token{ .eq = .{} },
            '+' => Token{ .plus = .{} },
            '-' => Token{ .minus = .{} },
            '&' => Token{ .and_ = .{} },
            '|' => Token{ .or_ = .{} },
            '!' => Token{ .not = .{} },
            '0' => Token{ .zero = .{} },
            '1' => Token{ .one = .{} },
            else => {
                return m.Error.ParserFailed;
            },
        };
        return m.Result(Token){ .value = tok, .rest = str[1..] };
    }
}

fn jump(_: *std.mem.Allocator, str: []const u8) m.Error!m.Result(Token) {
    if (std.mem.startsWith(u8, str, "J00")) {
        const tok: Token = Token{ .jump = Jump.J00 };
        return m.Result(Token){ .value = tok, .rest = str[3..] };
    } else if (std.mem.startsWith(u8, str, "JGT")) {
        const tok: Token = Token{ .jump = Jump.JGT };
        return m.Result(Token){ .value = tok, .rest = str[3..] };
    } else if (std.mem.startsWith(u8, str, "JEQ")) {
        const tok: Token = Token{ .jump = Jump.JEQ };
        return m.Result(Token){ .value = tok, .rest = str[3..] };
    } else if (std.mem.startsWith(u8, str, "JGE")) {
        const tok: Token = Token{ .jump = Jump.JGE };
        return m.Result(Token){ .value = tok, .rest = str[3..] };
    } else if (std.mem.startsWith(u8, str, "JLT")) {
        const tok: Token = Token{ .jump = Jump.JLT };
        return m.Result(Token){ .value = tok, .rest = str[3..] };
    } else if (std.mem.startsWith(u8, str, "JNE")) {
        const tok: Token = Token{ .jump = Jump.JNE };
        return m.Result(Token){ .value = tok, .rest = str[3..] };
    } else if (std.mem.startsWith(u8, str, "JLE")) {
        const tok: Token = Token{ .jump = Jump.JLE };
        return m.Result(Token){ .value = tok, .rest = str[3..] };
    } else if (std.mem.startsWith(u8, str, "JMP")) {
        const tok: Token = Token{ .jump = Jump.JMP };
        return m.Result(Token){ .value = tok, .rest = str[3..] };
    } else {
        return m.Error.ParserFailed;
    }
}

test "jump" {
    const test_allocator = testing.allocator;
    var res: Token = (try jump(test_allocator, "JMP")).value;
    try testing.expectEqual(res, Token{ .jump = Jump.JMP });
    res = (try jump(test_allocator, "J00")).value;
    try testing.expectEqual(res, Token{ .jump = Jump.J00 });
    res = (try jump(test_allocator, "JGT")).value;
    try testing.expectEqual(res, Token{ .jump = Jump.JGT });
    res = (try jump(test_allocator, "JEQ")).value;
    try testing.expectEqual(res, Token{ .jump = Jump.JEQ });
    res = (try jump(test_allocator, "JGE")).value;
    try testing.expectEqual(res, Token{ .jump = Jump.JGE });
    res = (try jump(test_allocator, "JLT")).value;
    try testing.expectEqual(res, Token{ .jump = Jump.JLT });
    try expectError(jump(test_allocator, "?"), m.Error.ParserFailed);
}

test "char_token" {
    const test_allocator = testing.allocator;
    var res: Token = (try char_token(test_allocator, "M")).value;
    try testing.expectEqual(res, Token{ .register = Register.M });
    res = (try char_token(test_allocator, ";")).value;
    try testing.expectEqual(res, Token{ .semicolon = .{} });
    try expectError(char_token(test_allocator, "?"), m.Error.ParserFailed);
    try expectError(char_token(test_allocator, "m"), m.Error.ParserFailed);
}

test "set_addr" {
    const test_allocator = testing.allocator;
    {
        const s = @as([]const u8, "ho");
        const res: Token = mktok_A_name(s);
        try testing.expect(std.mem.eql(u8, res.A_name, "ho"));
    }
    {
        const res = (try set_addr_name(test_allocator, "@foo")).value;
        defer res.free(test_allocator);
        try testing.expect(std.mem.eql(u8, res.A_name, "foo"));
    }
    {
        const res = (try set_addr_name(test_allocator, "@foo ")).value;
        defer res.free(test_allocator);
        try testing.expect(std.mem.eql(u8, res.A_name, "foo"));
    }
    {
        const res = (try set_addr_name(test_allocator, "@lol123//some comment")).value;
        defer res.free(test_allocator);
        try testing.expect(std.mem.eql(u8, res.A_name, "lol123"));
    }

    {
        const res: Token = (try set_addr_addr(test_allocator, "@123")).value;
        defer res.free(test_allocator);
        try testing.expectEqual(res.A_addr, 123);
    }
    {
        const res = (try set_addr_addr(test_allocator, "@123//")).value;
        defer res.free(test_allocator);
        try testing.expectEqual(res.A_addr, 123);
    }

    {
        const res = (try set_addr_name(test_allocator, "@R0")).value;
        defer res.free(test_allocator);
        try testing.expect(std.mem.eql(u8, res.A_name, "R0"));
    }
    {
        const res = (try set_addr_name(test_allocator, "@R0\n")).value;
        defer res.free(test_allocator);
        try testing.expect(std.mem.eql(u8, res.A_name, "R0"));
    }
    {
        const res = (try token(test_allocator, "@R0")).value;
        defer res.free(test_allocator);
        try testing.expect(std.mem.eql(u8, res.A_name, "R0"));
    }

    try expectError(set_addr_name(test_allocator, "asdf"), m.Error.ParserFailed);
    try expectError(set_addr_name(test_allocator, "@13123"), m.Error.ParserFailed);
    try expectError(set_addr_name(test_allocator, "@?a"), m.Error.ParserFailed);
    try expectError(set_addr_addr(test_allocator, "@?a"), m.Error.ParserFailed);
    try expectError(set_addr_name(test_allocator, "@"), m.Error.ParserFailed);
    try expectError(set_addr_addr(test_allocator, "@"), m.Error.ParserFailed);
}

test "def_label" {
    const test_allocator = testing.allocator;
    var res: m.Result(Token) = try def_label(test_allocator, "(asdf)");
    defer res.value.free(test_allocator);
    try testing.expect(std.mem.eql(u8, res.value.def_label, "asdf"));
}

pub fn tokenizeFileAbsolute(alloc: Allocator, path: []const u8) anyerror!ArrayList(Token) {
    const file = try std.fs.openFileAbsolute(path, .{ .read = true });
    defer file.close();
    const reader = std.io.bufferedReader(file.reader()).reader();
    var ret = ArrayList(Token).init(alloc);
    var buf: [1024]u8 = undefined;
    while (try reader.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        //std.debug.print("//// Start Parsing: ~~{s}~~\n", .{line});
        var toks = (try tokens(alloc, line)).value;
        defer alloc.free(toks);
        //std.debug.print("//// Stop Parsing: ~~{s}~~\n", .{line});
        try ret.appendSlice(toks);
    }
    return ret;
}

fn expectError(res: anytype, err_expected: anyerror) anyerror!void {
    if (res) |value| {
        _ = value;
        unreachable;
    } else |err| {
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

const Register = enum {
    A,
    D,
    M,
    pub fn format(reg: *const Register, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        const c: u8 = switch (reg.*) {
            Register.A => 'A',
            Register.D => 'D',
            Register.M => 'M',
        };
        return writer.print("{c}", .{c});
    }
};

const Jump = enum {
    J00,
    JGT,
    JEQ,
    JGE,
    JLT,
    JNE,
    JLE,
    JMP,
    pub fn format(jmp: *const Jump, fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        try switch (jmp.*) {
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

    fn machineBits(jmp: Jump) u16 {
        const ret: u16 = switch (jmp) {
            Jump.J00 => 0,
            Jump.JGT => 1,
            Jump.JEQ => 2,
            Jump.JGE => 3,
            Jump.JLT => 4,
            Jump.JNE => 5,
            Jump.JLE => 6,
            Jump.JMP => 7,
        };
        return ret;
    }
};

const Comp = union(enum) {
    zero,
    one,
    neg_one,
    not: Register,
    neg: Register,
    copy: Register,
    inc: Register,
    dec: Register,

    DplusA,
    DminusA,
    AminusD,
    DandA,
    DorA,
    DplusM,
    DminusM,
    MminusD,
    DandM,
    DorM,
    pub fn format(comp: *const Comp, fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        switch (comp.*) {
            Comp.zero => try writer.print("0", .{}),
            Comp.one => try writer.print("1", .{}),
            Comp.neg_one => try writer.print("-1", .{}),
            Comp.not => |reg| try writer.print("!{}", .{reg}),
            Comp.neg => |reg| try writer.print("-{}", .{reg}),
            Comp.copy => |reg| try writer.print("{}", .{reg}),
            Comp.inc => |reg| try writer.print("{}+1", .{reg}),
            Comp.dec => |reg| try writer.print("{}-1", .{reg}),
            Comp.DplusA => try writer.print("D+A", .{}),
            Comp.DminusA => try writer.print("D-A", .{}),
            Comp.AminusD => try writer.print("A-D", .{}),
            Comp.DandA => try writer.print("D&A", .{}),
            Comp.DorA => try writer.print("D|A", .{}),
            Comp.DplusM => try writer.print("D+M", .{}),
            Comp.DminusM => try writer.print("D-M", .{}),
            Comp.MminusD => try writer.print("M-D", .{}),
            Comp.DandM => try writer.print("D&M", .{}),
            Comp.DorM => try writer.print("D|M", .{}),
        }
    }

    fn equals(comp1: Comp, comp2: Comp) bool {
        return comp1.machineBits() == comp2.machineBits();
    }

    fn machineBits(comp: Comp) u16 {
        const c6: u16 = 1 << 6;
        const c5: u16 = 1 << 7;
        const c4: u16 = 1 << 8;
        const c3: u16 = 1 << 9;
        const c2: u16 = 1 << 10;
        const c1: u16 = 1 << 11;
        const a: u16 = 1 << 12;
        const z: u16 = 0;
        const ret: u16 = switch (comp) {
            Comp.zero => z | c1 | z | c3 | z | c5 | z,
            Comp.one => z | c1 | c2 | c3 | c4 | c5 | c6,
            Comp.neg_one => z | c1 | c2 | c3 | z | c5 | z,
            Comp.DplusA => z | z | z | z | z | c5 | z,
            Comp.DminusA => z | z | c2 | z | z | c5 | c6,
            Comp.AminusD => z | z | z | z | c4 | c5 | c6,
            Comp.DandA => z | z | z | z | z | z | z,
            Comp.DorA => z | z | c2 | z | c4 | z | c6,
            Comp.DplusM => a | z | z | z | z | c5 | z,
            Comp.DminusM => a | z | c2 | z | z | c5 | c6,
            Comp.MminusD => a | z | z | z | c4 | c5 | c6,
            Comp.DandM => a | z | z | z | z | z | z,
            Comp.DorM => a | z | c2 | z | c4 | z | c6,
            Comp.not => |reg| switch (reg) {
                Register.A => z | c1 | c2 | z | z | z | c6,
                Register.D => z | z | z | c3 | c4 | z | c6,
                Register.M => a | c1 | c2 | z | z | z | c6,
            },
            Comp.neg => |reg| switch (reg) {
                Register.A => z | c1 | c2 | z | z | c5 | c6,
                Register.D => z | z | z | c3 | c4 | c5 | c6,
                Register.M => a | c1 | c2 | z | z | c5 | c6,
            },
            Comp.copy => |reg| switch (reg) {
                Register.A => z | c1 | c2 | z | z | z | z,
                Register.D => z | z | z | c3 | c4 | z | z,
                Register.M => a | c1 | c2 | z | z | z | z,
            },
            Comp.inc => |reg| switch (reg) {
                Register.A => z | c1 | c2 | z | c4 | c5 | c6,
                Register.D => z | z | c2 | c3 | c4 | c5 | c6,
                Register.M => a | c1 | c2 | z | c4 | c5 | c6,
            },
            Comp.dec => |reg| switch (reg) {
                Register.A => z | c1 | c2 | z | z | c5 | z,
                Register.D => z | z | z | c3 | c4 | c5 | z,
                Register.M => a | c1 | c2 | z | z | c5 | z,
            },
        };
        return ret;
    }
};

fn binaryOp(reg1: Register, op: Token, reg2: Register) anyerror!Comp {
    const plus = Token.plus;
    const minus = Token.minus;
    const and_ = Token.and_;
    const or_ = Token.or_;
    const A = Register.A;
    const D = Register.D;
    const M = Register.M;
    if (reg1 == D and op == plus and reg2 == A) {
        return Comp.DplusA;
    } else if (reg1 == D and op == minus and reg2 == A) {
        return Comp.DminusA;
    } else if (reg1 == A and op == minus and reg2 == D) {
        return Comp.AminusD;
    } else if (reg1 == D and op == and_ and reg2 == A) {
        return Comp.DandA;
    } else if (reg1 == D and op == or_ and reg2 == A) {
        return Comp.DorA;
    } else if (reg1 == D and op == plus and reg2 == M) {
        return Comp.DplusM;
    } else if (reg1 == D and op == minus and reg2 == M) {
        return Comp.DminusM;
    } else if (reg1 == M and op == minus and reg2 == D) {
        return Comp.MminusD;
    } else if (reg1 == D and op == and_ and reg2 == M) {
        return Comp.DandM;
    } else if (reg1 == D and op == or_ and reg2 == M) {
        return Comp.DorM;
    } else {
        std.debug.print("reg1 = {any} op = {any} reg2 = {any}", .{ reg1, op, reg2 });
        return unexpectedToken;
    }
}

pub const Token = union(enum) {
    comment: []const u8,
    A_addr: u16,
    A_name: []const u8,
    def_label: []const u8,
    register: Register,
    semicolon: void,
    jump: Jump,
    eq: void,
    plus: void,
    minus: void,
    and_: void,
    or_: void,
    zero: void,
    one: void,
    not: void,
    pub fn format(tok: *const Token, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        try switch (tok.*) {
            Token.comment => |com| writer.print("//{s}", .{com}),
            Token.A_addr => |addr| writer.print("@{d}", .{addr}),
            Token.A_name => |name| writer.print("@{s}", .{name}),
            Token.def_label => |name| writer.print("({s})", .{name}),
            Token.semicolon => writer.print(";", .{}),
            Token.eq => writer.print("=", .{}),
            Token.plus => writer.print("+", .{}),
            Token.minus => writer.print("-", .{}),
            Token.and_ => writer.print("&", .{}),
            Token.or_ => writer.print("|", .{}),
            Token.not => writer.print("!", .{}),
            Token.zero => writer.print("0", .{}),
            Token.one => writer.print("1", .{}),
            Token.register => |reg| writer.print("{}", .{reg}),
            Token.jump => |jmp| writer.print("{}", .{jmp}),
        };
    }
    pub fn free(tok: Token, alloc: *std.mem.Allocator) void {
        switch (tok) {
            Token.comment => |s| alloc.free(s),
            Token.A_name => |s| alloc.free(s),
            Token.def_label => |s| alloc.free(s),
            else => {},
        }
    }
    pub fn equals(t1: Token, t2: Token) bool {
        const ret = switch (t1) {
            Token.comment => |str1| switch (t2) {
                Token.comment => |str2| std.mem.eql(u8, str1, str2),
                else => false,
            },
            Token.A_addr => |x1| switch (t2) {
                Token.A_addr => |x2| (x1 == x2),
                else => false,
            },
            Token.A_name => |str1| switch (t2) {
                Token.A_name => |str2| std.mem.eql(u8, str1, str2),
                else => false,
            },
            Token.def_label => |str1| switch (t2) {
                Token.def_label => |str2| std.mem.eql(u8, str1, str2),
                else => false,
            },
            Token.register => |x1| switch (t2) {
                Token.register => |x2| (x1 == x2),
                else => false,
            },
            Token.semicolon => |x1| switch (t2) {
                Token.semicolon => |x2| (x1 == x2),
                else => false,
            },
            Token.jump => |x1| switch (t2) {
                Token.jump => |x2| (x1 == x2),
                else => false,
            },
            Token.eq => |x1| switch (t2) {
                Token.eq => |x2| (x1 == x2),
                else => false,
            },
            Token.plus => |x1| switch (t2) {
                Token.plus => |x2| (x1 == x2),
                else => false,
            },
            Token.minus => |x1| switch (t2) {
                Token.minus => |x2| (x1 == x2),
                else => false,
            },
            Token.zero => |x1| switch (t2) {
                Token.zero => |x2| (x1 == x2),
                else => false,
            },
            Token.one => |x1| switch (t2) {
                Token.one => |x2| (x1 == x2),
                else => false,
            },
            Token.not => |x1| switch (t2) {
                Token.not => |x2| (x1 == x2),
                else => false,
            },
            Token.and_ => |x1| switch (t2) {
                Token.and_ => |x2| (x1 == x2),
                else => false,
            },
            Token.or_ => |x1| switch (t2) {
                Token.or_ => |x2| (x1 == x2),
                else => false,
            },
        };
        return ret;
    }
};

pub fn freeTokens(alloc: Allocator, toks: ArrayList(Token)) void {
    for (toks.items) |tok| {
        tok.free(alloc);
    }
    toks.deinit();
}

const CInstr = struct {
    destA: bool,
    destD: bool,
    destM: bool,
    comp: Comp,
    jump: Jump,
    pub fn equals(c1: CInstr, c2: CInstr) bool {
        return (c1.destA == c2.destA) and
            (c1.destD == c2.destD) and
            (c1.destM == c2.destM) and
            (c1.comp.equals(c2.comp)) and
            (c1.jump == c2.jump);
    }

    fn machineBits(cinstr: CInstr) u16 {
        const base: u16 = (1 << 15) | (1 << 14) | (1 << 13);

        var destBits: u16 = 0;
        const d3: u16 = 1 << 3;
        const d2: u16 = 1 << 4;
        const d1: u16 = 1 << 5;
        if (cinstr.destM) {
            destBits = destBits | d3;
        }
        if (cinstr.destD) {
            destBits = destBits | d2;
        }
        if (cinstr.destA) {
            destBits = destBits | d1;
        }

        return base | cinstr.comp.machineBits() | destBits | cinstr.jump.machineBits();
    }
};

pub const Instr = union(enum) {
    comment: []const u8,
    A_addr: u16,
    A_name: []const u8,
    C: CInstr,
    def_label: []const u8,

    pub fn format(instr: *const Instr, fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        switch (instr.*) {
            Instr.comment => |com| {
                try writer.print("//{s}", .{com});
            },
            Instr.A_addr => |addr| {
                try writer.print("@{d}", .{addr});
            },
            Instr.A_name => |name| {
                try writer.print("@{s}", .{name});
            },
            Instr.def_label => |name| {
                try writer.print("({s})", .{name});
            },
            Instr.C => |spec| {
                if (spec.destA) {
                    try writer.print("A", .{});
                }
                if (spec.destD) {
                    try writer.print("D", .{});
                }
                if (spec.destM) {
                    try writer.print("M", .{});
                }
                if (spec.destA or spec.destD or spec.destM) {
                    try writer.print("=", .{});
                }
                try writer.print("{};{}", .{ spec.comp, spec.jump });
            },
        }
    }

    pub fn free(self: Instr, alloc: Allocator) void {
        switch (self) {
            Instr.comment => |s| {
                alloc.free(s);
            },
            Instr.A_name => |s| {
                alloc.free(s);
            },
            Instr.def_label => |s| {
                alloc.free(s);
            },
            Instr.C => {},
            Instr.A_addr => {},
        }
    }

    pub fn machineCode(instr: Instr) MachineCodeFromInstrError!u16 {
        return switch (instr) {
            Instr.comment => {
                return LoweringError.NoMachineCodeForComment;
            },
            Instr.A_addr => |addr| {
                _ = try checkAddr(addr);
                return addr;
            },
            Instr.A_name => {
                return LoweringError.NoMachineCodeForA_name;
            },
            Instr.C => |cinstr| cinstr.machineBits(),
            Instr.def_label => {
                return LoweringError.NoMachineCodeFordef_label;
            },
        };
    }

    pub fn equals(instr1: Instr, instr2: Instr) bool {
        const ret = switch (instr1) {
            Instr.comment => |com1| switch (instr2) {
                Instr.comment => |com2| std.mem.eql(u8, com1, com2),
                else => false,
            },
            Instr.A_addr => |addr1| switch (instr2) {
                Instr.A_addr => |addr2| addr1 == addr2,
                else => false,
            },
            Instr.A_name => |name1| switch (instr2) {
                Instr.A_name => |name2| std.mem.eql(u8, name1, name2),
                else => false,
            },
            Instr.C => |c1| switch (instr2) {
                Instr.C => |c2| c1.equals(c2),
                else => false,
            },
            Instr.def_label => |label1| switch (instr2) {
                Instr.def_label => |label2| std.mem.eql(u8, label1, label2),
                else => false,
            },
        };
        return ret;
    }
};

test "Instr" {
    const test_allocator = testing.allocator;
    {
        const instr1 = try instrFromString(test_allocator, "0;JMP");
        const instr2 = Instr{ .C = .{
            .destA = false,
            .destD = false,
            .destM = false,
            .jump = Jump.JMP,
            .comp = Comp{ .zero = .{} },
        } };
        try std.testing.expect(instr1.equals(instr2));
    }
    {
        const instr1 = try instrFromString(test_allocator, "D = A");
        const instr2 = Instr{ .C = .{
            .destA = false,
            .destD = true,
            .destM = false,
            .jump = Jump.J00,
            .comp = Comp{ .copy = Register.A },
        } };
        try std.testing.expect(instr1.equals(instr2));
    }
    {
        const instr1 = try instrFromString(test_allocator, "@1233");
        const instr2 = Instr{
            .A_addr = 1233,
        };
        try std.testing.expect(instr1.equals(instr2));
    }
    {
        const instr1 = try instrFromString(test_allocator, "@hoho");
        defer instr1.free(test_allocator);
        const instr2 = Instr{
            .A_name = "hoho",
        };
        try std.testing.expect(instr1.equals(instr2));
    }
}

const SymbolTable = std.HashMap([]const u8, u16, std.hash_map.StringContext, 80);
// caller must free the symbol table
fn buildSymbolTable(alloc: Allocator, instrs: []const Instr) anyerror!SymbolTable {
    // const stdout = std.io.getStdOut().writer();
    // collect labels first
    // this is important, otherwise we may reserve memory
    // locations for variables that turn out to be labels later
    var linum: u16 = 0;
    var label_table = SymbolTable.init(alloc);
    defer label_table.deinit();
    for (instrs) |instr| {
        // try printInstr(stdout, instr);
        // try stdout.print("\n", .{});
        switch (instr) {
            Instr.def_label => |label| {
                var res = try label_table.getOrPut(label);
                if (res.found_existing) {
                    std.debug.print("Error: Duplicate definition of label ({s})", .{label});
                    return Error.SymbolResolutionError;
                } else {
                    res.value_ptr.* = linum;
                }
            },
            Instr.A_name => {
                linum += 1;
            },
            Instr.comment => {},
            Instr.A_addr => {
                linum += 1;
            },
            Instr.C => {
                linum += 1;
            },
        }
    }

    var symbol_table = SymbolTable.init(alloc);
    errdefer symbol_table.deinit();
    try symbol_table.put("R0", 0);
    try symbol_table.put("R1", 1);
    try symbol_table.put("R2", 2);
    try symbol_table.put("R3", 3);
    try symbol_table.put("R4", 4);
    try symbol_table.put("R5", 5);
    try symbol_table.put("R6", 6);
    try symbol_table.put("R7", 7);
    try symbol_table.put("R8", 8);
    try symbol_table.put("R9", 9);
    try symbol_table.put("R10", 10);
    try symbol_table.put("R11", 11);
    try symbol_table.put("R12", 12);
    try symbol_table.put("R13", 13);
    try symbol_table.put("R14", 14);
    try symbol_table.put("R15", 15);
    try symbol_table.put("SCREEN", 16384);
    try symbol_table.put("KBD", 24576);
    try symbol_table.put("SP", 0);
    try symbol_table.put("LCL", 1);
    try symbol_table.put("ARG", 2);
    try symbol_table.put("THIS", 3);
    try symbol_table.put("THAT", 4);

    var memloc: u16 = 16;
    for (instrs) |instr| {
        switch (instr) {
            Instr.A_name => |name| {
                _ = label_table.get(name) orelse {
                    var res_symbol = try symbol_table.getOrPut(name);
                    if (!res_symbol.found_existing) {
                        res_symbol.value_ptr.* = memloc;
                        memloc += 1;
                    }
                };
            },
            else => {},
        }
    }

    var label_entries = label_table.iterator();
    while (label_entries.next()) |entry| {
        try symbol_table.putNoClobber(entry.key_ptr.*, entry.value_ptr.*);
    }
    return symbol_table;
}

pub fn resolveSymbols(alloc: Allocator, instrs: ArrayList(Instr)) anyerror!ArrayList(Instr) {
    var ret = ArrayList(Instr).init(alloc);
    var symbol_table = try buildSymbolTable(alloc, instrs.items);
    defer symbol_table.deinit();

    // now resolve
    //
    for (instrs.items) |instr| {
        switch (instr) {
            Instr.def_label => {},
            Instr.A_name => |name| {
                var addr: u16 = symbol_table.get(name) orelse {
                    std.debug.print("Undefined symbol {s} {}", .{ name, instr });
                    unreachable;
                };
                try ret.append(Instr{ .A_addr = addr });
            },
            Instr.comment => {},
            Instr.A_addr => {
                try ret.append(instr);
            },
            Instr.C => {
                try ret.append(instr);
            },
        }
    }
    return ret;
}

pub fn appendParsedString(alloc: Allocator, ret: *ArrayList(Instr), line: []const u8) !void {
    const res_toks = (tokens(alloc, line)) catch |err| {
        std.debug.print("Error tokenizing {s}\n", .{line});
        return err;
    };
    const toks = res_toks.value;
    defer alloc.free(toks);
    errdefer {
        for (toks) |tok| {
            tok.free(alloc);
        }
    }

    var stream = TokenStream{ .items = toks };
    stream.appendInstructions(ret) catch |err| {
        std.debug.print("Error parsing {s}\n", .{line});
        std.debug.print("Tokens:\n", .{});
        for (stream.items) |tok| {
            std.debug.print("{} ", .{tok});
        }
        std.debug.print("\n", .{});
        return err;
    };
}

pub fn instrFromString(alloc: Allocator, s: []const u8) !Instr {
    var instrs: ArrayList(Instr) = ArrayList(Instr).init(alloc);
    defer instrs.deinit();
    try appendParsedString(alloc, &instrs, s);
    const N = instrs.items.len;
    switch (N) {
        1 => {
            return instrs.items[0];
        },
        else => {
            std.debug.print("Expected exactly one instruction. Got {d} instructions: \n", .{N});
            for (instrs.items) |instr| {
                std.debug.print("{}", .{instr});
            }
            return error.HighlanderExpected;
        },
    }
}

pub fn parseFileAbsolute(alloc: Allocator, path: []const u8) anyerror!ArrayList(Instr) {
    const file = try std.fs.openFileAbsolute(path, .{ .read = true });
    defer file.close();
    const reader = std.io.bufferedReader(file.reader()).reader();
    var buf: [1024]u8 = undefined;
    var linenum: u64 = 0;
    var ret: ArrayList(Instr) = ArrayList(Instr).init(alloc);
    while (try reader.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        linenum += 1;
        appendParsedString(alloc, &ret, line) catch |err| {
            std.debug.print("Error in line {d}:", .{linenum});
            return err;
        };
    }
    return ret;
}

const Error = error{
    UnexpectedToken,
    UnexpectedEndOfTokens,
    ExpectedSemicolon,
    ExpectedJump,
    UndefinedSymbol,
    SymbolResolutionError,
};

const InvalidAddrError = error{InvalidAddr};
fn checkAddr(addr: u16) InvalidAddrError!u16 {
    const topbit: u16 = 1 << 15;
    if ((addr & topbit) == topbit) {
        std.debug.print("Invalid address: {b}. Top bit must be zero.", .{addr});
        return InvalidAddrError.InvalidAddr;
    } else {
        return addr;
    }
}

fn checkTokenExpectedGot(expected: Token, got: Token) Error!void {
    if (expected.equals(got)) {
        return void{};
    } else {
        std.debug.print("Expected token {any} got token {any}", .{ expected, got });
        return Error.UnexpectedToken;
    }
}

fn unexpectedToken(tok: Token, msg: []const u8) Error {
    std.debug.print("Got unexpected token {any}\n {s}", .{ tok, msg });
    return Error.UnexpectedToken;
}

pub const TokenStream = struct {
    items: []Token,
    position: usize = 0,
    fn advance(self: *TokenStream) Error!Token {
        const pos = self.position;
        if (pos >= self.items.len) {
            return Error.UnexpectedEndOfTokens;
        } else {
            self.position = pos + 1;
            const tok = self.items[pos];
            //std.debug.print("{any}", .{tok});
            return tok;
        }
    }

    fn hasTokensLeft(self: *TokenStream) bool {
        return (self.position < self.items.len);
    }

    const Op = enum { plus, minus, and_, or_ };
    fn parseComp(self: *TokenStream) anyerror!Comp {
        const tok = try self.advance();
        const comp: Comp = switch (tok) {
            Token.zero => Comp.zero,
            Token.one => Comp.one,
            Token.minus => {
                const tok2 = try self.advance();
                switch (tok2) {
                    Token.register => |reg| {
                        return Comp{ .neg = reg };
                    },
                    Token.one => {
                        return Comp{ .neg_one = .{} };
                    },
                    else => {
                        return unexpectedToken(tok, "expected register");
                    },
                }
            },
            Token.not => {
                const tok2 = try self.advance();
                switch (tok2) {
                    Token.register => |reg| {
                        return Comp{ .not = reg };
                    },
                    else => {
                        return unexpectedToken(tok, "expected register");
                    },
                }
            },
            Token.register => |reg| {
                if (!self.hasTokensLeft()) {
                    return Comp{ .copy = reg };
                }
                const reg1 = reg;
                const tok_op = try self.advance();
                const op: Op = switch (tok_op) {
                    Token.comment => {
                        self.position -= 1;
                        return Comp{ .copy = reg };
                    },
                    Token.semicolon => {
                        self.position -= 1;
                        return Comp{ .copy = reg };
                    },
                    Token.plus => Op.plus,
                    Token.minus => Op.minus,
                    Token.and_ => Op.and_,
                    Token.or_ => Op.or_,
                    else => {
                        return unexpectedToken(tok_op, "expected operation");
                    },
                };
                const tok_arg2 = try self.advance();
                const reg2: Register = switch (tok_arg2) {
                    Token.register => |r| r,
                    Token.one => switch (op) {
                        Op.plus => return Comp{ .inc = reg1 },
                        Op.minus => return Comp{ .dec = reg1 },
                        else => {
                            return unexpectedToken(tok_arg2, "expected + 1 or - 1 or register");
                        },
                    },
                    else => {
                        return unexpectedToken(tok_arg2, "expected register or 1");
                    },
                };
                const D = Register.D;
                const A = Register.A;
                const M = Register.M;
                if (reg1 == D and op == Op.plus and reg2 == A) {
                    return Comp.DplusA;
                } else if (reg1 == D and op == Op.minus and reg2 == A) {
                    return Comp.DminusA;
                } else if (reg1 == A and op == Op.minus and reg2 == D) {
                    return Comp.AminusD;
                } else if (reg1 == D and op == Op.and_ and reg2 == A) {
                    return Comp.DandA;
                } else if (reg1 == D and op == Op.or_ and reg2 == A) {
                    return Comp.DorA;
                } else if (reg1 == D and op == Op.plus and reg2 == M) {
                    return Comp.DplusM;
                } else if (reg1 == D and op == Op.minus and reg2 == M) {
                    return Comp.DminusM;
                } else if (reg1 == M and op == Op.minus and reg2 == D) {
                    return Comp.MminusD;
                } else if (reg1 == D and op == Op.and_ and reg2 == M) {
                    return Comp.DandM;
                } else if (reg1 == D and op == Op.or_ and reg2 == M) {
                    return Comp.DorM;
                } else {
                    return unexpectedToken(tok_arg2, "illegal second argument for this operation");
                }
            },
            else => {
                return unexpectedToken(tok, "expected comp");
            },
        };
        return comp;
    }

    fn parseJump(self: *TokenStream) anyerror!Jump {
        if (!self.hasTokensLeft()) {
            return Jump.J00;
        }
        var tok = try self.advance();
        switch (tok) {
            Token.semicolon => {},
            Token.comment => {
                self.position -= 1;
                return Jump.J00;
            },
            else => {
                return unexpectedToken(tok, "Expected ; or // comment");
            },
        }
        if (!self.hasTokensLeft()) {
            return Jump.J00;
        }
        tok = try self.advance();
        switch (tok) {
            Token.jump => |jmp| {
                return jmp;
            },
            else => {
                return unexpectedToken(tok, "Expected jump");
            },
        }
    }

    fn parseCInstr(self: *TokenStream) anyerror!Instr {
        const pos = self.position;
        var tok: Token = try self.advance();
        // dest
        var destA = false;
        var destD = false;
        var destM = false;
        while (true) {
            switch (tok) {
                // e.g. A = ...
                Token.register => |reg| {
                    switch (reg) {
                        Register.A => {
                            destA = true;
                        },
                        Register.D => {
                            destD = true;
                        },
                        Register.M => {
                            destM = true;
                        },
                    }
                    tok = try self.advance();
                },
                else => {
                    // e.g. 0;JMP
                    self.position -= 1;
                    break;
                },
            }
        }
        if (destA or destD or destM) {
            tok = try self.advance();
            switch (tok) {
                Token.semicolon => {
                    // e.g D;JNE
                    self.position = pos;
                    destA = false;
                    destD = false;
                    destM = false;
                },
                Token.eq => {},
                else => {
                    return unexpectedToken(tok, "Expected = or ;");
                },
            }
        }
        const comp: Comp = try self.parseComp();
        const jmp: Jump = try self.parseJump();
        return Instr{ .C = .{ .destA = destA, .destD = destD, .destM = destM, .comp = comp, .jump = jmp } };
    }

    fn parseInstr(self: *TokenStream) anyerror!Instr {
        var tok: Token = try self.advance();
        var instr: Instr = switch (tok) {
            Token.comment => |com| Instr{ .comment = com },
            Token.A_addr => |addr| Instr{ .A_addr = try checkAddr(addr) },
            Token.A_name => |name| Instr{ .A_name = name },
            Token.def_label => |labl| Instr{ .def_label = labl },
            else => {
                self.position -= 1;
                return self.parseCInstr();
            },
            //Token.semicolon  => {return Error.UnexpectedToken;},
            //Token.jump       => {return Error.UnexpectedToken;},
            //Token.eq         => {return Error.UnexpectedToken;},
            //Token.plus       => {return Error.UnexpectedToken;},
            //Token.minus      => {return Error.UnexpectedToken;},
            //Token.zero       =>
            //Token.one        =>
        };
        return instr;
    }

    pub fn appendInstructions(self: *TokenStream, out: *ArrayList(Instr)) anyerror!void {
        while (self.hasTokensLeft()) {
            const instr: Instr = try self.parseInstr();
            try out.append(instr);
        }
        return;
    }
};

pub fn instructionsFromTokens(out: *ArrayList(Instr), toks: *TokenStream) anyerror!void {
    try toks.appendInstructions(out);
}

test "instructionsFromTokens" {
    const test_allocator = testing.allocator;
    var out = ArrayList(Instr).init(test_allocator);
    defer out.deinit();
    var tok = Token{ .comment = "hello" };
    var toks_array = [_]Token{tok}; // an array. Arrays have static size. [_] means size inference
    var toks: TokenStream = .{ .items = &toks_array };

    try instructionsFromTokens(&out, &toks);
    //std.debug.print("{any}", .{out.items});
    try testing.expectEqual(out.items.len, 1);
    var instr = out.items[0];
    try testing.expect(std.mem.eql(u8, instr.comment, tok.comment));

    var toks_array2 = [_]Token{
        Token{ .comment = "some comment" },
        Token{ .A_name = "aname" },
        Token{ .def_label = "mylabel" },
        Token{ .A_addr = 1337 },
    };
    toks = TokenStream{ .items = &toks_array2 };
    try out.resize(0);
    try instructionsFromTokens(&out, &toks);
    try testing.expectEqual(out.items.len, 4);
    try testing.expect(std.mem.eql(u8, out.items[0].comment, toks_array2[0].comment));
    try testing.expect(std.mem.eql(u8, out.items[1].A_name, toks_array2[1].A_name));
    try testing.expect(std.mem.eql(u8, out.items[2].def_label, toks_array2[2].def_label));
    try testing.expectEqual(out.items[3].A_addr, toks_array2[3].A_addr);

    var toks_array3 = [_]Token{
        Token{ .register = Register.A },
        Token{ .eq = .{} },
        Token{ .zero = .{} },
        Token{ .semicolon = .{} },
        Token{ .jump = Jump.JMP },
    };
    toks = TokenStream{ .items = &toks_array3 };
    try out.resize(0);
    try instructionsFromTokens(&out, &toks);
    try testing.expectEqual(out.items[0], Instr{ .C = .{ .destA = true, .destD = false, .destM = false, .comp = Comp.zero, .jump = Jump.JMP } });

    var toks_array4 = [_]Token{
        Token{ .zero = {} },
        Token{ .semicolon = {} },
        Token{ .jump = Jump.JMP },
    };
    toks = TokenStream{ .items = &toks_array4 };
    try out.resize(0);
    try instructionsFromTokens(&out, &toks);
    try testing.expectEqual(out.items[0], Instr{ .C = .{ .destA = false, .destD = false, .destM = false, .comp = Comp.zero, .jump = Jump.JMP } });
}

////////////////////////////////////////////////////////////////////////////////
///// Machine Code
////////////////////////////////////////////////////////////////////////////////
const LoweringError = error{
    NoMachineCodeForComment,
    NoMachineCodeForA_name,
    NoMachineCodeFordef_label,
};

const MachineCodeFromInstrError = LoweringError || InvalidAddrError;

pub fn printMachineInstr(writer: anytype, minstr: u16) anyerror!void {
    //{[argument][specifier]:[fill][alignment][width].[precision]}`
    try writer.print("{b:0>16}", .{minstr});
    //const one : u16 = 1;
    //var i : u4 = 15;
    //while (true) {
    //    var mask : u16 = one << i;
    //    var digit = @bitCast(u1, (mask == mask & minstr));
    //    try writer.print("{d}", .{digit});
    //    if (@mod(i, 4) == 0) {
    //        try writer.print(" ", .{});
    //    }
    //    if (i == 0) break;
    //    i = i - 1;
    //}
}

pub fn assembleFileAbsolute(
    alloc: Allocator,
    path_asm: []const u8,
    path_hack: []const u8,
) anyerror!void {
    const instrs = try parseFileAbsolute(alloc, path_asm);
    defer {
        for (instrs.items) |instr| {
            instr.free(alloc);
        }
        instrs.deinit();
    }
    const instrs_lowered = try resolveSymbols(alloc, instrs);
    defer {
        instrs_lowered.deinit();
    }
    const file = try std.fs.createFileAbsolute(path_hack, .{});
    defer file.close();
    const writer = file.writer();
    for (instrs_lowered.items) |instr| {
        var machinstr: u16 = try instr.machineCode();
        try printMachineInstr(writer, machinstr);
        try writer.print("\n", .{});
    }
}

fn testAsm2Hack(alloc: Allocator, s: []const u8, expectedMach: u16) !void {
    const instr = try instrFromString(alloc, s);
    const mach = try instr.machineCode();
    try testing.expectEqual(expectedMach, mach);
}
test "ams2hack" {
    const alloc = testing.allocator;
    try testAsm2Hack(alloc, "@16", 0b0000000000010000);
    try testAsm2Hack(alloc, "M=1;J00", 0b1110111111001000);
    try testAsm2Hack(alloc, "@17", 0b0000000000010001);
    try testAsm2Hack(alloc, "M=0;J00", 0b1110101010001000);
    try testAsm2Hack(alloc, "@16", 0b0000000000010000);
    try testAsm2Hack(alloc, "D=M;J00", 0b1111110000010000);
    try testAsm2Hack(alloc, "@100", 0b0000000001100100);
    try testAsm2Hack(alloc, "D=D-A;J00", 0b1110010011010000);
    try testAsm2Hack(alloc, "@18", 0b0000000000010010);
    try testAsm2Hack(alloc, "D;JGT", 0b1110001100000001);
    try testAsm2Hack(alloc, "@16", 0b0000000000010000);
    try testAsm2Hack(alloc, "D=M;J00", 0b1111110000010000);
    try testAsm2Hack(alloc, "@17", 0b0000000000010001);
    try testAsm2Hack(alloc, "M=D+M;J00", 0b1111000010001000);
    try testAsm2Hack(alloc, "@16", 0b0000000000010000);
    try testAsm2Hack(alloc, "M=M+1;J00", 0b1111110111001000);
    try testAsm2Hack(alloc, "@4", 0b0000000000000100);
    try testAsm2Hack(alloc, "0;JMP", 0b1110101010000111);
    try testAsm2Hack(alloc, "@18", 0b0000000000010010);
    try testAsm2Hack(alloc, "0;JMP", 0b1110101010000111);
    try testAsm2Hack(alloc, "D=D-M", 0b1111010011010000);
}

fn testAssembler(alloc: Allocator, path_input: []const u8, path_output: []const u8, path_expected: []const u8) !void {
    const realpath_input = try testDataPath(alloc, path_input);
    defer alloc.free(realpath_input);
    const realpath_output = path_output;
    //try testDataPath(alloc, path_output);
    //defer alloc.free(realpath_output);
    const realpath_expected = try testDataPath(alloc, path_expected);
    defer alloc.free(realpath_expected);
    try assembleFileAbsolute(alloc, realpath_input, realpath_output);
    const max_file_size: u64 = 1_000_000;
    const file_output = try std.fs.openFileAbsolute(realpath_output, .{ .read = true });
    defer file_output.close();
    const reader_output = std.io.bufferedReader(file_output.reader()).reader();
    const s_output: []const u8 = try reader_output.readAllAlloc(alloc, max_file_size);
    defer alloc.free(s_output);

    const file_expected = try std.fs.openFileAbsolute(realpath_expected, .{ .read = true });
    defer file_expected.close();
    const reader_expected = std.io.bufferedReader(file_expected.reader()).reader();
    const s_expected = try reader_expected.readAllAlloc(alloc, max_file_size);
    defer alloc.free(s_expected);
    try std.testing.expect(std.mem.eql(u8, s_output, s_expected));
}

pub fn testDataPath(alloc: Allocator, rpath: []const u8) ![]const u8 {
    const dir = std.fs.cwd();
    const ret = dir.realpathAlloc(alloc, rpath) catch |err| {
        std.debug.print("Problem creating realpath for rpath = {s}\n dir = {}\n", .{ rpath, dir });
        return err;
    };
    return ret;
}

test "asm2hack end2end" {
    const alloc = testing.allocator;
    //const dir = "testdata/";
    //const dir = "/home/jan/projects/LearnZig/nand2tetris/testdata";
    const dir = "testdata/assembler/";
    try testAssembler(
        alloc,
        dir ++ "Add.asm",
        "/tmp/Add.hack",
        dir ++ "Add.hack",
    );
    try testAssembler(
        alloc,
        dir ++ "MaxL.asm",
        "/tmp/MaxL.hack",
        dir ++ "MaxL.hack",
    );
    try testAssembler(
        alloc,
        dir ++ "Max.asm",
        "/tmp/Max.hack",
        dir ++ "Max.hack",
    );
    try testAssembler(
        alloc,
        dir ++ "RectL.asm",
        "/tmp/RectL.hack",
        dir ++ "RectL.hack",
    );
    try testAssembler(
        alloc,
        dir ++ "Rect.asm",
        "/tmp/Rect.hack",
        dir ++ "Rect.hack",
    );
    try testAssembler(
        alloc,
        dir ++ "PongL.asm",
        "/tmp/PongL.hack",
        dir ++ "PongL.hack",
    );
    try testAssembler(
        alloc,
        dir ++ "Pong.asm",
        "/tmp/Pong.hack",
        dir ++ "Pong.hack",
    );
}
