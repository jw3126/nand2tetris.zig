const std = @import("std");
const m = @import("mecha");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const hasm = @import("hasm.zig");

fn unreachableAllocFn(self: Allocator, len: usize, ptr_align: u29, len_align: u29, ret_addr: usize) std.mem.Allocator.Error![]u8 {
    _ = self;
    _ = len;
    _ = ptr_align;
    _ = len_align;
    _ = ret_addr;
    unreachable;
}

fn unreachableResizeFn(self: Allocator, buf: []u8, buf_align: u29, new_len: usize, len_align: u29, ret_addr: usize) std.mem.Allocator.Error!usize {
    _ = self;
    _ = buf;
    _ = buf_align;
    _ = new_len;
    _ = len_align;
    _ = ret_addr;
    unreachable;
}

pub fn tokenizeFileAbsolute(alloc: Allocator, path: []const u8) anyerror!ArrayList(Token) {
    const file = try std.fs.openFileAbsolute(path, .{ .read = true });
    defer file.close();
    const reader = std.io.bufferedReader(file.reader()).reader();
    var ret = ArrayList(Token).init(alloc);
    var buf: [1024]u8 = undefined;
    while (try reader.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        //std.debug.print("//// Start Parsing: ~~{s}~~\n", .{line});
        var toks = (try Parsers.tokens(alloc, line)).value;
        defer alloc.free(toks);
        //std.debug.print("//// Stop Parsing: ~~{s}~~\n", .{line});
        try ret.appendSlice(toks);
    }
    return ret;
}

test "tokenizeFileAbsolute" {
    const test_allocator = testing.allocator;
    const dir: []const u8 = try hasm.testDataPath(test_allocator, "testdata/vmtranslator");
    defer test_allocator.free(dir);
    var filenames = ArrayList([]const u8).init(test_allocator);
    defer filenames.deinit();
    try filenames.append("BasicTest.vm");
    try filenames.append("PointerTest.vm");
    try filenames.append("StackTest.vm");
    try filenames.append("StackTest.vm");
    for (filenames.items) |filename| {
        var path = ArrayList(u8).init(test_allocator);
        defer path.deinit();
        try path.appendSlice(dir);
        try path.append('/');
        try path.appendSlice(filename);
        const toks = try tokenizeFileAbsolute(test_allocator, path.items);
        defer {
            for (toks.items) |tok| {
                tok.deinit(test_allocator);
            }
            toks.deinit();
        }
    }
}

pub fn makeParser(comptime word: []const u8, comptime tok: Token) m.Parser(Token) {
    const ClosureStruct = struct {
        pub fn parser(_: Allocator, str: []const u8) m.Error!m.Result(Token) {
            const n = word.len;
            if (str.len < n) {
                return m.Error.ParserFailed;
            } else if (std.mem.eql(u8, word, str[0..n])) {
                return m.Result(Token){ .value = tok, .rest = str[n..] };
            } else {
                return m.Error.ParserFailed;
            }
        }
    };
    return ClosureStruct.parser;
}

test "makeParser" {
    const test_allocator = testing.allocator;
    {
        var res = try Parsers.push(test_allocator, "push");
        try testing.expectEqual(res.value, Token{ .push = .{} });
    }
    {
        var res = try Parsers.push(test_allocator, "push pointer 0");
        try testing.expectEqual(res.value, Token{ .push = .{} });
    }
    {
        var res = try Parsers.function(test_allocator, "function foo 0");
        try testing.expectEqual(res.value, Token{ .function = .{} });
    }
    {
        var res = try Parsers.argument(test_allocator, "argument 0");
        defer res.value.deinit(test_allocator);
        try testing.expectEqual(res.value, Token{ .segment = Segment.argument });
    }
    {
        var res = try Parsers.comment(test_allocator, "// argument 0\n");
        defer res.value.deinit(test_allocator);
        try testing.expect(std.mem.eql(u8, res.value.comment, " argument 0"));
    }
    {
        var res = try Parsers.identifier(test_allocator, "foo123 ");
        defer res.value.deinit(test_allocator);
        try testing.expect(std.mem.eql(u8, res.value.identifier, "foo123"));
    }
    {
        var res = try Parsers.integer(test_allocator, "123 ");
        defer res.value.deinit(test_allocator);
        try testing.expectEqual(res.value.integer, 123);
    }
}
test "token" {
    const test_allocator = testing.allocator;
    {
        var res = try Parsers.token(test_allocator, "push");
        defer res.value.deinit(test_allocator);
        try testing.expectEqual(res.value, Token{ .push = .{} });
    }
    {
        var res = try Parsers.token(test_allocator, "push pointer 0");
        defer res.value.deinit(test_allocator);
        try testing.expectEqual(res.value, Token{ .push = .{} });
    }
    {
        var res = try Parsers.token(test_allocator, "if-goto COMPUTE_ELEMENT ");
        defer res.value.deinit(test_allocator);
        try testing.expectEqual(res.value, Token{ .if_goto = .{} });
    }
    {
        var res = try Parsers.token(test_allocator, "function foo 0");
        defer res.value.deinit(test_allocator);
        try testing.expectEqual(res.value, Token{ .function = .{} });
    }
    {
        var res = try Parsers.token(test_allocator, "argument 0");
        defer res.value.deinit(test_allocator);
        try testing.expectEqual(res.value, Token{ .segment = Segment.argument });
    }
    {
        var res = try Parsers.token(test_allocator, "// argument 0\n");
        defer res.value.deinit(test_allocator);
        try testing.expect(std.mem.eql(u8, res.value.comment, " argument 0"));
    }
    {
        var res = try Parsers.token(test_allocator, "foo123 ");
        defer res.value.deinit(test_allocator);
        try testing.expect(std.mem.eql(u8, res.value.identifier, "foo123"));
    }
    {
        var res = try Parsers.token(test_allocator, "123 ");
        defer res.value.deinit(test_allocator);
        try testing.expectEqual(res.value.integer, 123);
    }
}

const Parsers = struct {
    const tokens = m.many(token, .{ .collect = true });

    pub fn identifier(alloc: Allocator, str: []const u8) m.Error!m.Result(Token) {
        const res_str = try @import("hasm.zig").identifier(alloc, str);
        const tok = Token{ .identifier = res_str.value };
        return m.Result(Token){ .value = tok, .rest = res_str.rest };
    }

    pub fn comment(alloc: Allocator, str: []const u8) m.Error!m.Result(Token) {
        const res_str = try @import("hasm.zig").comment_str(alloc, str);
        const tok = Token{ .comment = res_str.value };
        return m.Result(Token){ .value = tok, .rest = res_str.rest };
    }

    pub fn integer(alloc: Allocator, str: []const u8) m.Error!m.Result(Token) {
        const int = m.int(u16, .{ .base = 10, .parse_sign = false });
        const res_str = try int(alloc, str);
        const tok = Token{ .integer = res_str.value };
        return m.Result(Token){ .value = tok, .rest = res_str.rest };
    }

    const push = makeParser("push", Token{ .push = {} });
    const pop = makeParser("pop", Token{ .pop = {} });
    const add = makeParser("add", Token{ .add = {} });
    const sub = makeParser("sub", Token{ .sub = {} });
    const neg = makeParser("neg", Token{ .neg = {} });
    const not = makeParser("not", Token{ .not = {} });
    const and_ = makeParser("and", Token{ .and_ = {} });
    const or_ = makeParser("or", Token{ .or_ = {} });
    const lt = makeParser("lt", Token{ .lt = {} });
    const eq = makeParser("eq", Token{ .eq = {} });
    const gt = makeParser("gt", Token{ .gt = {} });
    const goto = makeParser("goto", Token{ .goto = {} });
    const if_goto = makeParser("if-goto", Token{ .if_goto = {} });
    const function = makeParser("function", Token{ .function = {} });
    const return_ = makeParser("return", Token{ .return_ = {} });
    const call = makeParser("call", Token{ .call = {} });

    // segment
    const argument = makeParser("argument", Token{ .segment = Segment.argument });
    const local = makeParser("local", Token{ .segment = Segment.local });
    const static = makeParser("static", Token{ .segment = Segment.static });
    const constant = makeParser("constant", Token{ .segment = Segment.constant });
    const this = makeParser("this", Token{ .segment = Segment.this });
    const that = makeParser("that", Token{ .segment = Segment.that });
    const pointer = makeParser("pointer", Token{ .segment = Segment.pointer });
    const temp = makeParser("temp", Token{ .segment = Segment.temp });

    const spaces_or_tabs = @import("hasm.zig").spaces_or_tabs;

    const token: m.Parser(Token) = m.combine(.{
        spaces_or_tabs,
        m.oneOf(.{
            push,
            pop,
            add,
            sub,
            neg,
            not,
            and_,
            or_,
            lt,
            eq,
            gt,
            goto,
            if_goto,
            function,
            return_,
            call,
            argument,
            local,
            static,
            constant,
            this,
            that,
            pointer,
            temp,
            comment,
            integer,
            identifier,
        }),
        spaces_or_tabs,
    });
};

const Segment = enum {
    argument,
    local,
    static,
    constant,
    this,
    that,
    pointer,
    temp,
    pub fn absoluteAddress(self: Segment, offset: u16) !u16 {
        switch (self) {
            .argument => return offset + 0,
            .local => return offset + 0,
            .static => return offset + 0,
            .constant => return error.ConstantSegmentHasNoPhysicalAddress,
            .this => return offset + 0,
            .that => return offset + 0,
            .pointer => return offset + 0,
            .temp => return offset + 0,
        }
    }
};

const Token = union(enum) {
    add,
    sub,
    neg,
    not,
    and_,
    or_,
    lt,
    eq,
    gt,
    return_,
    push,
    pop,
    goto,
    if_goto,
    function,
    call,
    label,
    segment: Segment,
    comment: []const u8,
    identifier: []const u8,
    integer: u16,

    pub fn deinit(tok: Token, alloc: Allocator) void {
        switch (tok) {
            Token.comment => |s| alloc.free(s),
            Token.identifier => |s| alloc.free(s),
            else => {},
        }
    }
};

const Addr = struct {
    const SP: u16 = 0;
    const LCL: u16 = 1;
    const ARG: u16 = 2;
    const THIS: u16 = 3;
    const THAT: u16 = 4;
    const R13: u16 = 13;
    const R14: u16 = 14;
    const R15: u16 = 15;
    const STATIC: u16 = 16;
};

const Instr = union(enum) {
    push: struct { segment: Segment, offset: u16 },
    pop: struct { segment: Segment, offset: u16 },
    function: struct { name: []const u8, nlocals: u16 },
    call: struct { name: []const u8, nargs: u16 },
    def_label: []const u8, // label
    comment: []const u8, // content
    goto: []const u8, // label
    if_goto: []const u8, // label
    add,
    sub,
    neg,
    not,
    and_,
    or_,
    lt,
    eq,
    gt,
    return_,

    fn setA(out: *ArrayList(hasm.Instr), addr: u16) !void {
        const instr = hasm.Instr{ .A_addr = addr };
        return out.append(instr);
    }

    fn incStackPointer(alloc: Allocator, out: *ArrayList(hasm.Instr)) !void {
        try Instr.setA(out, Addr.SP);
        try Instr.litasm(alloc, out, "M=M+1");
    }

    // set A to top of stack
    fn setAtopMSP(alloc: Allocator, out: *ArrayList(hasm.Instr)) !void {
        try Instr.setA(out, Addr.SP);
        try Instr.litasm(alloc, out, "A=M");
    }

    fn litasm(alloc: Allocator, out: *ArrayList(hasm.Instr), str: []const u8) !void {
        const instr = try hasm.instrFromString(alloc, str);
        try out.append(instr);
    }

    fn appendHasmPush(alloc: Allocator, out: *ArrayList(hasm.Instr), segment: Segment, offset: u16) !void {
        _ = segment;
        _ = offset;
        switch (segment) {
            Segment.constant => {
                try Instr.setA(out, offset); // @offset
                try Instr.litasm(alloc, out, "D = A");
            },
            else => {
                const addr = try segment.absoluteAddress(offset);
                try Instr.setA(out, addr);
                try Instr.litasm(alloc, out, "D = M");
            },
        }
        //try Instr.setAtopMSP(alloc, out);
        try Instr.litasm(alloc, out, "M = D");
        try Instr.incStackPointer(alloc, out);
    }

    pub fn appendHasm(self: Instr, alloc: Allocator, out: *ArrayList(hasm.Instr)) !void {
        switch (self) {
            Instr.push => |p| {
                const segment = p.segment;
                const offset = p.offset;
                try Instr.appendHasmPush(alloc, out, segment, offset);
            },
            else => unreachable,
        }
    }
};

test "Instr to asm" {
    const test_allocator = std.testing.allocator;
    {
        const instr = Instr{ .push = .{ .segment = Segment.constant, .offset = 42 } };
        var out = ArrayList(hasm.Instr).init(test_allocator);
        defer out.deinit();
        try instr.appendHasm(test_allocator, &out);
        // for (out.items) |item| {
        //     std.debug.print("{}\n", .{item});
        // }
    }
}

const Error = error{
    UnexpectedToken,
    UnexpectedEndOfTokens,
};

fn unexpectedToken(tok: Token, msg: []const u8) Error {
    std.debug.print("Got unexpected token {any}\n {s}", .{ tok, msg });
    return Error.UnexpectedToken;
}

test "TokenStream" {
    const toks = [_]Token{ Token{ .push = .{} }, Token{ .segment = Segment.constant }, Token{ .integer = 1 } };
    const slice: []const Token = toks[0..3];
    var stream = TokenStream{ .items = slice };
    const instr = try stream.parseInstr();
    try testing.expectEqual(instr.push.offset, 1);
    try testing.expectEqual(instr.push.segment, Segment.constant);
}

pub const TokenStream = struct {
    items: []const Token,
    position: usize = 0,
    fn advance(self: *TokenStream) !Token {
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

    pub fn appendInstructions(self: *TokenStream, out: *ArrayList(Instr)) !void {
        while (self.hasTokensLeft()) {
            const instr: Instr = try self.parseInstr();
            try out.append(instr);
        }
        return;
    }

    pub fn parseInstr(self: *TokenStream) !Instr {
        const tok = try self.advance();
        switch (tok) {
            Token.push => {
                const seg = try self.advanceSegment();
                const offset = try self.advanceInteger();
                return Instr{ .push = .{ .segment = seg, .offset = offset } };
            },
            Token.pop => {
                const seg = try self.advanceSegment();
                const offset = try self.advanceInteger();
                return Instr{ .pop = .{ .segment = seg, .offset = offset } };
            },
            Token.label => {
                const name = try self.advanceIdentifier();
                return Instr{ .def_label = name };
            },
            Token.goto => {
                const name = try self.advanceIdentifier();
                return Instr{ .goto = name };
            },
            Token.if_goto => {
                const name = try self.advanceIdentifier();
                return Instr{ .if_goto = name };
            },
            Token.function => {
                const name = try self.advanceIdentifier();
                const nlocals = try self.advanceInteger();
                return Instr{ .function = .{ .name = name, .nlocals = nlocals } };
            },
            Token.call => {
                const name = try self.advanceIdentifier();
                const nargs = try self.advanceInteger();
                return Instr{ .call = .{ .name = name, .nargs = nargs } };
            },
            Token.comment => |s| {
                return Instr{ .comment = s };
            },
            Token.add => {
                return Instr{ .add = .{} };
            },
            Token.sub => {
                return Instr{ .sub = .{} };
            },
            Token.neg => {
                return Instr{ .neg = .{} };
            },
            Token.not => {
                return Instr{ .not = .{} };
            },
            Token.and_ => {
                return Instr{ .and_ = .{} };
            },
            Token.or_ => {
                return Instr{ .or_ = .{} };
            },
            Token.lt => {
                return Instr{ .lt = .{} };
            },
            Token.eq => {
                return Instr{ .eq = .{} };
            },
            Token.gt => {
                return Instr{ .gt = .{} };
            },
            Token.return_ => {
                return Instr{ .return_ = .{} };
            },
            Token.segment => {
                return unexpectedToken(tok, "");
            },
            Token.identifier => {
                return unexpectedToken(tok, "");
            },
            Token.integer => {
                return unexpectedToken(tok, "");
            },
        }
    }

    fn advanceSegment(self: *TokenStream) !Segment {
        const tok = try self.advance();
        return switch (tok) {
            Token.segment => |segment| segment,
            else => unexpectedToken(tok, "expected segment"),
        };
    }

    fn advanceInteger(self: *TokenStream) !u16 {
        const tok = try self.advance();
        return switch (tok) {
            Token.integer => |x| x,
            else => unexpectedToken(tok, "expected integer"),
        };
    }
    fn advanceIdentifier(self: *TokenStream) ![]const u8 {
        const tok = try self.advance();
        return switch (tok) {
            Token.identifier => |x| x,
            else => unexpectedToken(tok, "expected identifier"),
        };
    }
};
