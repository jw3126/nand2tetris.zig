const std = @import("std");
const m = @import("mecha");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const hasm = @import("hasm.zig");

pub fn tokenizeFileAbsolute(alloc: *Allocator, path : [] const u8) anyerror!ArrayList(Token) {
    const file = try std.fs.openFileAbsolute(path, .{.read=true});
    defer file.close();
    const reader = std.io.bufferedReader(file.reader()).reader();
    var ret = ArrayList(Token).init(alloc);
    var buf : [1024]u8 = undefined;
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
    const dir : []const u8 = try hasm.testDataPath(test_allocator, "testdata/vmtranslator");
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

pub fn makeParser(comptime word : []const u8, comptime tok : Token) m.Parser(Token) {
    const ClosureStruct = struct {
        pub fn parser(_:*Allocator, str : []const u8) m.Error!m.Result(Token) {
            const n = word.len;
            if (str.len < n) {
                return m.Error.ParserFailed;
            } else if (std.mem.eql(u8, word, str[0..n])) {
                return m.Result(Token){.value=tok, .rest=str[n..]};
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
        try testing.expectEqual(res.value, Token{.push=.{}});
     }
     {
        var res = try Parsers.push(test_allocator, "push pointer 0");
        try testing.expectEqual(res.value, Token{.push=.{}});
     }
     {
        var res = try Parsers.function(test_allocator, "function foo 0");
        try testing.expectEqual(res.value, Token{.function=.{}});
     }
     {
        var res = try Parsers.argument(test_allocator, "argument 0");
        defer res.value.deinit(test_allocator);
        try testing.expectEqual(res.value, Token{.segment=Segment.argument});
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
        try testing.expectEqual(res.value, Token{.push=.{}});
     }
     {
        var res = try Parsers.token(test_allocator, "push pointer 0");
        defer res.value.deinit(test_allocator);
        try testing.expectEqual(res.value, Token{.push=.{}});
     }
     {
        var res = try Parsers.token(test_allocator, "if-goto COMPUTE_ELEMENT ");
        defer res.value.deinit(test_allocator);
        try testing.expectEqual(res.value, Token{.if_goto=.{}});
     }
     {
        var res = try Parsers.token(test_allocator, "function foo 0");
        defer res.value.deinit(test_allocator);
        try testing.expectEqual(res.value, Token{.function=.{}});
     }
     {
        var res = try Parsers.token(test_allocator, "argument 0");
        defer res.value.deinit(test_allocator);
        try testing.expectEqual(res.value, Token{.segment=Segment.argument});
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

    const tokens = m.many(token, .{.collect=true});

    pub fn identifier(alloc : *Allocator, str : []const u8) m.Error!m.Result(Token) {
        const res_str = try @import("hasm.zig").identifier(alloc, str);
        const tok = Token{.identifier=res_str.value};
        return m.Result(Token){.value=tok, .rest=res_str.rest};
    }

    pub fn comment(alloc : *Allocator, str : [] const u8) m.Error!m.Result(Token) {
        const res_str = try @import("hasm.zig").comment_str(alloc, str);
        const tok = Token{.comment=res_str.value};
        return m.Result(Token){.value=tok, .rest=res_str.rest};
    }

    pub fn integer(alloc : *Allocator, str : [] const u8) m.Error!m.Result(Token) {
        const int = m.int(u16, .{.base=10, .parse_sign=false});
        const res_str = try int(alloc, str);
        const tok = Token{.integer=res_str.value};
        return m.Result(Token){.value=tok, .rest=res_str.rest};
    }

    const push     = makeParser("push"     , Token{.push     = {}});
    const pop      = makeParser("pop"      , Token{.pop      = {}});
    const add      = makeParser("add"      , Token{.add      = {}});
    const sub      = makeParser("sub"      , Token{.sub      = {}});
    const neg      = makeParser("neg"      , Token{.neg      = {}});
    const not      = makeParser("not"      , Token{.not      = {}});
    const and_     = makeParser("and"      , Token{.and_     = {}});
    const or_      = makeParser("or"       , Token{.or_      = {}});
    const lt       = makeParser("lt"       , Token{.lt       = {}});
    const eq       = makeParser("eq"       , Token{.eq       = {}});
    const gt       = makeParser("gt"       , Token{.gt       = {}});
    const goto     = makeParser("goto"     , Token{.goto     = {}});
    const if_goto  = makeParser("if-goto"  , Token{.if_goto     = {}});
    const function = makeParser("function" , Token{.function = {}});
    const return_  = makeParser("return"   , Token{.return_  = {}});
    const call     = makeParser("call"     , Token{.call     = {}});

    // segment
    const argument = makeParser("argument" , Token{.segment = Segment.argument});
    const local    = makeParser("local"    , Token{.segment = Segment.local});
    const static   = makeParser("static"   , Token{.segment = Segment.static});
    const constant = makeParser("constant" , Token{.segment = Segment.constant});
    const this     = makeParser("this"     , Token{.segment = Segment.this});
    const that     = makeParser("that"     , Token{.segment = Segment.that});
    const pointer  = makeParser("pointer"  , Token{.segment = Segment.pointer});
    const temp     = makeParser("temp"     , Token{.segment = Segment.temp});

    const spaces_or_tabs = @import("hasm.zig").spaces_or_tabs;

    const token : m.Parser(Token) = m.combine(.{spaces_or_tabs,
        m.oneOf(.{
            push      ,
            pop       ,
            add       ,
            sub       ,
            neg       ,
            not       ,
            and_      ,
            or_       ,
            lt        ,
            eq        ,
            gt        ,
            goto      ,
            if_goto   ,
            function  ,
            return_   ,
            call      ,
            argument  ,
            local     ,
            static    ,
            constant  ,
            this      ,
            that      ,
            pointer   ,
            temp      ,
            comment   ,
            integer   ,
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
    segment : Segment,
    comment : [] const u8,
    identifier : [] const u8,
    integer : u16,

    pub fn deinit(tok : Token, alloc : *Allocator) void {
        switch(tok) {
            Token.comment => |s| alloc.free(s),
            Token.identifier => |s| alloc.free(s),
            else => {},
        }
    }
};

const Instr = union(enum) {
    push     : struct {segment: Segment, offset:u16},
    pop      : struct {segment: Segment, offset:u16},
    function : struct {name:[] const u8, nlocals:u16},
    call     : struct {name:[] const u8, nargs:u16},
    def_label: [] const u8, // label
    comment  : [] const u8, // content
    goto     : [] const u8, // label
    if_goto  : [] const u8, // label
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
};

const Error = error {
    UnexpectedToken,
    UnexpectedEndOfTokens,
};

fn unexpectedToken(tok : Token, msg : []const u8) Error {
    std.debug.print("Got unexpected token {any}\n {s}", .{tok, msg});
    return Error.UnexpectedToken;
}


test "TokenStream" {
    const toks = [_]Token {Token{.push=.{}}, Token{.segment=Segment.constant}, Token{.integer=1}};
    const slice :[]const Token = toks[0..3];
    var stream = TokenStream{.items=slice};
    const instr = try stream.parseInstr();
    try testing.expectEqual(instr.push.offset, 1);
    try testing.expectEqual(instr.push.segment, Segment.constant);
}

pub const TokenStream = struct {
    items : []const Token,
    position : usize = 0,
    fn advance(self : *TokenStream) !Token {
        const pos = self.position;
        if (pos >= self.items.len) {
            return Error.UnexpectedEndOfTokens;
        } else {
            self.position = pos+1;
            const tok = self.items[pos];
            //std.debug.print("{any}", .{tok});
            return tok;
        }
    }

    fn hasTokensLeft(self : *TokenStream) bool {
        return (self.position < self.items.len);
    }

    pub fn appendInstructions(self : *TokenStream, out : *ArrayList(Instr)) !void {
        while (self.hasTokensLeft()) {
            const instr : Instr = try self.parseInstr();
            try out.append(instr);
        }
        return;
    }

    pub fn parseInstr(self : *TokenStream) !Instr {
        const tok = try self.advance();
        switch(tok) {
            Token.push => {
                const seg    = try self.advanceSegment();
                const offset = try self.advanceInteger();
                return Instr{.push = .{.segment=seg, .offset=offset}};
            },
            Token.pop => {
                const seg    = try self.advanceSegment();
                const offset = try self.advanceInteger();
                return Instr{.pop = .{.segment=seg, .offset=offset}};
            },
            Token.label => {
                const name = try self.advanceIdentifier();
                return Instr{.def_label=name};
            },
            Token.goto => {
                const name = try self.advanceIdentifier();
                return Instr{.goto=name};
            },
            Token.if_goto => {
                const name = try self.advanceIdentifier();
                return Instr{.if_goto=name};
            },
            Token.function => {
                const name = try self.advanceIdentifier();
                const nlocals = try self.advanceInteger();
                return Instr{.function=.{.name=name, .nlocals=nlocals}};
            },
            Token.call => {
                const name = try self.advanceIdentifier();
                const nargs = try self.advanceInteger();
                return Instr{.call=.{.name=name, .nargs=nargs}};
            },
            Token.comment => |s| {return Instr{.comment=s};},
            else => unreachable,
        }
    }

    fn advanceSegment(self : *TokenStream) !Segment {
        const tok = try self.advance();
        return switch(tok) {
            Token.segment => |segment| segment,
            else => unexpectedToken(tok, "expected segment"),
        };
    }

    fn advanceInteger(self : *TokenStream) !u16 {
        const tok = try self.advance();
        return switch(tok) {
            Token.integer => |x| x,
            else => unexpectedToken(tok, "expected integer"),
        };
    }
    fn advanceIdentifier(self : *TokenStream) ![]const u8 {
        const tok = try self.advance();
        return switch(tok) {
            Token.identifier => |x| x,
            else => unexpectedToken(tok, "expected identifier"),
        };
    }
};
