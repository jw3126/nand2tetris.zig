const std = @import("std");
const m = @import("mecha");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

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
    function,
    return_,
    call,
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

// push constant 10
// pop local 0
// push constant 21
// push constant 22
// pop argument 2
// pop argument 1
// push constant 36
// pop this 6
// push constant 42
// push constant 45
// pop that 5
// pop that 2
// push constant 510
// pop temp 6
// push local 0
// push that 5
// add
// push argument 1
// sub
// push this 6
// push this 6
// add
// sub
// push temp 6
// add
