bytes: []const u8,
line: usize = 0,

const std = @import("std");
const Ini = @This();

pub const ParseError = error{
    ExpectedEquals,
    ExpectedCloseBracket,
    ExpectedNewline,
};

pub fn next(self: *Ini) ParseError!?Entry {
    self.line += 1;

    const whitespace = " \t\r";
    const bytes = std.mem.trimLeft(u8, self.bytes, whitespace);
    if (bytes.len == 0) {
        return null;
    }

    const newline = std.mem.indexOfScalar(u8, bytes, '\n') orelse bytes.len;
    self.bytes = bytes[@min(newline + 1, bytes.len)..];

    if (bytes[0] == '\n' or bytes[0] == ';') {
        return self.next();
    }

    if (bytes[0] == '[') {
        const end = std.mem.lastIndexOfScalar(u8, bytes[0..newline], ']') orelse return error.ExpectedCloseBracket;
        if (std.mem.indexOfNone(u8, bytes[end + 1 .. newline], whitespace)) |_| {
            return error.ExpectedNewline;
        }
        return .{
            .key = std.mem.trim(u8, bytes[1..end], whitespace),
            .value = null,
        };
    }

    if (std.mem.indexOfScalar(u8, bytes[0..newline], '=')) |equals| {
        return .{
            .key = std.mem.trim(u8, bytes[0..equals], whitespace),
            .value = std.mem.trim(u8, bytes[equals + 1 .. newline], whitespace),
        };
    }

    return error.ExpectedEquals;
}

pub const Entry = struct {
    key: []const u8,
    value: ?[]const u8,

    pub fn unpack(self: Entry, dest: anytype, comptime options: UnpackOptions) !void {
        const fields = if (@TypeOf(dest) == type) @typeInfo(dest).@"struct".decls else @typeInfo(@TypeOf(dest.*)).@"struct".fields;

        inline for (fields) |field| blk: {
            const ptr = &@field(dest, field.name);
            const FieldType = @TypeOf(ptr.*);

            switch (@typeInfo(FieldType)) {
                .@"fn", .type => break :blk,
                else => {},
            }

            for (options.blacklist) |item| {
                if (std.mem.eql(u8, item, field.name)) break :blk;
            }

            if (options.whitelist.len > 0) ok: {
                for (options.whitelist) |item| {
                    if (std.mem.eql(u8, item, field.name)) break :ok;
                }
                break :blk;
            }

            if (std.mem.eql(u8, field.name, self.key)) {
                return set(FieldType, ptr, self.value.?);
            }
        }

        return error.UnknownKey;
    }

    // ptr is anytype to allow *T and *?T
    fn set(comptime T: type, ptr: anytype, value: []const u8) !void {
        if (T == []const u8) {
            ptr.* = value;
            return;
        }

        switch (@typeInfo(T)) {
            .int => ptr.* = try std.fmt.parseInt(T, value, 10),
            .float => ptr.* = try std.fmt.parseFloat(T, value),
            .bool => ptr.* = if (std.mem.eql(u8, value, "true")) true else if (std.mem.eql(u8, value, "false")) false else return error.InvalidBool,
            .@"enum" => ptr.* = std.meta.stringToEnum(T, value) orelse return error.InvalidEnum,
            .optional => return set(std.meta.Child(T), ptr, value),
            .array => {
                var iter = std.mem.tokenizeScalar(u8, value, ' ');
                for (ptr) |*elem_ptr| {
                    const elem = iter.next() orelse return error.NotEnoughElements;
                    try set(std.meta.Child(T), elem_ptr, elem);
                }
                if (iter.next() != null) return error.ExtraElement;
            },
            else => @compileError("unsupported type: " ++ @typeName(T)),
        }
    }
};

pub fn write(values: anytype, writer: anytype, comptime options: UnpackOptions) !void {
    const fields = if (@TypeOf(values) == type) @typeInfo(values).@"struct".decls else @typeInfo(@TypeOf(values)).@"struct".fields;

    inline for (fields) |field| {
        const value = @field(values, field.name);
        var ok = true;

        switch (@typeInfo(@TypeOf(value))) {
            .@"fn", .type => continue,
            .optional => ok = (value != null),
            else => {},
        }

        for (options.blacklist) |item| {
            if (std.mem.eql(u8, item, field.name)) continue;
        }

        if (options.whitelist.len > 0) ok: {
            for (options.whitelist) |item| {
                if (std.mem.eql(u8, item, field.name)) break :ok;
            }
            continue;
        }

        if (ok) {
            try writer.print("{s} = ", .{field.name});
            try writeEntry(value, writer);
            try writer.writeByte('\n');
        }
    }
}

fn writeEntry(value: anytype, writer: anytype) !void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .pointer => try writer.print("{s}", .{value}),
        .int, .float, .bool => try writer.print("{}", .{value}),
        .@"enum" => try writer.print("{s}", .{@tagName(value)}),
        .array => {
            try writer.print("{}", .{value[0]});
            for (value[1..]) |elem| try writer.print(" {}", .{elem});
        },
        .optional => try writeEntry(value.?, writer),
        else => @compileError("unsupported type: " ++ @typeName(T)),
    }
}

pub const UnpackOptions = struct {
    blacklist: []const []const u8 = &.{},
    whitelist: []const []const u8 = &.{},
};
