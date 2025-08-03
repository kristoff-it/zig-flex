const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub const Options = struct {
    /// The parent type, usually provided via `@This()`.
    parent: type,
    /// The enum literal matching the field name of this flexible array.
    name: @Type(.enum_literal),
    /// The type to be used to store length information for the flexible array.
    ///
    /// Normally you will want to provide an integer type (e.g. u32, u27), but
    /// `void` and `bool` are also allowed:
    ///
    /// - `bool` will allow you to use `.get()` instead of `.slice()` on this
    ///    field
    /// - `void` will make the flexible array *NOT* store length information
    ///    which you will have to track externally (e.g. by deriving it from
    ///    other state in the struct) and occasionally provide to flex APIs.
    ///
    /// When a flexible array has a `void` length type, `.slice()` will return
    /// a [*]T. When present, length information will be stored in a packed
    /// struct so FlexibleArray can also be used with extern and packed structs.
    ///
    /// When length type is not `void`, you can access length information via
    /// `field.len`.
    length_type: type = usize,
};

pub fn Array(T: type, opts: Options) type {
    const P = opts.parent;

    return packed struct {
        len: LengthType,

        const IsFlexibleArray = {};
        const Child = T;
        const LengthType = opts.length_type;
        comptime {
            const pinfo = @typeInfo(P).@"struct"; // opts.parent must be a struct
            switch (LengthType) {
                bool => {},
                void => if (pinfo.fields[pinfo.fields.len - 1].type != @This()) {
                    @compileError("Only the last field of a struct can nave a `null` length type");
                },
                else => if (@typeInfo(LengthType) != .int) {
                    @compileError("Len must be an integer type or void");
                },
            }
        }

        pub fn init(f: *@This(), values: []const T) void {
            const s = f.slice();
            @memcpy(s, values); // 'values' has different len than allocated memory
        }

        /// Returns a pointer to the flexible value, only available when
        /// length_type is `bool`.
        pub fn getPtr(f: *@This()) ?*T {
            if (LengthType != bool) @compileError(
                "get is only available for flexible arrays of length type 'bool'",
            );

            return if (f.len) &f.sliceImpl()[0] else null;
        }

        /// Returns a slice to the flexible array. If the flexible array has
        /// length_type set to `void`, the return value will be [*]T, otherwise
        /// it will be []T.
        ///
        /// Not available when length_type is `bool`, use `get` instead.
        pub fn slice(f: *@This()) ReturnType {
            return switch (LengthType) {
                bool => @compileError(
                    "use 'get' on flexible arrays of length type 'bool'",
                ),
                else => f.sliceImpl(),
            };
        }

        const ReturnType = if (LengthType == void) [*]T else []T;
        fn sliceImpl(f: *@This()) ReturnType {
            const pinfo = @typeInfo(P).@"struct"; // opts.parent must be a struct
            const name = @tagName(opts.name);

            const parent: *P = @alignCast(@fieldParentPtr(name, f));
            const bytes: [*]align(@alignOf(P)) u8 = @ptrCast(parent);

            var offset: usize = @sizeOf(P);
            inline for (pinfo.fields) |field| {
                const is_flexible = @typeInfo(field.type) == .@"struct" and
                    @hasDecl(field.type, "IsFlexibleArray");

                if (!is_flexible) continue;

                offset = std.mem.alignForward(usize, offset, @alignOf(field.type.Child));

                if (std.mem.eql(u8, field.name, name)) {
                    const items: [*]T = @alignCast(@ptrCast(bytes[offset..]));
                    if (ReturnType == [*]T and LengthType == void) {
                        return items;
                    } else switch (field.type.LengthType) {
                        void => unreachable,
                        else => { // int
                            const value_len = intLen(@field(parent, field.name).len);
                            return items[0..value_len];
                        },
                    }
                }

                if (field.type.LengthType != void) {
                    const value_len: usize = intLen(@field(parent, field.name).len);
                    offset += value_len * @sizeOf(field.type.Child);
                }
            }
            unreachable;
        }
    };
}

pub fn Lengths(P: type) type {
    const fields = @typeInfo(P).@"struct".fields; // P must be a struct
    var buf: [fields.len]std.builtin.Type.StructField = undefined;
    var idx = 0;
    inline for (fields) |field| {
        const is_flexible = @typeInfo(field.type) == .@"struct" and
            @hasDecl(field.type, "IsFlexibleArray");

        if (!is_flexible) continue;
        const OriginalT = field.type.LengthType;
        const T = if (OriginalT == void) usize else OriginalT;
        buf[idx] = .{
            .name = field.name,
            .type = T,
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = @alignOf(T),
        };
        idx += 1;
    }

    return @Type(.{
        .@"struct" = .{
            .fields = buf[0..idx],
            .layout = .auto,
            .is_tuple = false,
            .decls = &.{},
        },
    });
}

pub fn SomeLengths(P: type) type {
    const fields = @typeInfo(P).@"struct".fields; // P must be a struct
    var buf: [fields.len]std.builtin.Type.StructField = undefined;
    var idx = 0;
    inline for (fields) |field| {
        const is_flexible = @typeInfo(field.type) == .@"struct" and
            @hasDecl(field.type, "IsFlexibleArray");

        if (!is_flexible) continue;
        const OriginalT = field.type.LengthType;
        const T = if (OriginalT == void) usize else OriginalT;
        buf[idx] = .{
            .name = field.name,
            .type = ?T,
            .default_value_ptr = @as(*const ?T, &null),
            .is_comptime = false,
            .alignment = @alignOf(?T),
        };
        idx += 1;
    }

    return @Type(.{
        .@"struct" = .{
            .fields = buf[0..idx],
            .layout = .auto,
            .is_tuple = false,
            .decls = &.{},
        },
    });
}

/// Creates an instance of a struct with FlexibleArray fields.
/// Sets all FlexibleArray len fields to the correct value.
pub fn create(
    /// A struct type that contains FlexibleArray Fields
    P: type,
    gpa: Allocator,
    /// A struct that contains a field for each FlexibleArray field in `P`.
    lengths: Lengths(P),
) error{OutOfMemory}!*P {
    const pinfo = @typeInfo(P).@"struct"; // P must be a struct
    var size: usize = @sizeOf(P);

    inline for (pinfo.fields) |field| {
        const is_flexible = @typeInfo(field.type) == .@"struct" and
            @hasDecl(field.type, "IsFlexibleArray");

        if (!is_flexible) continue;

        const field_len: usize = intLen(@field(lengths, field.name));
        size = std.mem.alignForward(usize, size, @alignOf(field.type.Child));
        size += field_len * @sizeOf(field.type.Child);
    }

    const data = try gpa.allocWithOptions(u8, size, .of(P), null);
    const p: *P = @ptrCast(data);

    inline for (pinfo.fields) |field| {
        const is_flexible = @typeInfo(field.type) == .@"struct" and
            @hasDecl(field.type, "IsFlexibleArray");

        if (!is_flexible) continue;
        if (field.type.LengthType != void) {
            @field(p, field.name).len = @field(lengths, field.name);
        }
    }

    return p;
}

pub fn destroy(
    gpa: Allocator,
    /// Pointer to an instance of a struct that contains FlexibleArray fields
    p: anytype,
    /// If the struct has a FlexibleArray field that has `length_type` set to
    /// void, you must provide its lenght. Pass `null` othrewise.
    void_len: ?usize,
) void {
    const P = @typeInfo(@TypeOf(p)).pointer.child; // p must be a pointer
    const pinfo = @typeInfo(P).@"struct"; // @TypeOf(p).pointer.child must be a struct

    if (std.debug.runtime_safety) {
        if (void_len != null) {
            // TODO add safety checks
        }
    }

    var size: usize = @sizeOf(P);
    inline for (pinfo.fields) |field| {
        const is_flexible = @typeInfo(field.type) == .@"struct" and
            @hasDecl(field.type, "IsFlexibleArray");

        if (!is_flexible) continue;

        size = std.mem.alignForward(usize, size, @alignOf(field.type.Child));

        switch (field.type.LengthType) {
            void => {
                size += void_len.? * @sizeOf(field.type.Child); // missing void_len!
            },
            else => {
                const field_len: usize = intLen(@field(p, field.name).len);
                size += field_len * @sizeOf(field.type.Child);
            },
        }

        if (std.meta.fieldInfo(field.type, .len).type != void) {} else {}
    }

    const bytes: [*]align(@alignOf(P)) u8 = @ptrCast(p);
    gpa.free(bytes[0..size]);
}

/// Resizes a flexible struct. If resizing requires moving the whole struct, a
/// pointer to the new location will be returned.
/// Resizing will also move data according to the new lengths provided.
///
/// For a given field:
///
/// - new_length > old_length:
///      all old data will be copied, new bytes will be set to undefined
///
/// - old_length > new_length:
///      only old data that fits the new length will be copied, discarding old
///      data starting from the end. e.g.: [1, 2, 3, 4] -> [1, 2, 3]
pub fn resize(
    P: type,
    gpa: Allocator,
    p: *P,
    void_len: ?usize,
    // Struct that contains all lenghts that must change. You can omit lenghts
    // that you intend to leave untouched.
    new_lengths: SomeLengths(P),
) !?*P {
    const original: P = p.*;
    errdefer {
        const linfo = @typeInfo(@TypeOf(new_lengths)).@"struct";
        inline for (linfo.fields) |field| {
            if (@TypeOf(@field(p, field.name).len) != void) {
                @field(p, field.name).len = @field(original, field.name).len;
            }
        }
    }

    var deltas: [flexibleFieldsCount(P)]struct {
        old_offset: usize,
        new_offset: usize,
        size: usize,
    } = undefined;
    var di: usize = deltas.len - 1;

    const pinfo = @typeInfo(P).@"struct"; // P must be a struct
    var old_size: usize = @sizeOf(P);
    var new_size: usize = @sizeOf(P);
    inline for (pinfo.fields) |field| {
        const is_flexible = @typeInfo(field.type) == .@"struct" and
            @hasDecl(field.type, "IsFlexibleArray");

        if (!is_flexible) continue;

        old_size = std.mem.alignForward(usize, old_size, @alignOf(field.type.Child));
        new_size = std.mem.alignForward(usize, new_size, @alignOf(field.type.Child));

        deltas[di].old_offset = old_size;
        deltas[di].new_offset = new_size;
        defer di -|= 1;

        switch (field.type.LengthType) {
            else => {
                const field_len: usize = intLen(@field(p, field.name).len);
                const field_size = field_len * @sizeOf(field.type.Child);
                old_size += field_size;

                if (@field(new_lengths, field.name)) |new_field_len| {
                    const usize_new_field_len: usize = intLen(new_field_len);
                    const new_field_size = usize_new_field_len * @sizeOf(field.type.Child);
                    new_size += new_field_size;
                    @field(p, field.name).len = new_field_len;
                    deltas[di].size = @min(field_size, new_field_size);
                } else {
                    new_size += field_len * @sizeOf(field.type.Child);
                    deltas[di].size = field_size;
                }
            },
            void => {
                const void_size = void_len.? * @sizeOf(field.type.Child); // missing void_len!

                old_size += void_size;
                if (@field(new_lengths, field.name)) |new_field_len| {
                    const usize_new_void_len: usize = new_field_len;
                    const new_void_size = usize_new_void_len * @sizeOf(field.type.Child);
                    new_size += new_void_size;
                    deltas[di].size = @min(void_size, new_void_size);
                } else {
                    new_size += void_size;
                    deltas[di].size = void_size;
                }
            },
        }
    }

    const bytes: [*]align(@alignOf(P)) u8 = @ptrCast(p);
    const new = gpa.remap(bytes[0..old_size], new_size) orelse {
        // remap failed, do everything manually

        const data = try gpa.allocWithOptions(u8, new_size, .of(P), null);
        const new: *P = @ptrCast(data);
        new.* = p.*;

        for (deltas[di..]) |d| @memcpy(
            data[d.new_offset..][0..d.size],
            bytes[d.old_offset..][0..d.size],
        );

        gpa.free(bytes[0..old_size]);
        return new;
    };

    for (deltas[di..]) |d| @memmove(
        new[d.new_offset..][0..d.size],
        new[d.old_offset..][0..d.size],
    );

    if (new.ptr == bytes) return null;
    return @ptrCast(new.ptr);
}

fn flexibleFieldsCount(P: type) comptime_int {
    var count = 0;
    const pinfo = @typeInfo(P).@"struct"; // P must be a struct
    inline for (pinfo.fields) |field| {
        const is_flexible = @typeInfo(field.type) == .@"struct" and
            @hasDecl(field.type, "IsFlexibleArray");

        if (!is_flexible) continue;
        count += 1;
    }

    return count;
}

fn intLen(l: anytype) switch (@TypeOf(l)) {
    bool => u1,
    void => unreachable,
    else => |t| t,
} {
    return switch (@TypeOf(l)) {
        bool => @intFromBool(l),
        void => unreachable,
        else => l,
    };
}

test {
    const RaxNode = packed struct {
        is_key: bool,
        is_null: bool,
        layout: enum(u1) { merge, split },
        bytes: Array(u8, .{
            .parent = @This(),
            .name = .bytes,
            .length_type = u29,
        }),
        ptrs: Array(*@This(), .{
            .parent = @This(),
            .name = .ptrs,
            .length_type = void,
        }),
    };

    _ = RaxNode;
}

test "alignment" {
    const Foo = struct {
        bar: u32,
        baz: Array(u8, .{
            .parent = @This(),
            .name = .baz,
        }),
        bax: Array(u64, .{
            .parent = @This(),
            .name = .bax,
        }),
    };

    const foo = try create(Foo, std.testing.allocator, .{
        .baz = 1,
        .bax = 1,
    });
    defer destroy(std.testing.allocator, foo, null);

    foo.bar = 0;
    foo.baz.init(&.{1});
    foo.bax.init(&.{2});

    try std.testing.expectEqual(0, foo.bar);
    try std.testing.expectEqualSlices(u8, &.{1}, foo.baz.slice());
    try std.testing.expectEqualSlices(u64, &.{2}, foo.bax.slice());
}

test {
    const Packet = struct {
        id: u32,
        hash: u32,
        name: Array(u8, .{
            .parent = @This(),
            .name = .name,
        }),
        label: Array(u8, .{
            .parent = @This(),
            .name = .label,
        }),
    };

    const name = "Andrew";
    const label = "zig <3";

    const packet = try create(Packet, std.testing.allocator, .{
        .name = name.len,
        .label = label.len,
    });
    defer destroy(std.testing.allocator, packet, null);

    packet.id = 1;
    packet.hash = 10;
    packet.name.init(name);
    packet.label.init(label);

    try std.testing.expectEqualSlices(u8, name, packet.name.slice());
    try std.testing.expectEqualSlices(u8, label, packet.label.slice());
}
