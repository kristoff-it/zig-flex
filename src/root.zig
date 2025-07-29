const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// Example:
///         const Foo = packed struct {
///            field1: usize,
///            field2: []const u8,
///            bar: FlexibleArray(u8 .{
///               .parent = @This(),
///               .name = .bar,
///               .length_type = usize
///            }),
///            baz: FlexibleArray(usize, .{
///               .parent = @This(),
///               .name = .baz,
///               .length_type = void
///            }),
///         }
///
/// Resulting layout:
///         const Foo = struct {
///            field1: usize,
///            field2: []const u8,
///            bar: packed struct {
///               len: usize,
///               fn slice()
///            }
///            baz: packed struct {
///               len: void,
///               fn slice()
///            }
///         }
///
pub const Options = struct {
    /// The parent type, usually provided via `@This()`.
    parent: type,
    /// The enum literal matching the field name of this flexible array.
    name: @Type(.enum_literal),
    /// The integer type to be used to store length information for the
    /// flexible array. To make the flexible array not store length information
    /// in the struct, use `void`.
    ///
    /// Note that only the last field of a struct can have `lenght_type` set to
    /// `void`.
    ///
    /// When a flexible array has a `void` lenght type, the `slice` function
    /// will return a [*]T. When present, length information will be stored in
    /// a packed struct so FlexibleArray can be used with extern and packed
    /// structs.
    ///
    /// When length type is not `void`, you can access length information via
    /// `field.len`.
    length_type: type,
};

pub fn FlexibleArray(T: type, opts: Options) type {
    const P = opts.parent;

    return packed struct {
        len: opts.length_type,

        const IsFlexibleArray = {};
        const Child = T;
        comptime {
            const pinfo = @typeInfo(P).@"struct"; // opts.parent must be a struct
            const leninfo = @typeInfo(opts.length_type);
            if (opts.length_type == void) {
                if (pinfo.fields[pinfo.fields.len - 1].type != @This()) {
                    @compileError("Only the last field of a struct can nave a `null` length type");
                }
            } else if (leninfo != .int) {
                @compileError("Len must be an integer type or void");
            }
        }

        pub fn init(f: *@This(), values: []const T) void {
            const s = f.slice();
            @memcpy(s, values); // 'values' has different len than allocated memory
        }

        const ReturnType = if (opts.length_type == void) [*]T else []T;
        pub fn slice(f: *@This()) ReturnType {
            const pinfo = @typeInfo(P).@"struct"; // opts.parent must be a struct
            const name = @tagName(opts.name);

            const parent: *P = @alignCast(@fieldParentPtr(name, f));
            const bytes: [*]align(@alignOf(P)) u8 = @ptrCast(parent);
            var offset: usize = @sizeOf(P);

            inline for (pinfo.fields) |field| {
                const is_flexible = @typeInfo(field.type) == .@"struct" and
                    @hasDecl(field.type, "IsFlexibleArray");

                if (!is_flexible) continue;

                const value = @field(parent, field.name);
                if (std.mem.eql(u8, field.name, name)) {
                    const items: [*]T = @ptrCast(bytes[offset..]);
                    if (opts.length_type == void)
                        return items
                    else
                        return items[0..value.len];
                }

                offset += value.len * @sizeOf(field.type.Child);
            }
            unreachable;
        }
    };
}

/// Creates an instance of a struct with FlexibleArray fields.
/// Sets all FlexibleArray len fields to the correct value.
pub fn create(
    /// A struct type that contains FlexibleArray Fields
    P: type,
    gpa: Allocator,
    /// A struct that contains a field for each FlexibleArray field in `P`.
    lengths: anytype,
) error{OutOfMemory}!*P {
    const pinfo = @typeInfo(P).@"struct"; // P must be a struct
    var size: usize = @sizeOf(P);

    inline for (pinfo.fields) |field| {
        const is_flexible = @typeInfo(field.type) == .@"struct" and
            @hasDecl(field.type, "IsFlexibleArray");

        if (!is_flexible) continue;
        if (!@hasField(@TypeOf(lengths), field.name)) {
            @compileError("lengths is missing '" ++ field.name ++ "'");
        }
        size += @field(lengths, field.name);
    }

    const data = try gpa.allocWithOptions(u8, size, .of(P), null);
    const p: *P = @ptrCast(data);

    inline for (pinfo.fields) |field| {
        const is_flexible = @typeInfo(field.type) == .@"struct" and
            @hasDecl(field.type, "IsFlexibleArray");

        if (!is_flexible) continue;
        if (field.type.Child != void) {
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
        if (field.type.Child == void) {
            size += void_len.?; // missing void_len!
        } else {
            size += @field(p, field.name).len;
        }
    }

    const bytes: [*]align(@alignOf(P)) u8 = @ptrCast(p);
    gpa.free(bytes[0..size]);
}

test {
    const RaxNode = packed struct {
        is_key: bool,
        is_null: bool,
        layout: enum(u1) { merge, split },
        bytes: FlexibleArray(u8, .{
            .parent = @This(),
            .name = .bytes,
            .length_type = u29,
        }),
        ptrs: FlexibleArray(*@This(), .{
            .parent = @This(),
            .name = .ptrs,
            .length_type = void,
        }),
    };

    _ = RaxNode;
}

test {
    const Packet = struct {
        id: u32,
        hash: u32,
        name: FlexibleArray(u8, .{
            .parent = @This(),
            .name = .name,
            .length_type = usize,
        }),
        label: FlexibleArray(u8, .{
            .parent = @This(),
            .name = .label,
            .length_type = usize,
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
