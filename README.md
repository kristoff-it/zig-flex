# zig-flex
Like C's flexible array members but better :^)

## TODOs

- [ ] Packed struct support (see Zig [#20458](https://github.com/ziglang/zig/issues/20458))
- [ ] Support more than one void array and improve API accordingly

The library is otherwise in working condition, albeit not very well battle tested.

## Abstract
Imagine that you have a `Person` struct that has an age and a name.
This is how you would define it normally:

```zig
const Person = struct {
  age: usize,
  name: []const u8,
};
```

Note how this memory layout implies that a person and a name are expected to
be distinct allocations, which you can connect through the `Person.name` slice
pointer.

```
+--------+
| PERSON |
+--------+
| AGE    |    +-----------+
| NAME --|--->| LORIS CRO |
+--------+    +-----------+
```

In some circumstances it's instead desireable for closely-related data to always
be stored as a single allocation. This means allocating enough memory for a
instance of `Person` **and** also enough memory to store the full name.

Additionally, in such case you would not want to use a slice type because you
don't need to store any pointer in `Person` if the bytes for `name` are
immediately after the struct.

```
+------------+
|   PERSON   |
+------------+
| AGE        |
| NAME_LEN   |  
+------------+
| LORIS CRO  |
+------------+  
```

Without any abstraction, this is how you would write this in Zig:

```zig
const Person = struct {
  age: usize,
  name_len: usize,

  pub fn create(gpa: Allocator, age: usize, name_len: usize) *Person {
    const size: usize = @sizeOf(Person) + name_len;
    const bytes = gpa.allocWithOptions(u8, size, .of(Person), null);
    const p: *Person = @ptrCast(bytes);
    p.* = .{
      .age = age,
      .name_len = name_len,
    };

    return p;
  }

  pub fn destroy(p: *Person, gpa: Allocator) void {
    const bytes: [*]u8 = @ptrCast(p);
    gpa.free(bytes[0..(@sizeOf(Person) + p.name_len)]);
  }
 
  pub fn name(p: *Person) []u8 {
      const bytes: [*]u8 = @ptrCast(p);
      return bytes[@sizeOf(Person)..][0..p.name]; 
  }
}
```

The C programming language uses [flexible array member](https://en.wikipedia.org/wiki/Flexible_array_member) to give programmers a convenient way of accessing the
memory right after the end of a struct.

Real world scenarios where this technique is used:
- [antirez/rax](https://github.com/antirez/rax/)

Flex is a more type-safe implementation of flexible array members from C.

## Usage

```zig
const flex = @import("flex");

const Person = struct {
  age: u32,
  name: flex.Array(u8, .{
    .parent = Person,
    .field_name = .name,
  }),
  surname: flex.Array(u8, .{
    .parent = Person,
    .field_name = .surname,
  }),
}
  

pub fn main () !void {
  const gpa = std.heap.smp_allocator;
  const p = try flex.create(Person, gpa, .{
    .name = 5,
    .surname = 3,
  });

  p.age = 30;
  p.name.init("loris"); // asserts matching length
  p.surname.init("cro"); // asserts matching length
  
  std.debug.print("name = {s} surname = {s}\n",. {
     p.name.slice(),
     p.surname.slice(),
  });

  const p1 = try flex.resize(Person, gpa, p, null, .{
    .name = 8,
    .surname = 0,
  }) orelse p;

  p1.name.init("kristoff");
}
```
