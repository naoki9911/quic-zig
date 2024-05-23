const std = @import("std");

pub fn main() !void {}

test {
    _ = @import("packet.zig");
    _ = @import("key.zig");
    std.testing.refAllDecls(@This());
}
