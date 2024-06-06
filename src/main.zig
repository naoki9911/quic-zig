const std = @import("std");

pub fn main() !void {}

test {
    _ = @import("packet.zig");
    _ = @import("key.zig");
    _ = @import("client.zig");
    std.testing.refAllDecls(@This());
}
