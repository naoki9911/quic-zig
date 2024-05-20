const std = @import("std");
const packet = @import("packet.zig");

pub fn main() !void {
    const buf = [_]u8{};
    _ = try packet.InitialPacket.decodeFromSlice(&buf);
}

test {
    std.testing.refAllDecls(@This());
}
