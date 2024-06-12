const std = @import("std");
const posix = std.posix;
const client = @import("client.zig");
const allocator = std.heap.page_allocator;

pub fn main() !void {
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(sockfd);

    const addr = try std.net.Address.resolveIp("127.0.0.1", 4242);
    try posix.connect(sockfd, &addr.any, addr.getOsSockLen());

    var c = try client.Client.new(allocator, [_]u8{ 0x93, 0x70, 0xB2, 0xC9, 0xCA, 0xA4, 0x7F, 0xBA, 0xBA, 0xF4, 0x55, 0x9F, 0xED, 0xBA, 0x75, 0x3D, 0xE1, 0x71, 0xFA, 0x71, 0xF5, 0x0F, 0x1C, 0xE1, 0x5D, 0x43, 0xE9, 0x94, 0xEC, 0x74, 0xD7, 0x48 });
    try c.dst_con_id.appendSlice(&[_]u8{ 0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08 });
    try c.src_con_id.appendSlice(&[_]u8{ 0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08 });
    const pkt = try c.create_initial_packet();
    const send_bytes = try posix.send(sockfd, pkt, 0);
    std.debug.print("sent {} bytes\n", .{send_bytes});
}

test {
    _ = @import("packet.zig");
    _ = @import("key.zig");
    _ = @import("client.zig");
    std.testing.refAllDecls(@This());
}
