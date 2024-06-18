const std = @import("std");
const posix = std.posix;
const client = @import("client.zig");
const udp = @import("udp.zig");
const allocator = std.heap.page_allocator;

pub fn main() !void {
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(sockfd);

    const addr = try std.net.Address.resolveIp("127.0.0.1", 4242);
    try posix.connect(sockfd, &addr.any, addr.getOsSockLen());
    const udpRW = try udp.PacketReaderWriterUDP.new("127.0.0.1", 4242);

    var c = try client.ClientImpl(udp.PacketReaderWriterUDP).new(allocator, udpRW);
    try c.setX25519PrivateKey([_]u8{ 0x93, 0x70, 0xB2, 0xC9, 0xCA, 0xA4, 0x7F, 0xBA, 0xBA, 0xF4, 0x55, 0x9F, 0xED, 0xBA, 0x75, 0x3D, 0xE1, 0x71, 0xFA, 0x71, 0xF5, 0x0F, 0x1C, 0xE1, 0x5D, 0x43, 0xE9, 0x94, 0xEC, 0x74, 0xD7, 0x48 });
    c.setRandom([_]u8{ 0xEB, 0xF8, 0xFA, 0x56, 0xF1, 0x29, 0x39, 0xB9, 0x58, 0x4A, 0x38, 0x96, 0x47, 0x2E, 0xC4, 0x0B, 0xB8, 0x63, 0xCF, 0xD3, 0xE8, 0x68, 0x04, 0xFE, 0x3A, 0x47, 0xF0, 0x6A, 0x2B, 0x69, 0x48, 0x4C });
    try c.dst_con_id.appendSlice(&[_]u8{ 0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08 });
    try c.src_con_id.appendSlice(&[_]u8{ 0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08 });
    std.debug.print("{}\n", .{c.state});
    try c.procNext(); // send initial packet
    std.debug.print("{}\n", .{c.state});
    try c.procNext(); // recv initial packet
    std.debug.print("{}\n", .{c.state});
    try c.procNext(); // recv handshake packet
    std.debug.print("{}\n", .{c.state});
    try c.procNext(); // send ack packet
    std.debug.print("{}\n", .{c.state});
}

test {
    _ = @import("packet.zig");
    _ = @import("key.zig");
    _ = @import("client.zig");
    std.testing.refAllDecls(@This());
}
