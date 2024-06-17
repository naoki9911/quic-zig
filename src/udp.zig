const std = @import("std");
const posix = std.posix;

pub const PacketReaderWriterMock = struct {
    const Self = @This();
    const MTU = 1500;

    written: [MTU]u8 = [_]u8{0} ** MTU,
    written_size: usize = 0,
    next_read: []const u8 = &[_]u8{},

    pub fn new() Self {
        return .{};
    }

    pub fn read(self: *Self, buf: []u8) !usize {
        const readSize = @min(buf.len, self.next_read.len);
        std.mem.copyForwards(u8, buf, self.next_read[0..readSize]);
        return readSize;
    }

    pub fn write(self: *Self, buf: []const u8) !usize {
        const writeSize = @min(buf.len, Self.MTU);
        std.mem.copyForwards(u8, &self.written, buf[0..writeSize]);
        self.written_size = writeSize;
        return writeSize;
    }

    pub fn deinit(self: Self) void {
        _ = self;
    }
};

pub const PacketReaderWriterUDP = struct {
    const Self = @This();

    sockfd: posix.socket_t,

    pub fn new(name: []const u8, port: u16) !Self {
        const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
        const addr = try std.net.Address.resolveIp(name, port);
        try posix.connect(sockfd, &addr.any, addr.getOsSockLen());
        return .{
            .sockfd = sockfd,
        };
    }

    pub fn read(self: *Self, buf: []u8) !usize {
        return try posix.recv(self.sockfd, buf, 0);
    }

    pub fn write(self: *Self, buf: []const u8) !usize {
        return try posix.send(self.sockfd, buf, 0);
    }

    pub fn deinit(self: Self) void {
        posix.close(self.sockfd);
    }
};
