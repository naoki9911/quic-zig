const std = @import("std");
const key = @import("key.zig");
const tls13 = @import("tls13");

/// RFC9000 Section 16. Variable-Length Integer Encoding
///
/// 2MSB	Length	Usable Bits	Range
/// 00	1	6	0-63
/// 01	2	14	0-16383
/// 10	4	30	0-1073741823
/// 11	8	62	0-4611686018427387903
pub const VLI = struct {
    value: u64,
    length: u8,

    const Self = @This();

    pub fn default() Self {
        return .{
            .value = 0,
            .length = 0,
        };
    }

    pub fn decodeFromSlice(buf: []const u8) Self {
        const type_bits: u2 = @intCast((buf[0] >> 6) & 0x3);
        switch (type_bits) {
            0 => {
                return .{
                    .value = @intCast(buf[0] & 0x3F),
                    .length = 1,
                };
            },
            1 => {
                var tmp_buf = [1]u8{0} ** 2;
                std.mem.copyForwards(u8, &tmp_buf, buf[0..2]);
                tmp_buf[0] = tmp_buf[0] & 0x3F;
                return .{
                    .value = @intCast(std.mem.readInt(u16, &tmp_buf, .big)),
                    .length = 2,
                };
            },
            2 => {
                var tmp_buf = [1]u8{0} ** 4;
                std.mem.copyForwards(u8, &tmp_buf, buf[0..4]);
                tmp_buf[0] = tmp_buf[0] & 0x3F;
                return .{
                    .value = @intCast(std.mem.readInt(u32, &tmp_buf, .big)),
                    .length = 4,
                };
            },
            3 => {
                var tmp_buf = [1]u8{0} ** 8;
                std.mem.copyForwards(u8, &tmp_buf, buf[0..8]);
                tmp_buf[0] = tmp_buf[0] & 0x3F;
                return .{
                    .value = @intCast(std.mem.readInt(u64, &tmp_buf, .big)),
                    .length = 8,
                };
            },
        }
    }

    pub fn encodeWithWriter(self: Self, writer: anytype) !usize {
        switch (self.length) {
            1 => {
                const type_byte: u8 = @intCast(self.value & 0x3F);
                try writer.writeByte(type_byte);
                return 1;
            },
            2 => {
                var buf = [_]u8{0} ** 2;
                std.mem.writeInt(u16, buf[0..2], @intCast(self.value), .big);
                buf[0] = (buf[0] & 0x3F) | (1 << 6);
                return try writer.write(&buf);
            },
            4 => {
                var buf = [_]u8{0} ** 4;
                std.mem.writeInt(u32, buf[0..4], @intCast(self.value), .big);
                buf[0] = (buf[0] & 0x3F) | (2 << 6);
                return try writer.write(&buf);
            },
            8 => {
                var buf = [_]u8{0} ** 8;
                std.mem.writeInt(u64, buf[0..8], @intCast(self.value), .big);
                buf[0] = (buf[0] & 0x3F) | (3 << 6);
                return try writer.write(&buf);
            },
            else => @panic("invalid length"),
        }
    }
};

pub const QuicPacketError = error{
    InvalidHeaderForm,
    InvalidFixedBit,
    InvalidPacketType,
    InvalidDestinationConnectionIDLength,
    InvalidSourceConnectionIDLength,
    InvalidTokenLength,
    NotInitialPacket,
};

pub const PacketType = enum(u16) {
    short_1RTT = 0x000,
    long_initial = 0x100,
    //long_zeroRTT = 0x101,
    long_handshake = 0x102,
    //long_retry = 0x103,
};

pub const Packet = union(PacketType) {
    short_1RTT: ShortHeaderPacket,
    long_initial: InitialPacket,
    long_handshake: HandshakePacket,

    const Self = @This();
    pub fn decodeFromSlice(buf: []const u8, sent_by_server: bool, dst_con_id_len: usize) QuicPacketError!Self {
        const is_long = (buf[0] >> 7) & 0x1 == 1;
        if (is_long) {
            const pkt_type: LongHeaderType = @enumFromInt((buf[0] >> 4) & 0x3);
            switch (pkt_type) {
                .Initial => return .{ .long_initial = try InitialPacket.decodeFromSlice(buf, sent_by_server) },
                .ZeroRTT => @panic("ZeroRTT is not implemented"),
                .Handshake => return .{ .long_handshake = try HandshakePacket.decodeFromSlice(buf) },
                .Retry => @panic("Retry is not implemented"),
            }
        } else {
            return .{ .short_1RTT = try ShortHeaderPacket.decodeFromSlice(buf, dst_con_id_len) };
        }
    }
};

/// RFC9000 Section 17.2. Long Header Packets Table 5
/// Type	Name	Section
/// 0x00	Initial	Section 17.2.2
/// 0x01	0-RTT	Section 17.2.3
/// 0x02	Handshake	Section 17.2.4
/// 0x03	Retry	Section 17.2.5
pub const LongHeaderType = enum(u4) {
    Initial = 0x00,
    ZeroRTT = 0x01,
    Handshake = 0x02,
    Retry = 0x03,
};

/// RFC9000 Section 17.2. Long Header Packets Figure 13
///
/// Long Header Packet {
///   Header Form (1) = 1,
///   Fixed Bit (1) = 1,
///   Long Packet Type (2),
///   Type-Specific Bits (4),
///   Version (32),
///   Destination Connection ID Length (8),
///   Destination Connection ID (0..160),
///   Source Connection ID Length (8),
///   Source Connection ID (0..160),
///   Type-Specific Payload (..),
/// }
/// Figure 13: Long Header Packet Format
pub const LongHeaderPacket = struct {
    const Self = @This();

    packet_type: LongHeaderType,
    type_specific_bits: u4,
    version: u32,

    /// Not owning
    destination_connection_id: []const u8,

    /// Not owning
    source_connection_id: []const u8,

    pub fn decodeFromSlice(buf: []const u8) QuicPacketError!Self {
        var idx: usize = 0;

        // validate Header From
        if ((buf[idx] >> 7) & 0x1 != 1) {
            return QuicPacketError.InvalidHeaderForm;
        }

        // ensure Fixed Bit is 1.
        if ((buf[idx] >> 6) & 0x1 != 1) {
            return QuicPacketError.InvalidFixedBit;
        }

        const pkt_type: LongHeaderType = @enumFromInt((buf[0] >> 4) & 0x3);
        const specific_bits: u4 = @intCast(buf[0] & 0xF);
        idx += 1;

        const version = std.mem.readInt(u32, buf[idx..][0..4], .big);
        idx += 4;

        const dst_con_id_len = buf[idx];
        if (dst_con_id_len > 20) {
            return QuicPacketError.InvalidDestinationConnectionIDLength;
        }
        idx += 1;

        const dst_con_id = buf[idx .. idx + dst_con_id_len];
        idx += dst_con_id_len;

        const src_con_id_len = buf[idx];
        if (src_con_id_len > 20) {
            return QuicPacketError.InvalidSourceConnectionIDLength;
        }
        idx += 1;

        const src_con_id = buf[idx .. idx + src_con_id_len];
        idx += src_con_id_len;

        return Self{
            .packet_type = pkt_type,
            .type_specific_bits = specific_bits,
            .version = version,
            .destination_connection_id = dst_con_id,
            .source_connection_id = src_con_id,
        };
    }

    pub fn encodeToSlice(self: Self, buf: []u8, tsb: u4) !usize {
        var idx: usize = 0;
        buf[0] = 0x3 << 6;
        buf[0] = buf[0] | (@as(u8, @intFromEnum(self.packet_type)) << 4);
        buf[0] = buf[0] | tsb;
        idx += 1;

        std.mem.writeInt(u32, buf[idx .. idx + 4][0..4], self.version, .big);
        idx += 4;

        buf[idx] = @intCast(self.destination_connection_id.len);
        idx += 1;
        std.mem.copyForwards(u8, buf[idx..], self.destination_connection_id);
        idx += self.destination_connection_id.len;

        buf[idx] = @intCast(self.source_connection_id.len);
        idx += 1;
        std.mem.copyForwards(u8, buf[idx..], self.source_connection_id);
        idx += self.source_connection_id.len;

        return idx;
    }

    pub fn length(self: Self) usize {
        var len: usize = 1;
        len += 4;
        len += 1 + self.destination_connection_id.len;
        len += 1 + self.source_connection_id.len;
        return len;
    }
};

/// RFC9000 Section 17.2. Long Header Packets Figure 15
///
/// Initial Packet {
///   Header Form (1) = 1,
///   Fixed Bit (1) = 1,
///   Long Packet Type (2) = 0,
///   Reserved Bits (2),
///   Packet Number Length (2),
///   Version (32),
///   Destination Connection ID Length (8),
///   Destination Connection ID (0..160),
///   Source Connection ID Length (8),
///   Source Connection ID (0..160),
///   Token Length (i),
///   Token (..),
///   Length (i),
///   Packet Number (8..32),
///   Packet Payload (8..),
/// }
pub const InitialPacket = struct {
    const Self = @This();

    lhp: LongHeaderPacket,

    token_length: VLI,
    // not owning
    token: []const u8,

    // not owning
    sample: *const [16]u8,

    protected_offset: usize,
    length: VLI,

    pub fn decodeFromSlice(buf: []const u8, sent_by_server: bool) !Self {
        // decode as LHP
        const lhp = try LongHeaderPacket.decodeFromSlice(buf);

        if (lhp.packet_type != .Initial) {
            return QuicPacketError.NotInitialPacket;
        }

        const payload_slice = buf[lhp.length()..];

        var payload_idx: usize = 0;
        const token_length_vli = VLI.decodeFromSlice(payload_slice);
        payload_idx += @intCast(token_length_vli.length);

        if (sent_by_server and token_length_vli.value != 0) {
            return QuicPacketError.InvalidTokenLength;
        }

        const token = payload_slice[payload_idx .. payload_idx + @as(usize, token_length_vli.value)];
        payload_idx += @intCast(token_length_vli.value);

        const length_vli = VLI.decodeFromSlice(payload_slice[payload_idx..]);
        payload_idx += @intCast(length_vli.length);

        const sample = payload_slice[payload_idx + 4 .. payload_idx + 4 + 16][0..16];

        return Self{
            .lhp = lhp,
            .token = token,
            .token_length = token_length_vli,
            .length = length_vli,
            .sample = sample,
            .protected_offset = lhp.length() + payload_idx,
        };
    }

    pub fn encodeToSlice(self: Self, buf: []u8, pn_len: u4) !usize {
        var idx = try self.lhp.encodeToSlice(buf, pn_len - 1);
        var stream = std.io.fixedBufferStream(buf[idx..]);
        idx += try self.token_length.encodeWithWriter(stream.writer());
        std.mem.copyForwards(u8, buf[idx..], self.token);
        idx += self.token.len;
        stream = std.io.fixedBufferStream(buf[idx..]);
        idx += try self.length.encodeWithWriter(stream.writer());

        return idx;
    }

    /// return header length withtou packet number
    pub fn header_length(self: Self) usize {
        var len: usize = self.lhp.length();
        len += self.token_length.length;
        len += self.token.len;
        len += self.length.length;

        return len;
    }
};

/// RFC9000 Section 17.2.4. Handshake Packet
///
/// Initial Packet {
///   Header Form (1) = 1,
///   Fixed Bit (1) = 1,
///   Long Packet Type (2) = 0,
///   Reserved Bits (2),
///   Packet Number Length (2),
///   Version (32),
///   Destination Connection ID Length (8),
///   Destination Connection ID (0..160),
///   Source Connection ID Length (8),
///   Source Connection ID (0..160),
///   Length (i),
///   Packet Number (8..32),
///   Packet Payload (8..),
/// }
pub const HandshakePacket = struct {
    const Self = @This();

    lhp: LongHeaderPacket,

    // not owning
    sample: *const [16]u8,

    protected_offset: usize,
    length: VLI,

    pub fn decodeFromSlice(buf: []const u8) !Self {
        // decode as LHP
        const lhp = try LongHeaderPacket.decodeFromSlice(buf);

        if (lhp.packet_type != .Handshake) {
            return QuicPacketError.NotInitialPacket;
        }

        const payload_slice = buf[lhp.length()..];

        var payload_idx: usize = 0;
        const length_vli = VLI.decodeFromSlice(payload_slice[payload_idx..]);
        payload_idx += @intCast(length_vli.length);

        const sample = payload_slice[payload_idx + 4 .. payload_idx + 4 + 16][0..16];

        return Self{
            .lhp = lhp,
            .length = length_vli,
            .sample = sample,
            .protected_offset = lhp.length() + payload_idx,
        };
    }

    pub fn encodeToSlice(self: Self, buf: []u8, pn_len: u4) !usize {
        var idx = try self.lhp.encodeToSlice(buf, pn_len - 1);
        var stream = std.io.fixedBufferStream(buf[idx..]);
        idx += try self.length.encodeWithWriter(stream.writer());

        return idx;
    }

    /// return header length withtou packet number
    pub fn header_length(self: Self) usize {
        var len: usize = self.lhp.length();
        len += self.length.length;

        return len;
    }
};

/// RFC9000 17.3.1. 1-RTT Packet
///
/// 1-RTT Packet {
///   Header Form (1) = 0,
///   Fixed Bit (1) = 1,
///   Spin Bit (1),
///   Reserved Bits (2),
///   Key Phase (1),
///   Packet Number Length (2),
///   Destination Connection ID (0..160),
///   Packet Number (8..32),
///   Packet Payload (8..),
/// }
pub const ShortHeaderPacket = struct {
    const Self = @This();

    spin_bit: u1,
    key_phase: u1,
    pn_len: u8,

    /// Not owning
    destination_connection_id: []const u8,

    // not owning
    sample: *const [16]u8,

    protected_offset: usize,

    pub fn decodeFromSlice(buf: []const u8, dst_con_id_len: usize) QuicPacketError!Self {
        var idx: usize = 0;

        // validate Header From
        if ((buf[idx] >> 7) & 0x1 != 0) {
            return QuicPacketError.InvalidHeaderForm;
        }

        // ensure Fixed Bit is 1.
        if ((buf[idx] >> 6) & 0x1 != 1) {
            return QuicPacketError.InvalidFixedBit;
        }

        const spin_bit: u1 = @intCast(buf[idx] >> 5 & 0x1);
        const key_phase: u1 = @intCast(buf[idx] >> 2 & 0x1);
        const pn_len = (buf[idx] & 0x3) + 1;
        idx += 1;

        if (dst_con_id_len > 20) {
            return QuicPacketError.InvalidDestinationConnectionIDLength;
        }
        const dst_con_id = buf[idx .. idx + dst_con_id_len];
        idx += dst_con_id_len;

        const sample = buf[idx + 4 .. idx + 4 + 16][0..16];
        return Self{
            .spin_bit = spin_bit,
            .key_phase = key_phase,
            .pn_len = pn_len,
            .destination_connection_id = dst_con_id,
            .sample = sample,
            .protected_offset = 1 + dst_con_id_len,
        };
    }

    pub fn encodeToSlice(self: Self, buf: []u8) usize {
        var idx: usize = 0;
        buf[idx] = 0x1 << 6;
        buf[idx] = buf[idx] | (@as(u8, self.spin_bit) << 5);
        buf[idx] = buf[idx] | (@as(u8, self.key_phase) << 2);
        buf[idx] = buf[idx] | ((self.pn_len - 1) & 0x3);
        idx += 1;

        std.mem.copyForwards(u8, buf[idx..], self.destination_connection_id);
        idx += self.destination_connection_id.len;

        return idx;
    }

    pub fn length(self: Self) usize {
        var len: usize = 1;
        len += self.destination_connection_id.len;
        return len;
    }
};

/// RFC9000 12.4. Frames and Frame Types
///
/// Type Value	Frame Type Name	Definition	Pkts	Spec
/// 0x00	PADDING	Section 19.1	IH01	NP
/// 0x01	PING	Section 19.2	IH01
/// 0x02-0x03	ACK	Section 19.3	IH_1	NC
/// 0x04	RESET_STREAM	Section 19.4	__01
/// 0x05	STOP_SENDING	Section 19.5	__01
/// 0x06	CRYPTO	Section 19.6	IH_1
/// 0x07	NEW_TOKEN	Section 19.7	___1
/// 0x08-0x0f	STREAM	Section 19.8	__01	F
/// 0x10	MAX_DATA	Section 19.9	__01
/// 0x11	MAX_STREAM_DATA	Section 19.10	__01
/// 0x12-0x13	MAX_STREAMS	Section 19.11	__01
/// 0x14	DATA_BLOCKED	Section 19.12	__01
/// 0x15	STREAM_DATA_BLOCKED	Section 19.13	__01
/// 0x16-0x17	STREAMS_BLOCKED	Section 19.14	__01
/// 0x18	NEW_CONNECTION_ID	Section 19.15	__01	P
/// 0x19	RETIRE_CONNECTION_ID	Section 19.16	__01
/// 0x1a	PATH_CHALLENGE	Section 19.17	__01	P
/// 0x1b	PATH_RESPONSE	Section 19.18	___1	P
/// 0x1c-0x1d	CONNECTION_CLOSE	Section 19.19	ih01	N
/// 0x1e	HANDSHAKE_DONE	Section 19.20	___1
pub const FrameType = enum(u8) {
    padding = 0x00,
    //Ping = 0x01,
    ack = 0x02,
    ackECN = 0x03,
    //ResetStream = 0x4,
    //StopSending = 0x5,
    crypto = 0x06,
    //NewToken = 0x07,
    //Stream1 = 0x8,
    //Stream2 = 0x9,
    //Stream3 = 0xa,
    //Stream4 = 0xb,
    //Stream5 = 0xc,
    //Stream6 = 0xd,
    //Stream7 = 0xe,
    //Stream8 = 0xf,
    //MaxData = 0x10,
    //MaxStreamData = 0x11,
    //MAxStreams1 = 0x12,
    //MAxStreams2 = 0x13,
    //DataBlocked = 0x14,
    //StreamDataBlocked = 0x15,
    //StreamsBlocked1 = 0x16,
    //StreamsBlocked2 = 0x17,
    newConnectionID = 0x18,
    //RetireConnectionID = 0x19,
    //PathChallenge = 0x1a,
    //PathResponse = 0x1b,
    //ConnectionClose1 = 0x1c,
    //ConnectionClose2 = 0x1d,
    //HandshakeDone = 0x1e,
};

pub const TransportErrorCode = error{
    FrameEncodingError,
};

pub const Frame = union(FrameType) {
    const Self = @This();
    padding: PaddingFrame,
    ack: AckFrame,
    ackECN: AckFrame,
    crypto: CryptoFrame,
    newConnectionID: NewConnectionIDFrame,

    pub fn decodeFromSlice(buf: []const u8) Self {
        const type_vli = VLI.decodeFromSlice(buf);
        const t: u8 = @intCast(type_vli.value & 0xFF);
        const frame_type: FrameType = @enumFromInt(t);

        switch (frame_type) {
            .padding => return Self{
                .padding = PaddingFrame.decodeFromSlice(buf),
            },
            .ack => return Self{
                .ack = AckFrame.decodeFromSlice(buf),
            },
            .ackECN => return Self{
                .ackECN = AckFrame.decodeFromSlice(buf),
            },
            .crypto => return Self{
                .crypto = CryptoFrame.decodeFromSlice(buf),
            },
            .newConnectionID => return Self{
                .newConnectionID = NewConnectionIDFrame.decodeFromSlice(buf),
            },
        }
    }

    pub fn encodeToSlice(self: Self, buf: []u8) !usize {
        switch (self) {
            inline else => |case| return try case.encodeToSlice(buf),
        }
    }

    pub fn length(self: Self) usize {
        switch (self) {
            inline else => |case| return case.length(),
        }
    }
};

/// RFC9000 19.1. PADDING Frames
///
/// PADDING Frame {
///   Type (i) = 0x00,
/// }
pub const PaddingFrame = struct {
    const Self = @This();

    len: usize,
    pub fn init(len: usize) Self {
        return .{
            .len = len,
        };
    }

    pub fn decodeFromSlice(buf: []const u8) Self {
        var len: usize = 0;
        for (buf) |b| {
            if (b == 0) {
                len += 1;
            } else {
                break;
            }
        }

        return Self{ .len = len };
    }

    pub fn encodeToSlice(self: Self, buf: []u8) !usize {
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            buf[i] = 0;
        }
        return self.len;
    }

    pub fn length(self: Self) usize {
        return self.len;
    }
};

/// RFC9000 19.3. ACK Frames
///
/// ACK Frame {
///   Type (i) = 0x02..0x03,
///   Largest Acknowledged (i),
///   ACK Delay (i),
///   ACK Range Count (i),
///   First ACK Range (i),
///   ACK Range (..) ...,
///   [ECN Counts (..)],
/// }
/// Figure 25: ACK Frame Format
pub const AckFrame = struct {
    const Self = @This();

    /// RFC9000 19.3.1. ACK Ranges
    /// ACK Range {
    ///   Gap (i),
    ///   ACK Range Length (i),
    /// }
    /// Figure 26: ACK Ranges
    pub const AckRange = struct {
        const Self = @This();

        gap: VLI,
        ack_range_length: VLI,

        pub fn decodeFromSlice(buf: []const u8) AckRange {
            var offset: usize = 0;
            const gap = VLI.decodeFromSlice(buf);
            offset += gap.length;
            const ack_range_length = VLI.decodeFromSlice(buf[offset..]);

            return AckRange{ .gap = gap, .ack_range_length = ack_range_length };
        }

        pub fn length(self: AckRange) usize {
            return @as(usize, self.gap.length) + @as(usize, self.gap.length);
        }
    };

    /// RFC9000 19.3.2. ECN Counts
    /// ECN Counts {
    ///   ECT0 Count (i),
    ///   ECT1 Count (i),
    ///   ECN-CE Count (i),
    /// }
    /// Figure 27: ECN Count Format
    pub const ECNCounts = struct {
        ECT0_count: VLI,
        ECT1_count: VLI,
        ECN_CE_count: VLI,

        pub fn default() ECNCounts {
            return .{
                .ECT0_count = VLI.default(),
                .ECT1_count = VLI.default(),
                .ECN_CE_count = VLI.default(),
            };
        }

        pub fn decodeFromSlice(buf: []const u8) ECNCounts {
            var offset: usize = 0;
            const ECT0 = VLI.decodeFromSlice(buf);
            offset += ECT0.length;
            const ECT1 = VLI.decodeFromSlice(buf[offset..]);
            offset += ECT1.length;
            const ECNCE = VLI.decodeFromSlice(buf[offset..]);

            return ECNCounts{
                .ECT0_count = ECT0,
                .ECT1_count = ECT1,
                .ECN_CE_count = ECNCE,
            };
        }

        pub fn encodeToSlice(self: ECNCounts, buf: []u8) !usize {
            var stream = std.io.fixedBufferStream(buf);
            var idx = try self.ECT0_count.encodeWithWriter(stream.writer());
            idx += try self.ECT1_count.encodeWithWriter(stream.writer());
            idx += try self.ECN_CE_count.encodeWithWriter(stream.writer());

            return idx;
        }

        pub fn length(self: ECNCounts) usize {
            return @as(usize, self.ECT0_count.length) + @as(usize, self.ECT1_count.length) + @as(usize, self.ECN_CE_count.length);
        }
    };

    frame_type: FrameType,
    frame_type_vli: VLI,
    largest_acked: VLI,
    ack_delay: VLI,
    ack_range_count: VLI,
    first_ack_range: VLI,
    ack_range_data: []const u8, // not owning
    ECN_counts: ECNCounts,

    frame_length: usize,

    pub fn decodeFromSlice(buf: []const u8) Self {
        var frame_length: usize = 0;

        const ft_vli = VLI.decodeFromSlice(buf);
        frame_length += ft_vli.length;
        const ft: FrameType = @enumFromInt(ft_vli.value);

        const largest_acked = VLI.decodeFromSlice(buf[frame_length..]);
        frame_length += largest_acked.length;

        const ack_delay = VLI.decodeFromSlice(buf[frame_length..]);
        frame_length += ack_delay.length;

        const ack_range_count = VLI.decodeFromSlice(buf[frame_length..]);
        frame_length += ack_range_count.length;

        const first_ack_range = VLI.decodeFromSlice(buf[frame_length..]);
        frame_length += first_ack_range.length;

        const ar_start_idx = frame_length;
        var i: usize = 0;
        while (i < ack_range_count.value) : (i += 1) {
            const ar = AckRange.decodeFromSlice(buf[frame_length..]);
            frame_length += ar.length();
        }
        const ar_end_idx = frame_length;

        var ECN_cnt = ECNCounts.default();
        if (ft == .ackECN) {
            ECN_cnt = ECNCounts.decodeFromSlice(buf[frame_length..]);
            frame_length += ECN_cnt.length();
        }

        return Self{
            .frame_type = ft,
            .frame_type_vli = ft_vli,
            .largest_acked = largest_acked,
            .ack_delay = ack_delay,
            .ack_range_count = ack_range_count,
            .first_ack_range = first_ack_range,
            .ack_range_data = buf[ar_start_idx..ar_end_idx],
            .ECN_counts = ECN_cnt,
            .frame_length = frame_length,
        };
    }

    pub fn encodeToSlice(self: Self, buf: []u8) !usize {
        var idx: usize = 0;
        var stream = std.io.fixedBufferStream(buf);
        idx += try self.frame_type_vli.encodeWithWriter(stream.writer());
        idx += try self.largest_acked.encodeWithWriter(stream.writer());
        idx += try self.ack_delay.encodeWithWriter(stream.writer());
        idx += try self.ack_range_count.encodeWithWriter(stream.writer());
        idx += try self.first_ack_range.encodeWithWriter(stream.writer());
        std.mem.copyForwards(u8, buf[idx..], self.ack_range_data);
        idx += self.ack_range_data.len;

        if (self.frame_type == .ackECN) {
            idx += try self.ECN_counts.encodeToSlice(buf[idx..]);
        }

        return idx;
    }

    /// This function can be called only after decodeFromSlice
    pub fn length(self: Self) usize {
        return self.frame_length;
    }
};

/// RFC9000 19.6. CRYPTO Frames
///
/// CRYPTO Frame {
///   Type (i) = 0x06,
///   Offset (i),
///   Length (i),
///   Crypto Data (..),
/// }
/// Figure 30: CRYPTO Frame Format
pub const CryptoFrame = struct {
    const Self = @This();

    frame_type: VLI,
    offset: VLI,
    len: VLI,

    data: []const u8,
    pub fn decodeFromSlice(buf: []const u8) Self {
        var frame_length: usize = 0;

        const frame_type = VLI.decodeFromSlice(buf);
        frame_length += frame_type.length;

        const offset_vli = VLI.decodeFromSlice(buf[frame_length..]);
        frame_length += offset_vli.length;

        const length_vli = VLI.decodeFromSlice(buf[frame_length..]);
        frame_length += length_vli.length;

        const data_offset = frame_length + offset_vli.value;
        frame_length += length_vli.value;

        return Self{
            .frame_type = frame_type,
            .offset = offset_vli,
            .len = length_vli,
            .data = buf[data_offset..frame_length],
        };
    }

    pub fn encodeToSlice(self: Self, buf: []u8) !usize {
        const frame_length = try self.encodeToSliceWithoutData(buf);
        std.mem.copyForwards(u8, buf[frame_length .. frame_length + self.data.len], self.data);
        return frame_length + self.data.len;
    }

    pub fn encodeToSliceWithoutData(self: Self, buf: []u8) !usize {
        var frame_length: usize = 0;
        var stream = std.io.fixedBufferStream(buf);
        frame_length += try self.frame_type.encodeWithWriter(stream.writer());
        frame_length += try self.offset.encodeWithWriter(stream.writer());
        frame_length += try self.len.encodeWithWriter(stream.writer());
        return frame_length;
    }

    pub fn length(self: Self) usize {
        return self.header_length() + self.data.len;
    }

    pub fn header_length(self: Self) usize {
        var frame_length = self.frame_type.length;
        frame_length += self.offset.length;
        frame_length += self.len.length;

        return frame_length;
    }
};

/// RFC9000 19.15. NEW_CONNECTION_ID Frames
/// NEW_CONNECTION_ID Frame {
///   Type (i) = 0x18,
///   Sequence Number (i),
///   Retire Prior To (i),
///   Length (8),
///   Connection ID (8..160),
///   Stateless Reset Token (128),
/// }
/// Figure 39: NEW_CONNECTION_ID Frame Format
pub const NewConnectionIDFrame = struct {
    const Self = @This();

    frame_type: VLI,
    seq_number: VLI,
    retire_prior_to: VLI,

    // not owing
    con_id: []const u8,

    stateless_reset_token: []const u8,

    pub fn decodeFromSlice(buf: []const u8) Self {
        var frame_length: usize = 0;

        const frame_type = VLI.decodeFromSlice(buf);
        frame_length += frame_type.length;

        const seq_num = VLI.decodeFromSlice(buf[frame_length..]);
        frame_length += seq_num.length;

        const rpt = VLI.decodeFromSlice(buf[frame_length..]);
        frame_length += rpt.length;

        const con_id_len = buf[frame_length];
        frame_length += 1;

        const con_id = buf[frame_length .. frame_length + con_id_len];
        frame_length += con_id_len;

        const srt = buf[frame_length .. frame_length + 16];

        return Self{
            .frame_type = frame_type,
            .seq_number = seq_num,
            .retire_prior_to = rpt,
            .con_id = con_id,
            .stateless_reset_token = srt,
        };
    }

    pub fn encodeToSlice(self: Self, buf: []u8) !usize {
        _ = self;
        _ = buf;
        @panic("unimplemented");
    }

    pub fn length(self: Self) usize {
        var len: usize = self.frame_type.length;
        len += self.seq_number.length;
        len += self.retire_prior_to.length;
        len += 1 + self.con_id.len;
        len += self.stateless_reset_token.len;

        return len;
    }
};

/// RFC9000 19.8. STREAM Frames
/// STREAM Frame {
///   Type (i) = 0x08..0x0f,
///   Stream ID (i),
///   [Offset (i)],
///   [Length (i)],
///   Stream Data (..),
/// }
pub const StreamFrame = struct {
    const Self = @This();

    frame_type: VLI,
    stream_id: VLI,

    // not owing
    data: []const u8,

    pub fn decodeFromSlice(buf: []const u8) Self {
        _ = buf;
        @panic("unimplemented");
    }

    pub fn encodeToSlice(self: Self, buf: []u8) !usize {
        var stream = std.io.fixedBufferStream(buf);
        var idx: usize = try self.frame_type.encodeWithWriter(stream.writer());
        idx += try self.stream_id.encodeWithWriter(stream.writer());
        idx += try stream.writer().write(self.data);

        return idx;
    }

    pub fn length(self: Self) usize {
        var len: usize = self.frame_type.length;
        len += self.stream_id.length;
        len += self.data.len;

        return len;
    }
};

/// RETIRE_CONNECTION_ID Frame {
///   Type (i) = 0x19,
///   Sequence Number (i),
/// }
pub const RetireConnectionIDFrame = struct {
    const Self = @This();

    frame_type: VLI,
    seq_num: VLI,

    pub fn decodeFromSlice(buf: []const u8) Self {
        _ = buf;
        @panic("unimplemented");
    }

    pub fn encodeToSlice(self: Self, buf: []u8) !usize {
        var idx: usize = self.frame_type.encodeToSlice(buf);
        idx += self.seq_num.encodeToSlice(buf[idx..]);

        return idx;
    }

    pub fn length(self: Self) usize {
        var len: usize = self.frame_type.length;
        len += self.seq_num.length;

        return len;
    }
};

const Aes128 = std.crypto.core.aes.Aes128;
fn getHeaderProtectonMask(sample: *const [Aes128.block.block_length]u8, hp: [Aes128.key_bits / 8]u8) [5]u8 {
    const enc = Aes128.initEnc(hp);
    var headerProtectionKey = [_]u8{0} ** 16;
    enc.encrypt(&headerProtectionKey, sample);
    return headerProtectionKey[0..5].*;
}

pub fn unlockHeaderProtection(
    buf: []u8,
    protected_offset: usize,
    pn_len: *usize,
    pn: *u32,
    sample: *const [Aes128.block.block_length]u8,
    hp: [Aes128.key_bits / 8]u8,
) void {
    const mask = getHeaderProtectonMask(sample, hp);
    if ((buf[0] & 0x80) == 0x80) {
        buf[0] ^= mask[0] & 0xf;
    } else {
        buf[0] ^= mask[0] & 0x1f;
    }
    pn_len.* = (buf[0] & 0x03) + 1;

    for (0..pn_len.*, mask[1 .. 1 + pn_len.*]) |i, m| {
        buf[protected_offset + i] ^= m;
        pn.* = (pn.* << 8) | buf[protected_offset + i];
    }
}

pub fn lockHeaderProtection(
    buf: []u8,
    protected_offset: usize,
    pn_len: usize,
    sample: *const [Aes128.block.block_length]u8,
    hp: [Aes128.key_bits / 8]u8,
) void {
    const mask = getHeaderProtectonMask(sample, hp);
    if (buf[0] & 0x80 == 0x80) {
        buf[0] ^= mask[0] & 0xf;
    } else {
        buf[0] ^= mask[0] & 0x1f;
    }

    for (0..pn_len, mask[1 .. 1 + pn_len]) |i, m| {
        buf[protected_offset + i] ^= m;
    }
}

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
pub fn getNonce(pkt_number: u32, iv: [Aes128Gcm.nonce_length]u8) [Aes128Gcm.nonce_length]u8 {
    var nonce = [_]u8{0} ** Aes128Gcm.nonce_length;
    std.mem.writeInt(u32, nonce[nonce.len - 4 ..], pkt_number, .big);
    for (&nonce, iv) |*n, i| {
        n.* = n.* ^ i;
    }

    return nonce;
}

const expect = std.testing.expect;
const aead = @import("aead.zig");

test "parse Client Initial Packet" {
    // RFC9001 A.2. Client Initial
    // zig fmt: off
    const recv_msg = [_]u8{
    0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xC8, 0xF0, 
    0x3E, 0x51, 0x57, 0x08, 0x00, 0x00, 0x44, 0x9E, 0x7B, 0x9A, 
    0xEC, 0x34, 0xD1, 0xB1, 0xC9, 0x8D, 0xD7, 0x68, 0x9F, 0xB8, 
    0xEC, 0x11, 0xD2, 0x42, 0xB1, 0x23, 0xDC, 0x9B, 0xD8, 0xBA, 
    0xB9, 0x36, 0xB4, 0x7D, 0x92, 0xEC, 0x35, 0x6C, 0x0B, 0xAB, 
    0x7D, 0xF5, 0x97, 0x6D, 0x27, 0xCD, 0x44, 0x9F, 0x63, 0x30, 
    0x00, 0x99, 0xF3, 0x99, 0x1C, 0x26, 0x0E, 0xC4, 0xC6, 0x0D, 
    0x17, 0xB3, 0x1F, 0x84, 0x29, 0x15, 0x7B, 0xB3, 0x5A, 0x12, 
    0x82, 0xA6, 0x43, 0xA8, 0xD2, 0x26, 0x2C, 0xAD, 0x67, 0x50, 
    0x0C, 0xAD, 0xB8, 0xE7, 0x37, 0x8C, 0x8E, 0xB7, 0x53, 0x9E, 
    0xC4, 0xD4, 0x90, 0x5F, 0xED, 0x1B, 0xEE, 0x1F, 0xC8, 0xAA, 
    0xFB, 0xA1, 0x7C, 0x75, 0x0E, 0x2C, 0x7A, 0xCE, 0x01, 0xE6, 
    0x00, 0x5F, 0x80, 0xFC, 0xB7, 0xDF, 0x62, 0x12, 0x30, 0xC8, 
    0x37, 0x11, 0xB3, 0x93, 0x43, 0xFA, 0x02, 0x8C, 0xEA, 0x7F, 
    0x7F, 0xB5, 0xFF, 0x89, 0xEA, 0xC2, 0x30, 0x82, 0x49, 0xA0, 
    0x22, 0x52, 0x15, 0x5E, 0x23, 0x47, 0xB6, 0x3D, 0x58, 0xC5, 
    0x45, 0x7A, 0xFD, 0x84, 0xD0, 0x5D, 0xFF, 0xFD, 0xB2, 0x03, 
    0x92, 0x84, 0x4A, 0xE8, 0x12, 0x15, 0x46, 0x82, 0xE9, 0xCF, 
    0x01, 0x2F, 0x90, 0x21, 0xA6, 0xF0, 0xBE, 0x17, 0xDD, 0xD0, 
    0xC2, 0x08, 0x4D, 0xCE, 0x25, 0xFF, 0x9B, 0x06, 0xCD, 0xE5, 
    0x35, 0xD0, 0xF9, 0x20, 0xA2, 0xDB, 0x1B, 0xF3, 0x62, 0xC2, 
    0x3E, 0x59, 0x6D, 0x11, 0xA4, 0xF5, 0xA6, 0xCF, 0x39, 0x48, 
    0x83, 0x8A, 0x3A, 0xEC, 0x4E, 0x15, 0xDA, 0xF8, 0x50, 0x0A, 
    0x6E, 0xF6, 0x9E, 0xC4, 0xE3, 0xFE, 0xB6, 0xB1, 0xD9, 0x8E, 
    0x61, 0x0A, 0xC8, 0xB7, 0xEC, 0x3F, 0xAF, 0x6A, 0xD7, 0x60, 
    0xB7, 0xBA, 0xD1, 0xDB, 0x4B, 0xA3, 0x48, 0x5E, 0x8A, 0x94, 
    0xDC, 0x25, 0x0A, 0xE3, 0xFD, 0xB4, 0x1E, 0xD1, 0x5F, 0xB6, 
    0xA8, 0xE5, 0xEB, 0xA0, 0xFC, 0x3D, 0xD6, 0x0B, 0xC8, 0xE3, 
    0x0C, 0x5C, 0x42, 0x87, 0xE5, 0x38, 0x05, 0xDB, 0x05, 0x9A, 
    0xE0, 0x64, 0x8D, 0xB2, 0xF6, 0x42, 0x64, 0xED, 0x5E, 0x39, 
    0xBE, 0x2E, 0x20, 0xD8, 0x2D, 0xF5, 0x66, 0xDA, 0x8D, 0xD5, 
    0x99, 0x8C, 0xCA, 0xBD, 0xAE, 0x05, 0x30, 0x60, 0xAE, 0x6C, 
    0x7B, 0x43, 0x78, 0xE8, 0x46, 0xD2, 0x9F, 0x37, 0xED, 0x7B, 
    0x4E, 0xA9, 0xEC, 0x5D, 0x82, 0xE7, 0x96, 0x1B, 0x7F, 0x25, 
    0xA9, 0x32, 0x38, 0x51, 0xF6, 0x81, 0xD5, 0x82, 0x36, 0x3A, 
    0xA5, 0xF8, 0x99, 0x37, 0xF5, 0xA6, 0x72, 0x58, 0xBF, 0x63, 
    0xAD, 0x6F, 0x1A, 0x0B, 0x1D, 0x96, 0xDB, 0xD4, 0xFA, 0xDD, 
    0xFC, 0xEF, 0xC5, 0x26, 0x6B, 0xA6, 0x61, 0x17, 0x22, 0x39, 
    0x5C, 0x90, 0x65, 0x56, 0xBE, 0x52, 0xAF, 0xE3, 0xF5, 0x65, 
    0x63, 0x6A, 0xD1, 0xB1, 0x7D, 0x50, 0x8B, 0x73, 0xD8, 0x74, 
    0x3E, 0xEB, 0x52, 0x4B, 0xE2, 0x2B, 0x3D, 0xCB, 0xC2, 0xC7, 
    0x46, 0x8D, 0x54, 0x11, 0x9C, 0x74, 0x68, 0x44, 0x9A, 0x13, 
    0xD8, 0xE3, 0xB9, 0x58, 0x11, 0xA1, 0x98, 0xF3, 0x49, 0x1D, 
    0xE3, 0xE7, 0xFE, 0x94, 0x2B, 0x33, 0x04, 0x07, 0xAB, 0xF8, 
    0x2A, 0x4E, 0xD7, 0xC1, 0xB3, 0x11, 0x66, 0x3A, 0xC6, 0x98, 
    0x90, 0xF4, 0x15, 0x70, 0x15, 0x85, 0x3D, 0x91, 0xE9, 0x23, 
    0x03, 0x7C, 0x22, 0x7A, 0x33, 0xCD, 0xD5, 0xEC, 0x28, 0x1C, 
    0xA3, 0xF7, 0x9C, 0x44, 0x54, 0x6B, 0x9D, 0x90, 0xCA, 0x00, 
    0xF0, 0x64, 0xC9, 0x9E, 0x3D, 0xD9, 0x79, 0x11, 0xD3, 0x9F, 
    0xE9, 0xC5, 0xD0, 0xB2, 0x3A, 0x22, 0x9A, 0x23, 0x4C, 0xB3, 
    0x61, 0x86, 0xC4, 0x81, 0x9E, 0x8B, 0x9C, 0x59, 0x27, 0x72, 
    0x66, 0x32, 0x29, 0x1D, 0x6A, 0x41, 0x82, 0x11, 0xCC, 0x29, 
    0x62, 0xE2, 0x0F, 0xE4, 0x7F, 0xEB, 0x3E, 0xDF, 0x33, 0x0F, 
    0x2C, 0x60, 0x3A, 0x9D, 0x48, 0xC0, 0xFC, 0xB5, 0x69, 0x9D, 
    0xBF, 0xE5, 0x89, 0x64, 0x25, 0xC5, 0xBA, 0xC4, 0xAE, 0xE8, 
    0x2E, 0x57, 0xA8, 0x5A, 0xAF, 0x4E, 0x25, 0x13, 0xE4, 0xF0, 
    0x57, 0x96, 0xB0, 0x7B, 0xA2, 0xEE, 0x47, 0xD8, 0x05, 0x06, 
    0xF8, 0xD2, 0xC2, 0x5E, 0x50, 0xFD, 0x14, 0xDE, 0x71, 0xE6, 
    0xC4, 0x18, 0x55, 0x93, 0x02, 0xF9, 0x39, 0xB0, 0xE1, 0xAB, 
    0xD5, 0x76, 0xF2, 0x79, 0xC4, 0xB2, 0xE0, 0xFE, 0xB8, 0x5C, 
    0x1F, 0x28, 0xFF, 0x18, 0xF5, 0x88, 0x91, 0xFF, 0xEF, 0x13, 
    0x2E, 0xEF, 0x2F, 0xA0, 0x93, 0x46, 0xAE, 0xE3, 0x3C, 0x28, 
    0xEB, 0x13, 0x0F, 0xF2, 0x8F, 0x5B, 0x76, 0x69, 0x53, 0x33, 
    0x41, 0x13, 0x21, 0x19, 0x96, 0xD2, 0x00, 0x11, 0xA1, 0x98, 
    0xE3, 0xFC, 0x43, 0x3F, 0x9F, 0x25, 0x41, 0x01, 0x0A, 0xE1, 
    0x7C, 0x1B, 0xF2, 0x02, 0x58, 0x0F, 0x60, 0x47, 0x47, 0x2F, 
    0xB3, 0x68, 0x57, 0xFE, 0x84, 0x3B, 0x19, 0xF5, 0x98, 0x40, 
    0x09, 0xDD, 0xC3, 0x24, 0x04, 0x4E, 0x84, 0x7A, 0x4F, 0x4A, 
    0x0A, 0xB3, 0x4F, 0x71, 0x95, 0x95, 0xDE, 0x37, 0x25, 0x2D, 
    0x62, 0x35, 0x36, 0x5E, 0x9B, 0x84, 0x39, 0x2B, 0x06, 0x10, 
    0x85, 0x34, 0x9D, 0x73, 0x20, 0x3A, 0x4A, 0x13, 0xE9, 0x6F, 
    0x54, 0x32, 0xEC, 0x0F, 0xD4, 0xA1, 0xEE, 0x65, 0xAC, 0xCD, 
    0xD5, 0xE3, 0x90, 0x4D, 0xF5, 0x4C, 0x1D, 0xA5, 0x10, 0xB0, 
    0xFF, 0x20, 0xDC, 0xC0, 0xC7, 0x7F, 0xCB, 0x2C, 0x0E, 0x0E, 
    0xB6, 0x05, 0xCB, 0x05, 0x04, 0xDB, 0x87, 0x63, 0x2C, 0xF3, 
    0xD8, 0xB4, 0xDA, 0xE6, 0xE7, 0x05, 0x76, 0x9D, 0x1D, 0xE3, 
    0x54, 0x27, 0x01, 0x23, 0xCB, 0x11, 0x45, 0x0E, 0xFC, 0x60, 
    0xAC, 0x47, 0x68, 0x3D, 0x7B, 0x8D, 0x0F, 0x81, 0x13, 0x65, 
    0x56, 0x5F, 0xD9, 0x8C, 0x4C, 0x8E, 0xB9, 0x36, 0xBC, 0xAB, 
    0x8D, 0x06, 0x9F, 0xC3, 0x3B, 0xD8, 0x01, 0xB0, 0x3A, 0xDE, 
    0xA2, 0xE1, 0xFB, 0xC5, 0xAA, 0x46, 0x3D, 0x08, 0xCA, 0x19, 
    0x89, 0x6D, 0x2B, 0xF5, 0x9A, 0x07, 0x1B, 0x85, 0x1E, 0x6C, 
    0x23, 0x90, 0x52, 0x17, 0x2F, 0x29, 0x6B, 0xFB, 0x5E, 0x72, 
    0x40, 0x47, 0x90, 0xA2, 0x18, 0x10, 0x14, 0xF3, 0xB9, 0x4A, 
    0x4E, 0x97, 0xD1, 0x17, 0xB4, 0x38, 0x13, 0x03, 0x68, 0xCC, 
    0x39, 0xDB, 0xB2, 0xD1, 0x98, 0x06, 0x5A, 0xE3, 0x98, 0x65, 
    0x47, 0x92, 0x6C, 0xD2, 0x16, 0x2F, 0x40, 0xA2, 0x9F, 0x0C, 
    0x3C, 0x87, 0x45, 0xC0, 0xF5, 0x0F, 0xBA, 0x38, 0x52, 0xE5, 
    0x66, 0xD4, 0x45, 0x75, 0xC2, 0x9D, 0x39, 0xA0, 0x3F, 0x0C, 
    0xDA, 0x72, 0x19, 0x84, 0xB6, 0xF4, 0x40, 0x59, 0x1F, 0x35, 
    0x5E, 0x12, 0xD4, 0x39, 0xFF, 0x15, 0x0A, 0xAB, 0x76, 0x13, 
    0x49, 0x9D, 0xBD, 0x49, 0xAD, 0xAB, 0xC8, 0x67, 0x6E, 0xEF, 
    0x02, 0x3B, 0x15, 0xB6, 0x5B, 0xFC, 0x5C, 0xA0, 0x69, 0x48, 
    0x10, 0x9F, 0x23, 0xF3, 0x50, 0xDB, 0x82, 0x12, 0x35, 0x35, 
    0xEB, 0x8A, 0x74, 0x33, 0xBD, 0xAB, 0xCB, 0x90, 0x92, 0x71, 
    0xA6, 0xEC, 0xBC, 0xB5, 0x8B, 0x93, 0x6A, 0x88, 0xCD, 0x4E, 
    0x8F, 0x2E, 0x6F, 0xF5, 0x80, 0x01, 0x75, 0xF1, 0x13, 0x25, 
    0x3D, 0x8F, 0xA9, 0xCA, 0x88, 0x85, 0xC2, 0xF5, 0x52, 0xE6, 
    0x57, 0xDC, 0x60, 0x3F, 0x25, 0x2E, 0x1A, 0x8E, 0x30, 0x8F, 
    0x76, 0xF0, 0xBE, 0x79, 0xE2, 0xFB, 0x8F, 0x5D, 0x5F, 0xBB, 
    0xE2, 0xE3, 0x0E, 0xCA, 0xDD, 0x22, 0x07, 0x23, 0xC8, 0xC0, 
    0xAE, 0xA8, 0x07, 0x8C, 0xDF, 0xCB, 0x38, 0x68, 0x26, 0x3F, 
    0xF8, 0xF0, 0x94, 0x00, 0x54, 0xDA, 0x48, 0x78, 0x18, 0x93, 
    0xA7, 0xE4, 0x9A, 0xD5, 0xAF, 0xF4, 0xAF, 0x30, 0x0C, 0xD8, 
    0x04, 0xA6, 0xB6, 0x27, 0x9A, 0xB3, 0xFF, 0x3A, 0xFB, 0x64, 
    0x49, 0x1C, 0x85, 0x19, 0x4A, 0xAB, 0x76, 0x0D, 0x58, 0xA6, 
    0x06, 0x65, 0x4F, 0x9F, 0x44, 0x00, 0xE8, 0xB3, 0x85, 0x91, 
    0x35, 0x6F, 0xBF, 0x64, 0x25, 0xAC, 0xA2, 0x6D, 0xC8, 0x52, 
    0x44, 0x25, 0x9F, 0xF2, 0xB1, 0x9C, 0x41, 0xB9, 0xF9, 0x6F, 
    0x3C, 0xA9, 0xEC, 0x1D, 0xDE, 0x43, 0x4D, 0xA7, 0xD2, 0xD3, 
    0x92, 0xB9, 0x05, 0xDD, 0xF3, 0xD1, 0xF9, 0xAF, 0x93, 0xD1, 
    0xAF, 0x59, 0x50, 0xBD, 0x49, 0x3F, 0x5A, 0xA7, 0x31, 0xB4, 
    0x05, 0x6D, 0xF3, 0x1B, 0xD2, 0x67, 0xB6, 0xB9, 0x0A, 0x07, 
    0x98, 0x31, 0xAA, 0xF5, 0x79, 0xBE, 0x0A, 0x39, 0x01, 0x31, 
    0x37, 0xAA, 0xC6, 0xD4, 0x04, 0xF5, 0x18, 0xCF, 0xD4, 0x68, 
    0x40, 0x64, 0x7E, 0x78, 0xBF, 0xE7, 0x06, 0xCA, 0x4C, 0xF5, 
    0xE9, 0xC5, 0x45, 0x3E, 0x9F, 0x7C, 0xFD, 0x2B, 0x8B, 0x4C, 
    0x8D, 0x16, 0x9A, 0x44, 0xE5, 0x5C, 0x88, 0xD4, 0xA9, 0xA7, 
    0xF9, 0x47, 0x42, 0x41, 0xE2, 0x21, 0xAF, 0x44, 0x86, 0x00, 
    0x18, 0xAB, 0x08, 0x56, 0x97, 0x2E, 0x19, 0x4C, 0xD9, 0x34, 
    };
    // zig fmt: on

    var client_msg_buf = [_]u8{0} ** 1500;
    std.mem.copyForwards(u8, &client_msg_buf, &recv_msg);
    const client_msgs = client_msg_buf[0..recv_msg.len];

    const pkt = try InitialPacket.decodeFromSlice(client_msgs, false);

    try expect(pkt.lhp.version == 1);
    try expect(pkt.lhp.type_specific_bits == 0);
    try expect(std.mem.eql(u8, pkt.lhp.source_connection_id, &[_]u8{}));
    try expect(std.mem.eql(u8, pkt.lhp.destination_connection_id, &[_]u8{ 0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08 }));
    try expect(pkt.token.len == 0);
    try expect(pkt.length.length == 2);
    try expect(pkt.length.value == 0x049E);
    try expect(pkt.length.value + pkt.header_length() == 1200);

    const sample_ans = [_]u8{
        0xD1, 0xB1, 0xC9, 0x8D, 0xD7, 0x68, 0x9F, 0xB8, 0xEC, 0x11,
        0xD2, 0x42, 0xB1, 0x23, 0xDC, 0x9B,
    };
    try expect(std.mem.eql(u8, pkt.sample, &sample_ans));

    const secret = try key.InitialSecret.generate(pkt.lhp.destination_connection_id);
    const mask = getHeaderProtectonMask(pkt.sample[0..16], secret.client_secret.hp);
    const mask_ans = [_]u8{
        0x43,
        0x7B,
        0x9A,
        0xEC,
        0x36,
    };
    try expect(std.mem.eql(u8, &mask, &mask_ans));

    var pn_len: usize = 0;
    var pn: u32 = 0;
    unlockHeaderProtection(client_msgs, pkt.protected_offset, &pn_len, &pn, pkt.sample, secret.client_secret.hp);
    try expect(pn_len == 4);
    try expect(pn == 2);

    const nonce = getNonce(pn, secret.client_secret.iv);
    var m = [_]u8{0} ** 1500;
    const payload = client_msgs[pkt.protected_offset + pn_len ..];
    const plain = try aead.EasyAes128Gcm.decrypt(&m, payload, client_msgs[0 .. pkt.protected_offset + pn_len], nonce, secret.client_secret.key);

    const frame = Frame.decodeFromSlice(plain);
    try expect(frame == Frame.crypto);
    const crypto_frame = frame.crypto;
    try expect(crypto_frame.frame_type.length == 1);
    try expect(crypto_frame.offset.length == 1);
    try expect(crypto_frame.offset.value == 0);
    try expect(crypto_frame.len.length == 2);
    try expect(crypto_frame.len.value == 0xf1);

    var readStream = std.io.fixedBufferStream(crypto_frame.data);
    var hs = try tls13.handshake.Handshake.decode(readStream.reader(), std.testing.allocator, null);
    defer hs.deinit();
    try expect(hs == tls13.handshake.Handshake.client_hello);
    const ch = hs.client_hello;

    const exts = ch.extensions.items;
    try expect(exts.len == 11);
    try expect(exts[0] == .server_name);
    try expect(exts[1] == .renegotiation_info);
    try expect(exts[2] == .supported_groups);
    try expect(exts[3] == .application_layer_protocol_negotiation);
    try expect(exts[4] == .status_request);
    try expect(exts[5] == .key_share);
    try expect(exts[6] == .supported_versions);
    try expect(exts[7] == .signature_algorithms);
    try expect(exts[8] == .psk_key_exchange_modes);
    try expect(exts[9] == .record_size_limit);
    try expect(exts[10] == .quic_transport_parameters);
    const quic_trans_params = exts[10].quic_transport_parameters;
    try expect(quic_trans_params.length() == 0x32);
    try expect(quic_trans_params.params.items.len == 8);
    const qtps = quic_trans_params.params.items;
    try expect(qtps[0].id == tls13.quic.TransportParameterType.initial_max_data);
    try expect(qtps[1].id == tls13.quic.TransportParameterType.initial_max_stream_data_bidi_local);
    try expect(qtps[2].id == tls13.quic.TransportParameterType.initial_max_stream_data_uni);
    try expect(qtps[3].id == tls13.quic.TransportParameterType.initial_max_streams_bidi);
    try expect(qtps[4].id == tls13.quic.TransportParameterType.max_idle_timeout);
    try expect(qtps[5].id == tls13.quic.TransportParameterType.initial_max_streams_uni);
    try expect(qtps[6].id == tls13.quic.TransportParameterType.initial_source_connection_id);
    try expect(qtps[7].id == tls13.quic.TransportParameterType.initial_max_stream_data_bidi_remote);

    const frame2 = Frame.decodeFromSlice(plain[frame.length()..]);
    try expect(frame2 == Frame.padding);
    try expect(frame2.padding.len == 917);

    var buf = [_]u8{0} ** 1500;
    var writeStream = std.io.fixedBufferStream(&buf);

    const enc_len = try hs.encode(writeStream.writer());
    try expect(enc_len == crypto_frame.data.len);
    try expect(std.mem.eql(u8, crypto_frame.data, buf[0..enc_len]));

    var send_buf = [_]u8{0} ** 1500;
    const hdr_size = try pkt.encodeToSlice(&send_buf, 4);
    std.mem.writeInt(u32, send_buf[hdr_size..][0..4], 2, .big);
    try expect(std.mem.eql(u8, send_buf[0 .. hdr_size + 4], client_msgs[0 .. hdr_size + 4]));

    var idx = hdr_size + 4;
    idx += try frame.encodeToSlice(send_buf[idx..]);
    idx += try frame2.encodeToSlice(send_buf[idx..]);
    try expect(std.mem.eql(u8, send_buf[hdr_size + 4 .. idx], plain));

    const enc_res = aead.EasyAes128Gcm.encrypt(send_buf[hdr_size + 4 ..], send_buf[hdr_size + 4 .. idx], send_buf[0 .. hdr_size + 4], nonce, secret.client_secret.key);
    idx += Aes128Gcm.tag_length;
    try expect(std.mem.eql(u8, enc_res, payload));

    lockHeaderProtection(&send_buf, pkt.protected_offset, 4, send_buf[pkt.protected_offset + 4 .. pkt.protected_offset + 20][0..16], secret.client_secret.hp);
    try expect(std.mem.eql(u8, send_buf[0..idx], &recv_msg));
}

test "parse Server Initial Packet" {
    // RFC9001 A.3. Server Initial
    const recv_msg = [_]u8{
        0xCF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xF0, 0x67, 0xA5,
        0x50, 0x2A, 0x42, 0x62, 0xB5, 0x00, 0x40, 0x75, 0xC0, 0xD9,
        0x5A, 0x48, 0x2C, 0xD0, 0x99, 0x1C, 0xD2, 0x5B, 0x0A, 0xAC,
        0x40, 0x6A, 0x58, 0x16, 0xB6, 0x39, 0x41, 0x00, 0xF3, 0x7A,
        0x1C, 0x69, 0x79, 0x75, 0x54, 0x78, 0x0B, 0xB3, 0x8C, 0xC5,
        0xA9, 0x9F, 0x5E, 0xDE, 0x4C, 0xF7, 0x3C, 0x3E, 0xC2, 0x49,
        0x3A, 0x18, 0x39, 0xB3, 0xDB, 0xCB, 0xA3, 0xF6, 0xEA, 0x46,
        0xC5, 0xB7, 0x68, 0x4D, 0xF3, 0x54, 0x8E, 0x7D, 0xDE, 0xB9,
        0xC3, 0xBF, 0x9C, 0x73, 0xCC, 0x3F, 0x3B, 0xDE, 0xD7, 0x4B,
        0x56, 0x2B, 0xFB, 0x19, 0xFB, 0x84, 0x02, 0x2F, 0x8E, 0xF4,
        0xCD, 0xD9, 0x37, 0x95, 0xD7, 0x7D, 0x06, 0xED, 0xBB, 0x7A,
        0xAF, 0x2F, 0x58, 0x89, 0x18, 0x50, 0xAB, 0xBD, 0xCA, 0x3D,
        0x20, 0x39, 0x8C, 0x27, 0x64, 0x56, 0xCB, 0xC4, 0x21, 0x58,
        0x40, 0x7D, 0xD0, 0x74, 0xEE,
    };

    var server_msg_buf = [_]u8{0} ** 1500;
    std.mem.copyForwards(u8, &server_msg_buf, &recv_msg);
    const server_msg = server_msg_buf[0..recv_msg.len];

    const dst_con_id = [_]u8{ 0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08 };
    const pkt = try InitialPacket.decodeFromSlice(server_msg, true);
    const secret = try key.InitialSecret.generate(&dst_con_id);
    var pn_len: usize = 0;
    var pn: u32 = 0;
    unlockHeaderProtection(server_msg, pkt.protected_offset, &pn_len, &pn, pkt.sample, secret.server_secret.hp);
    try expect(pn_len == 2);
    try expect(pn == 1);

    const nonce = getNonce(pn, secret.server_secret.iv);
    var m = [_]u8{0} ** 1500;
    const payload = server_msg[pkt.protected_offset + pn_len ..];
    try Aes128Gcm.decrypt(m[0 .. payload.len - Aes128Gcm.tag_length], payload[0 .. payload.len - Aes128Gcm.tag_length], payload[payload.len - Aes128Gcm.tag_length ..][0..Aes128Gcm.tag_length].*, server_msg[0 .. pkt.protected_offset + pn_len], nonce, secret.server_secret.key);

    const plain = m[0 .. payload.len - Aes128Gcm.tag_length];
    const frame = Frame.decodeFromSlice(plain);
    try expect(frame == Frame.ack);
    const ack = frame.ack;
    try expect(ack.largest_acked.value == 0);
    try expect(ack.ack_delay.value == 0);
    try expect(ack.ack_range_count.value == 0);
    try expect(ack.first_ack_range.value == 0);

    const frame2 = Frame.decodeFromSlice(plain[frame.length()..]);
    try expect(frame2 == Frame.crypto);
    const crypto_frame = frame2.crypto;
    try expect(crypto_frame.offset.value == 0);
    try expect(crypto_frame.len.value == 0x5a);
    var readStream = std.io.fixedBufferStream(crypto_frame.data);
    var hs = try tls13.handshake.Handshake.decode(readStream.reader(), std.testing.allocator, null);
    defer hs.deinit();
    try expect(hs == tls13.handshake.Handshake.server_hello);
    const sh = hs.server_hello;
    const exts = sh.extensions.items;
    try expect(exts.len == 2);
    try expect(exts[0] == .key_share);
    const ks = exts[0].key_share;
    try expect(ks.entries.items[0].group == .x25519);
    try expect(exts[1] == .supported_versions);

    var buf = [_]u8{0} ** 1500;
    var writeStream = std.io.fixedBufferStream(&buf);

    const enc_len = try hs.encode(writeStream.writer());
    try expect(enc_len == crypto_frame.data.len);
    try expect(std.mem.eql(u8, crypto_frame.data, buf[0..enc_len]));

    var send_buf = [_]u8{0} ** 1500;
    const hdr_size = try pkt.encodeToSlice(&send_buf, 2);
    std.mem.writeInt(u16, send_buf[hdr_size..][0..2], 1, .big);
    try expect(std.mem.eql(u8, send_buf[0 .. hdr_size + 2], server_msg[0 .. hdr_size + 2]));

    var idx = hdr_size + 2;
    idx += try frame.encodeToSlice(send_buf[idx..]);
    idx += try frame2.encodeToSlice(send_buf[idx..]);
    try expect(std.mem.eql(u8, send_buf[hdr_size + 2 .. idx], plain));

    const enc_res = aead.EasyAes128Gcm.encrypt(send_buf[hdr_size + 2 ..], send_buf[hdr_size + 2 .. idx], send_buf[0 .. hdr_size + 2], nonce, secret.server_secret.key);
    idx += Aes128Gcm.tag_length;
    try expect(std.mem.eql(u8, enc_res, payload));

    lockHeaderProtection(&send_buf, pkt.protected_offset, 2, send_buf[pkt.protected_offset + 4 .. pkt.protected_offset + 20][0..16], secret.server_secret.hp);
    try expect(std.mem.eql(u8, send_buf[0..idx], &recv_msg));
}
