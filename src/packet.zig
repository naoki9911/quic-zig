const std = @import("std");
const key = @import("key.zig");

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

    length: usize,
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
        if ((buf[idx] >> 7) & 0x1 == 0) {
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
            .length = idx,
            .packet_type = pkt_type,
            .type_specific_bits = specific_bits,
            .version = version,
            .destination_connection_id = dst_con_id,
            .source_connection_id = src_con_id,
        };
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

    // not owning
    token: []const u8,

    // not owning
    sample: []const u8,

    // not owning
    header: []const u8,

    // not owning
    payload: []const u8,

    length: VLI,
    mask: [5]u8,
    pkt_number: u32,
    secret: key.InitialSecret,
    nonce: [key.InitialSecret.Aead.nonce_length]u8,

    pub fn decodeFromSlice(buf: []u8, plain: []u8) !Self {
        // decode as LHP
        const lhp = try LongHeaderPacket.decodeFromSlice(buf);

        if (lhp.packet_type != .Initial) {
            return QuicPacketError.NotInitialPacket;
        }

        const payload_slice = buf[lhp.length..];

        var payload_idx: usize = 0;
        const token_length_vli = VLI.decodeFromSlice(payload_slice);
        payload_idx += @intCast(token_length_vli.length);

        // careful this
        // if (sentByServer and token_length_vli.value != 0) {
        //     return QuicPacketError.InvalidTokenLength;
        // }

        const token = payload_slice[payload_idx .. payload_idx + @as(usize, token_length_vli.value)];
        payload_idx += @intCast(token_length_vli.value);

        const length_vli = VLI.decodeFromSlice(payload_slice[payload_idx..]);
        payload_idx += @intCast(length_vli.length);

        const sample = payload_slice[payload_idx + 4 .. payload_idx + 4 + 16];
        const secret = try key.InitialSecret.generate(lhp.destination_connection_id);
        const aes128decoder = std.crypto.core.aes.Aes128.initEnc(secret.client_secret.hp);
        var headerProtectionKey = [_]u8{0} ** 16;
        aes128decoder.encrypt(&headerProtectionKey, sample[0..16]);
        const mask = headerProtectionKey[0..5];

        // RFC9001 5.4.1. Header Protection Application
        // pn_length = (packet[0] & 0x03) + 1
        // if (packet[0] & 0x80) == 0x80:
        //    # Long header: 4 bits masked
        //    packet[0] ^= mask[0] & 0x0f
        // else:
        //    # Short header: 5 bits masked
        //    packet[0] ^= mask[0] & 0x1f
        if ((buf[0] & 0x80) == 0x80) {
            buf[0] ^= mask[0] & 0xf;
        } else {
            buf[0] ^= mask[0] & 0x1f;
        }
        const pn_len = (buf[0] & 0x03) + 1;

        var pn: u32 = 0;
        const protected_payload = buf[lhp.length + payload_idx ..];
        for (0..pn_len, mask[1 .. 1 + pn_len]) |i, m| {
            protected_payload[i] ^= m;
            pn = (pn << 8) | protected_payload[i];
        }
        const header = buf[0 .. lhp.length + payload_idx + pn_len];
        const payload = buf[header.len..];

        // RFC9001 5.3. AEAD Usage
        // The key and IV for the packet are computed as described in Section 5.1.
        // The nonce, N, is formed by combining the packet protection IV with the packet number.
        // The 62 bits of the reconstructed QUIC packet number in network byte order are left-padded with zeros to the size of the IV.
        // The exclusive OR of the padded packet number and the IV forms the AEAD nonce.
        // The associated data, A, for the AEAD is the contents of the QUIC header, starting from the first byte of either the short or long header, up to and including the unprotected packet number.
        // The input plaintext, P, for the AEAD is the payload of the QUIC packet, as described in [QUIC-TRANSPORT].
        // The output ciphertext, C, of the AEAD is transmitted in place of P.

        var nonce = [_]u8{0} ** key.InitialSecret.Aead.nonce_length;
        std.mem.writeInt(u32, nonce[nonce.len - 4 ..], pn, .big);
        for (&nonce, secret.client_secret.iv) |*n, i| {
            n.* = n.* ^ i;
        }
        const ad = header;

        try key.InitialSecret.Aead.decrypt(plain[0 .. payload.len - 16], payload[0 .. payload.len - 16], payload[payload.len - 16 ..][0..16].*, ad, nonce, secret.client_secret.key);

        return Self{
            .lhp = lhp,
            .token = token,
            .length = length_vli,
            .sample = sample,
            .mask = mask.*,
            .pkt_number = pn,
            .secret = secret,
            .header = header,
            .payload = payload,
            .nonce = nonce,
        };
    }
};

const expect = std.testing.expect;

test "parse Initial Packet" {
    // RFC9001 A.2. Client Initial
    // zig fmt: off
    var client_msgs = [_]u8{
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

    var plain = [_]u8{0} ** 1500;
    const pkt = try InitialPacket.decodeFromSlice(&client_msgs, &plain);

    try expect(pkt.lhp.version == 1);
    try expect(pkt.lhp.type_specific_bits == 0);
    try expect(std.mem.eql(u8, pkt.lhp.source_connection_id, &[_]u8{}));
    try expect(std.mem.eql(u8, pkt.lhp.destination_connection_id, &[_]u8{ 0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08 }));
    try expect(pkt.length.value == 0x049E);

    const sample_ans = [_]u8{
        0xD1, 0xB1, 0xC9, 0x8D, 0xD7, 0x68, 0x9F, 0xB8, 0xEC, 0x11,
        0xD2, 0x42, 0xB1, 0x23, 0xDC, 0x9B,
    };
    try expect(std.mem.eql(u8, pkt.sample, &sample_ans));

    const secret = try key.InitialSecret.generate(pkt.lhp.destination_connection_id);
    const aes128decoder = std.crypto.core.aes.Aes128.initEnc(secret.client_secret.hp);
    var headerProtectionKey = [_]u8{0} ** 16;
    aes128decoder.encrypt(&headerProtectionKey, pkt.sample[0..16]);
    const mask = headerProtectionKey[0..5];
    const mask_ans = [_]u8{
        0x43,
        0x7B,
        0x9A,
        0xEC,
        0x36,
    };
    try expect(std.mem.eql(u8, mask, &mask_ans));

    try expect(pkt.pkt_number == 2);
    const nonce_ans = [_]u8{
        0xFA, 0x04, 0x4B, 0x2F, 0x42, 0xA3, 0xFD, 0x3B, 0x46, 0xFB,
        0x25, 0x5E,
    };
    try expect(std.mem.eql(u8, &pkt.nonce, &nonce_ans));

    // '1' is the lenght of PacketNumber
    //try expect(pkt.length.value == pkt.protected_payload.len);
}
