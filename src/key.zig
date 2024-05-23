const std = @import("std");
const tls13crypto = @import("tls13-crypto");

pub fn AeadSecret(comptime Aead: type) type {
    return struct {
        key: [Aead.key_length]u8 = [_]u8{0} ** Aead.key_length,
        iv: [Aead.nonce_length]u8 = [_]u8{0} ** Aead.nonce_length,
        hp: [Aead.key_length]u8 = [_]u8{0} ** Aead.key_length,
    };
}

/// RFC9001 5.2. Initial Secrets
///
/// initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
/// initial_secret = HKDF-Extract(initial_salt,
///                               client_dst_connection_id)
///
/// client_initial_secret = HKDF-Expand-Label(initial_secret,
///                                           "client in", "",
///                                           Hash.length)
/// server_initial_secret = HKDF-Expand-Label(initial_secret,
///                                           "server in", "",
///                                           Hash.length)
pub const InitialSecret = struct {
    const SALT = [_]u8{
        0x38, 0x76, 0x2C, 0xF7, 0xF5, 0x59, 0x34, 0xB3, 0x4D, 0x17,
        0x9A, 0xE6, 0xA4, 0xC8, 0x0C, 0xAD, 0xCC, 0xBB, 0x7F, 0x0A,
    };

    // RFC 9001 5. Packet Protection
    // Initial packets use AEAD_AES_128_GCM
    const hkdf = tls13crypto.Hkdf.Sha256.hkdf;
    pub const Aead = tls13crypto.Aead.Aes128Gcm.C;

    const Self = @This();
    const SecretType = AeadSecret(Aead);

    client_secret: SecretType,
    server_secret: SecretType,

    /// out.len >= Sha256.digest_length
    pub fn getInitialSecret(out: []u8, client_dst_con_id: []const u8) void {
        hkdf.extract(out, &SALT, client_dst_con_id);
    }

    pub fn generate(dst_con_id: []const u8) !Self {
        var init = [_]u8{0} ** hkdf.digest_length;
        hkdf.extract(&init, &SALT, dst_con_id);

        var client_init = [_]u8{0} ** hkdf.digest_length;
        try InitialSecret.hkdf.hkdfExpandLabel(&client_init, &init, "client in", "", 32);

        var client_secret = SecretType{};
        try InitialSecret.hkdf.hkdfExpandLabel(&client_secret.key, &client_init, "quic key", "", client_secret.key.len);
        try InitialSecret.hkdf.hkdfExpandLabel(&client_secret.iv, &client_init, "quic iv", "", client_secret.iv.len);
        try InitialSecret.hkdf.hkdfExpandLabel(&client_secret.hp, &client_init, "quic hp", "", client_secret.hp.len);

        var server_init = [_]u8{0} ** hkdf.digest_length;
        try InitialSecret.hkdf.hkdfExpandLabel(&server_init, &init, "server in", "", 32);

        var server_secret = SecretType{};
        try InitialSecret.hkdf.hkdfExpandLabel(&server_secret.key, &server_init, "quic key", "", server_secret.key.len);
        try InitialSecret.hkdf.hkdfExpandLabel(&server_secret.iv, &server_init, "quic iv", "", server_secret.iv.len);
        try InitialSecret.hkdf.hkdfExpandLabel(&server_secret.hp, &server_init, "quic hp", "", server_secret.hp.len);

        return Self{
            .client_secret = client_secret,
            .server_secret = server_secret,
        };
    }
};

const expect = std.testing.expect;

test "generate initial secret" {
    const dst_con_id = [_]u8{ 0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08 };
    const init_secret = try InitialSecret.generate(&dst_con_id);

    const client_key_ans = [_]u8{
        0x1F, 0x36, 0x96, 0x13, 0xDD, 0x76, 0xD5, 0x46, 0x77, 0x30,
        0xEF, 0xCB, 0xE3, 0xB1, 0xA2, 0x2D,
    };
    try expect(std.mem.eql(u8, &init_secret.client_secret.key, &client_key_ans));

    const client_iv_ans = [_]u8{
        0xFA, 0x04, 0x4B, 0x2F, 0x42, 0xA3, 0xFD, 0x3B, 0x46, 0xFB,
        0x25, 0x5C,
    };
    try expect(std.mem.eql(u8, &init_secret.client_secret.iv, &client_iv_ans));

    const client_hp_ans = [_]u8{
        0x9F, 0x50, 0x44, 0x9E, 0x04, 0xA0, 0xE8, 0x10, 0x28, 0x3A,
        0x1E, 0x99, 0x33, 0xAD, 0xED, 0xD2,
    };
    try expect(std.mem.eql(u8, &init_secret.client_secret.hp, &client_hp_ans));

    const server_key_ans = [_]u8{
        0xCF, 0x3A, 0x53, 0x31, 0x65, 0x3C, 0x36, 0x4C, 0x88, 0xF0,
        0xF3, 0x79, 0xB6, 0x06, 0x7E, 0x37,
    };
    try expect(std.mem.eql(u8, &init_secret.server_secret.key, &server_key_ans));

    const server_iv_ans = [_]u8{
        0x0A, 0xC1, 0x49, 0x3C, 0xA1, 0x90, 0x58, 0x53, 0xB0, 0xBB,
        0xA0, 0x3E,
    };
    try expect(std.mem.eql(u8, &init_secret.server_secret.iv, &server_iv_ans));

    const server_hp_ans = [_]u8{
        0xC2, 0x06, 0xB8, 0xD9, 0xB9, 0xF0, 0xF3, 0x76, 0x44, 0x43,
        0x0B, 0x49, 0x0E, 0xEA, 0xA3, 0x14,
    };
    try expect(std.mem.eql(u8, &init_secret.server_secret.hp, &server_hp_ans));

    //InitialSecret.HKDF.hkdfExpandLabel(self: Self, out: []u8, prk: []const u8, label: []const u8, ctx: []const u8, len: usize)
}
