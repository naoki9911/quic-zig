const std = @import("std");
const aead = std.crypto.aead;

const Aes128Gcm = aead.aes_gcm.Aes128Gcm;
pub const EasyAes128Gcm = EasyAead(Aes128Gcm);

pub fn EasyAead(comptime Aead: type) type {
    return struct {
        pub fn decrypt(m: []u8, c: []const u8, ad: []const u8, nonce: [Aead.nonce_length]u8, key: [Aead.key_length]u8) ![]u8 {
            const body_len = c.len - Aead.tag_length;
            try Aead.decrypt(m[0..body_len], c[0..body_len], c[body_len..][0..Aead.tag_length].*, ad, nonce, key);

            return m[0..body_len];
        }

        pub fn encrypt(c: []u8, m: []const u8, ad: []const u8, nonce: [Aead.nonce_length]u8, key: [Aead.key_length]u8) []u8 {
            Aead.encrypt(c[0..m.len], c[m.len..][0..Aead.tag_length], m, ad, nonce, key);
            return c[0 .. m.len + Aead.tag_length];
        }
    };
}
