//! tink —— tink data-flow node frame protocol (universal, language-agnostic).
//!
//! Frame = [len u32 BE][payload][crc u32 BE]; crc = CRC32-IEEE (0xEDB88320).
//! Mirrors std/tink.tie (tie standard library) and the Rust / C / Python / JS /
//! C++ / Java / C# / Go tink libraries; pure functions over byte slices, IO
//! (stdin/stdout) left to the caller. Zig, std-only, no dependencies.
//!
//! const tink = @import("tink.zig");
//! const frame = tink.frameEncode(&.{ 1, 2, 3 });
//! const got = tink.frameNext(frame, 0);

const std = @import("std");

/// CRC32-IEEE over a byte slice (bit-loop, no table; matches zlib.crc32).
/// Check vector: `crc32("123456789") == 0xCBF43926`.
pub fn crc32(data: []const u8) u32 {
    var crc: u32 = 0xFFFFFFFF;
    for (data) |b| {
        crc ^= b;
        var k: u4 = 0;
        while (k < 8) : (k += 1) {
            crc = if (crc & 1 != 0) (crc >> 1) ^ 0xEDB88320 else crc >> 1;
        }
    }
    return crc ^ 0xFFFFFFFF;
}

/// Encode a payload into a full frame: [len u32 BE][payload][crc u32 BE].
/// Returns a new []u8 of payload.len + 8 bytes.
pub fn frameEncode(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, payload.len + 8);
    errdefer allocator.free(out);
    const n: u32 = @intCast(payload.len);
    std.mem.writeInt(u32, out[0..4], n, .big);
    @memcpy(out[4 .. 4 + payload.len], payload);
    std.mem.writeInt(u32, out[4 + payload.len ..][0..4], crc32(payload), .big);
    return out;
}

/// Result of parsing a frame: the payload (zero-copy slice into the input) and
/// the position right after the frame (payload length + 8).
pub const Frame = struct {
    payload: []const u8,
    next: usize,
};

/// Parse one frame at `pos` (verifies CRC). Returns the Frame, or null on
/// out-of-bounds or CRC mismatch.
pub fn frameNext(bytes: []const u8, pos: usize) ?Frame {
    if (bytes.len < pos + 8) return null;
    const n = std.mem.readInt(u32, bytes[pos..][0..4], .big);
    const end = pos + 8 + n;
    if (bytes.len < end) return null;
    const payload = bytes[pos + 4 .. pos + 4 + n];
    const want = std.mem.readInt(u32, bytes[end - 4 ..][0..4], .big);
    if (crc32(payload) != want) return null;
    return .{ .payload = payload, .next = end };
}

/// Skip one frame at `pos` without copying or verifying (zero-copy). Returns
/// the position after the frame, or null on out-of-bounds.
pub fn frameSkip(bytes: []const u8, pos: usize) ?usize {
    if (bytes.len < pos + 8) return null;
    const n = std.mem.readInt(u32, bytes[pos..][0..4], .big);
    const end = pos + 8 + n;
    if (bytes.len < end) return null;
    return end;
}

test "crc32 vector" {
    try std.testing.expectEqual(@as(u32, 0xCBF43926), crc32("123456789"));
}

test "frame roundtrip" {
    const alloc = std.testing.allocator;
    const p = [_]u8{ 1, 2, 3 };
    const f = try frameEncode(alloc, &p);
    defer alloc.free(f);
    const got = frameNext(f, 0).?;
    try std.testing.expectEqual(@as(usize, f.len), got.next);
    try std.testing.expectEqualSlices(u8, &p, got.payload);
}

test "empty frame roundtrip" {
    const alloc = std.testing.allocator;
    const f = try frameEncode(alloc, &[_]u8{});
    defer alloc.free(f);
    const got = frameNext(f, 0).?;
    try std.testing.expectEqual(@as(usize, f.len), got.next);
    try std.testing.expectEqual(@as(usize, 0), got.payload.len);
}

test "crc tamper rejected" {
    const alloc = std.testing.allocator;
    const f = try frameEncode(alloc, &[_]u8{ 1, 2, 3 });
    defer alloc.free(f);
    f[4] +%= 1; // tamper payload[0]
    try std.testing.expect(frameNext(f, 0) == null);
}

test "frameSkip matches length" {
    const alloc = std.testing.allocator;
    const f = try frameEncode(alloc, &[_]u8{ 1, 2, 3 });
    defer alloc.free(f);
    try std.testing.expectEqual(@as(usize, f.len), frameSkip(f, 0).?);
}

test "out of bounds" {
    const alloc = std.testing.allocator;
    const f = try frameEncode(alloc, &[_]u8{ 1, 2, 3 });
    defer alloc.free(f);
    try std.testing.expect(frameNext(f, f.len) == null);
    try std.testing.expect(frameSkip(f, f.len) == null);
}