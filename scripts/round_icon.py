#!/usr/bin/env python3
"""Place an 824px square image on a 1024px transparent canvas with rounded corners (stdlib only)."""
import struct, sys, zlib

def read_png(path):
    data = open(path, "rb").read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    pos, idat, w = 8, b"", 0
    while pos < len(data):
        n = struct.unpack(">I", data[pos:pos+4])[0]; kind = data[pos+4:pos+8]; body = data[pos+8:pos+8+n]; pos += 12 + n
        if kind == b"IHDR":
            w, h, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", body)
            assert depth == 8 and ctype in (2, 6) and interlace == 0, (depth, ctype, interlace)
            bpp = 3 if ctype == 2 else 4
        elif kind == b"IDAT":
            idat += body
    raw = zlib.decompress(idat); stride = w * bpp; rows = []; prev = bytearray(stride); i = 0
    for _ in range(h):
        f = raw[i]; line = bytearray(raw[i+1:i+1+stride]); i += 1 + stride
        for x in range(stride):
            a = line[x-bpp] if x >= bpp else 0; b = prev[x]; c = prev[x-bpp] if x >= bpp else 0
            if f == 1: line[x] = (line[x] + a) & 255
            elif f == 2: line[x] = (line[x] + b) & 255
            elif f == 3: line[x] = (line[x] + (a + b) // 2) & 255
            elif f == 4:
                p = a + b - c; pa, pb, pc = abs(p-a), abs(p-b), abs(p-c)
                line[x] = (line[x] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        rows.append(line); prev = line
    return w, h, bpp, rows

def write_png(path, w, h, rows):
    raw = b"".join(b"\x00" + bytes(r) for r in rows)
    def chunk(k, d): return struct.pack(">I", len(d)) + k + d + struct.pack(">I", zlib.crc32(k + d) & 0xffffffff)
    open(path, "wb").write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
                           + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))

src, out = sys.argv[1], sys.argv[2]
w, h, bpp, rows = read_png(src)
CANVAS, BODY, R = 1024, w, 185  # Apple grid: 824px body, ~185px corner radius
off = (CANVAS - BODY) // 2
def coverage(x, y):  # 4x4 supersampled rounded-rect coverage for pixel (x, y) of the body
    inside = 0
    for sy in range(4):
        for sx in range(4):
            px, py = x + (sx + .5) / 4, y + (sy + .5) / 4
            cx = min(max(px, R), BODY - R); cy = min(max(py, R), BODY - R)
            inside += (px - cx) ** 2 + (py - cy) ** 2 <= R * R
    return inside / 16
out_rows = [bytearray(CANVAS * 4) for _ in range(CANVAS)]
for y in range(BODY):
    src_row = rows[y]; dst = out_rows[y + off]
    near_y = y < R or y >= BODY - R
    for x in range(BODY):
        r, g, b = src_row[x*bpp:x*bpp+3]
        a = coverage(x, y) if near_y and (x < R or x >= BODY - R) else 1.0
        i = (x + off) * 4; dst[i:i+4] = bytes((r, g, b, round(255 * a)))
write_png(out, CANVAS, CANVAS, out_rows)
print("ok", out)
