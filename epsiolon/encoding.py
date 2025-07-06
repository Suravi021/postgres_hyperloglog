_base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
b64lookup = [-1] * 128

# Fill the lookup table as per C array
for i, c in enumerate(_base64):
    b64lookup[ord(c)] = i


def hll_b64_encode(src: bytes) -> str:
    dst = []
    buf = 0
    pos = 2
    line_len = 76
    count = 0

    for b in src:
        buf |= b << (pos * 8)
        pos -= 1

        if pos < 0:
            dst.append(_base64[(buf >> 18) & 0x3F])
            dst.append(_base64[(buf >> 12) & 0x3F])
            dst.append(_base64[(buf >> 6) & 0x3F])
            dst.append(_base64[buf & 0x3F])
            buf = 0
            pos = 2
            count += 4

            if count >= line_len:
                dst.append('\n')
                count = 0

    if pos != 2:
        dst.append(_base64[(buf >> 18) & 0x3F])
        dst.append(_base64[(buf >> 12) & 0x3F])
        if pos == 0:
            dst.append(_base64[(buf >> 6) & 0x3F])
        else:
            dst.append('=')
        dst.append('=')

    return ''.join(dst)


def hll_b64_decode(src: str) -> bytes:
    dst = bytearray()
    buf = 0
    pos = 0
    end = 0

    for c in src:
        if c in ' \t\r\n':
            continue
        elif c == '=':
            if not end:
                if pos == 2:
                    end = 1
                elif pos == 3:
                    end = 2
                else:
                    raise ValueError('unexpected "="')
            b = 0
        else:
            if ord(c) >= 128 or b64lookup[ord(c)] == -1:
                raise ValueError('invalid symbol')
            b = b64lookup[ord(c)]

        buf = (buf << 6) + b
        pos += 1

        if pos == 4:
            dst.append((buf >> 16) & 0xFF)
            if end == 0 or end > 1:
                dst.append((buf >> 8) & 0xFF)
            if end == 0 or end > 2:
                dst.append(buf & 0xFF)
            buf = 0
            pos = 0

    if pos != 0:
        raise ValueError('invalid end sequence')

    return bytes(dst)


def b64_enc_len(srclen: int) -> int:
    # Same logic as: (srclen + 2) * 4 // 3 + srclen // (76 * 3 // 4)
    return ((srclen + 2) * 4 // 3) + (srclen // 57)


def b64_dec_len(srclen: int) -> int:
    return (srclen * 3) >> 2


# --- Example usage ---
if __name__ == "__main__":
    raw = b"Hello, PostgreSQL-like base64!"
    encoded = hll_b64_encode(raw)
    decoded = hll_b64_decode(encoded)

    print("Encoded:\n", encoded)
    print("Decoded:\n", decoded)
