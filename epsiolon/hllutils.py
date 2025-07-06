import math
import struct
from typing import List


def murmurhash64a(key: bytes, seed: int) -> int:
    m = 0xc6a4a7935bd1e995
    r = 47
    h = seed ^ (len(key) * m)
    data = key
    length = len(data)
    nblocks = length // 8

    for i in range(nblocks):
        k = struct.unpack_from('<Q', data, i * 8)[0]
        k *= m
        k ^= k >> r
        k *= m

        h ^= k
        h *= m

    tail = data[nblocks * 8:]
    remaining = len(tail)
    if remaining:
        for i in range(remaining):
            h ^= tail[i] << (i * 8)
        h *= m

    h ^= h >> r
    h *= m
    h ^= h >> r

    return h & 0xFFFFFFFFFFFFFFFF  # simulate 64-bit unsigned


def insertion_sort(arr: List[int]) -> None:
    for i in range(1, len(arr)):
        value = arr[i]
        j = i
        while j > 0 and value < arr[j - 1]:
            arr[j] = arr[j - 1]
            j -= 1
        arr[j] = value


def dedupe(sparse_data: List[int]) -> int:
    n = len(sparse_data)

    for i in range(n - 1):
        if sparse_data[i] > sparse_data[i + 1]:
            insertion_sort(sparse_data)
            break

    j = 1
    for i in range(1, n):
        if sparse_data[i] != sparse_data[j - 1]:
            sparse_data[j] = sparse_data[i]
            j += 1

    for i in range(j, n):
        sparse_data[i] = 0

    return j


def size_sparse_array(b: int) -> int:
    return 2 ** (b - 4) - math.ceil(HLLData.SIZE / 4.0)


# Simulate HLLData size (adjust based on actual structure if needed)
class HLLData:
    SIZE = 16  # Placeholder for sizeof(HLLData) in bytes


# PGLZ wrappers are placeholders — Python has no direct PGLZ support
def pg_decompress(source: bytes, rawsize: int) -> bytes:
    raise NotImplementedError("PGLZ decompression is PostgreSQL-specific and not available in Python")


def pg_compress(source: bytes, strategy=None) -> bytes:
    raise NotImplementedError("PGLZ compression is PostgreSQL-specific and not available in Python")


# --- Example usage ---
if __name__ == "__main__":
    key = b"example"
    hashed = murmurhash64a(key, seed=12345)
    print("Hashed:", hashed)

    sparse = [5, 3, 3, 2, 8, 1]
    count = dedupe(sparse)
    print("Dedupe result:", sparse[:count])
    print("Sparse array size (b=12):", size_sparse_array(12))
