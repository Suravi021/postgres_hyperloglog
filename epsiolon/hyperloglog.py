import math
import struct
import hashlib
from typing import List, Optional, Union
from enum import IntEnum
import zlib

class HLLFormat(IntEnum):
    PACKED = 0
    UNPACKED = 1
    PACKED_UNPACKED = 2
    UNPACKED_UNPACKED = 3

class HLLCounter:
    """HyperLogLog counter implementation in Python"""
    
    def __init__(self, ndistinct: float, error: float, format_type: HLLFormat = HLLFormat.PACKED):
        """
        Initialize HLL counter
        
        Args:
            ndistinct: Expected number of distinct elements
            error: Target error rate (0-1)
            format_type: Storage format
        """
        # Constants
        self.STRUCT_VERSION = 1
        self.MIN_INDEX_BITS = 4
        self.MAX_INDEX_BITS = 20
        self.MIN_BINBITS = 4
        self.MAX_BINBITS = 8
        self.ERROR_CONST = 1.04
        self.HASH_SEED = 0x12345678
        self.HASH_LENGTH = 64
        
        # Validation
        if error <= 0 or error >= 1:
            raise ValueError("Invalid error rate - only values in (0,1) allowed")
            
        if (self.MIN_BINBITS >= math.ceil(math.log2(math.log2(ndistinct))) or 
            self.MAX_BINBITS <= math.ceil(math.log2(math.log2(ndistinct)))):
            raise ValueError("Invalid ndistinct - must be between 257 and 1.1579 * 10^77")
        
        # Initialize counter properties
        self.version = self.STRUCT_VERSION
        self.format = format_type
        
        # Calculate required parameters
        m = self.ERROR_CONST / (error * error)
        self.b = max(self.MIN_INDEX_BITS, min(self.MAX_INDEX_BITS, math.ceil(math.log2(m))))
        self.binbits = math.ceil(math.log2(math.log2(ndistinct)))
        
        # Start with sparse representation
        self.idx = 0  # Index for sparse data (-1 indicates dense)
        self.data = []  # Data storage
        self.compressed = False
        
        # Pre-computed constants for estimation
        self._init_constants()
    
    def _init_constants(self):
        """Initialize constants for HLL estimation"""
        # Alpha constants for bias correction
        self.alpha = {
            4: 0.673,
            5: 0.697,
            6: 0.709,
            7: 0.715
        }
        
        # For b >= 8, alpha = 0.7213 / (1 + 1.079 / m)
        if self.b >= 8:
            m = 2 ** self.b
            self.alpha[self.b] = 0.7213 / (1 + 1.079 / m)
        elif self.b not in self.alpha:
            self.alpha[self.b] = 0.715  # Default fallback
    
    def _murmurhash64a(self, data: bytes, seed: int = None) -> int:
        """
        Simplified MurmurHash64A implementation
        For production use, consider using a proper hash library
        """
        if seed is None:
            seed = self.HASH_SEED
            
        # Use Python's built-in hash for simplicity
        # In production, use a proper MurmurHash implementation
        hash_obj = hashlib.sha256(data + seed.to_bytes(8, 'big'))
        return int.from_bytes(hash_obj.digest()[:8], 'big')
    
    def _count_leading_zeros(self, x: int, max_bits: int = 64) -> int:
        """Count leading zeros in binary representation"""
        if x == 0:
            return max_bits
        return max_bits - x.bit_length()
    
    def _get_sparse_size(self) -> int:
        """Get size for sparse array"""
        return 2 ** (self.b - 2)
    
    def add_element(self, element: Union[str, bytes]) -> 'HLLCounter':
        """Add an element to the HLL counter"""
        if isinstance(element, str):
            element = element.encode('utf-8')
        
        # Compute hash
        hash_val = self._murmurhash64a(element)
        
        # Add hash to counter
        if self.idx == -1:  # Dense representation
            self._add_hash_dense(hash_val)
        else:  # Sparse representation
            self._add_hash_sparse(hash_val)
        
        return self
    
    def _add_hash_dense(self, hash_val: int):
        """Add hash to dense representation"""
        # Get index from first b bits
        idx = hash_val >> (self.HASH_LENGTH - self.b)
        
        # Get rho (number of leading zeros + 1)
        rho = self._count_leading_zeros(hash_val << self.b, self.HASH_LENGTH - self.b) + 1
        
        # Handle case where all remaining bits are zero
        if rho == self.HASH_LENGTH - self.b + 1:
            # Rehash to get more bits
            additional_bits = 0
            temp_hash = hash_val
            while additional_bits == 0 and rho < 2 ** self.binbits:
                temp_hash = self._murmurhash64a(temp_hash.to_bytes(8, 'big'))
                additional_bits = self._count_leading_zeros(temp_hash) + 1
                rho += additional_bits
        
        # Ensure we have dense storage
        if len(self.data) < 2 ** self.b:
            self.data.extend([0] * (2 ** self.b - len(self.data)))
        
        # Keep maximum value
        self.data[idx] = max(self.data[idx], rho)
    
    def _add_hash_sparse(self, hash_val: int):
        """Add hash to sparse representation"""
        encoded_hash = self._encode_hash(hash_val)
        self.data.append(encoded_hash)
        self.idx += 1
        
        # Check if we need to promote to dense
        if self.idx > self._get_sparse_size():
            self._dedupe_sparse()
            if self.idx > self._get_sparse_size() * 7 // 8:
                self._sparse_to_dense()
    
    def _encode_hash(self, hash_val: int) -> int:
        """Encode hash for sparse representation"""
        # Simplified encoding - in practice this would be more complex
        # This is a placeholder implementation
        return hash_val & 0xFFFFFFFF
    
    def _dedupe_sparse(self):
        """Remove duplicates from sparse data"""
        if self.idx > 0:
            unique_data = list(set(self.data[:self.idx]))
            self.data = unique_data
            self.idx = len(unique_data)
    
    def _sparse_to_dense(self):
        """Convert from sparse to dense representation"""
        # Create dense array
        dense_data = [0] * (2 ** self.b)
        
        # Process each sparse element
        for encoded_hash in self.data[:self.idx]:
            # Decode hash to get index and rho
            # This is simplified - actual implementation would decode properly
            idx = encoded_hash >> (32 - self.b)
            rho = self._count_leading_zeros(encoded_hash << self.b, 32 - self.b) + 1
            
            # Keep maximum value
            dense_data[idx] = max(dense_data[idx], rho)
        
        # Switch to dense representation
        self.data = dense_data
        self.idx = -1
        
        # Update format
        if self.format == HLLFormat.PACKED:
            self.format = HLLFormat.UNPACKED
        elif self.format == HLLFormat.PACKED_UNPACKED:
            self.format = HLLFormat.UNPACKED_UNPACKED
    
    def estimate(self) -> float:
        """Estimate cardinality"""
        if self.idx == -1:  # Dense representation
            return self._estimate_dense()
        else:  # Sparse representation
            return self._estimate_sparse()
    
    def _estimate_dense(self) -> float:
        """Estimate cardinality for dense representation"""
        m = 2 ** self.b
        
        # Calculate harmonic mean
        harmonic_sum = sum(2 ** (-x) for x in self.data)
        
        # Raw estimate
        raw_estimate = self.alpha[self.b] * (m * m) / harmonic_sum
        
        # Apply small range correction
        if raw_estimate <= 2.5 * m:
            # Count zeros for linear counting
            zeros = self.data.count(0)
            if zeros != 0:
                linear_estimate = m * math.log(m / zeros)
                # Use appropriate threshold logic here
                return linear_estimate
        
        # Apply large range correction
        if raw_estimate <= (1.0/30.0) * (2 ** 32):
            return raw_estimate
        else:
            return -2 ** 32 * math.log(1 - raw_estimate / (2 ** 32))
    
    def _estimate_sparse(self) -> float:
        """Estimate cardinality for sparse representation"""
        # Use linear counting for sparse representation
        self._dedupe_sparse()
        
        # Total possible values in the space
        m = 2 ** (32 - 1 - self.binbits)
        
        # Number of observed values
        v = self.idx
        
        # Linear counting estimate
        if v == 0:
            return 0.0
        
        return m * math.log(m / (m - v))
    
    def merge(self, other: 'HLLCounter') -> 'HLLCounter':
        """Merge two HLL counters"""
        # Compatibility check
        if self.b != other.b:
            raise ValueError(f"Index size differs ({self.b} != {other.b})")
        if self.binbits != other.binbits:
            raise ValueError(f"Bin size differs ({self.binbits} != {other.binbits})")
        
        # Create result counter
        result = HLLCounter.__new__(HLLCounter)
        result.__dict__.update(self.__dict__)
        result.data = self.data.copy()
        
        # Merge logic
        if result.idx == -1 and other.idx == -1:
            # Both dense
            for i in range(len(result.data)):
                result.data[i] = max(result.data[i], other.data[i])
        elif result.idx == -1:
            # Self is dense, other is sparse
            for encoded_hash in other.data[:other.idx]:
                # Decode and merge (simplified)
                idx = encoded_hash >> (32 - result.b)
                rho = max(1, self._count_leading_zeros(encoded_hash << result.b, 32 - result.b) + 1)
                result.data[idx] = max(result.data[idx], rho)
        elif other.idx == -1:
            # Self is sparse, other is dense
            result._sparse_to_dense()
            for i in range(len(result.data)):
                result.data[i] = max(result.data[i], other.data[i])
        else:
            # Both sparse
            result.data.extend(other.data[:other.idx])
            result.idx += other.idx
            
            # Check if promotion needed
            if result.idx > result._get_sparse_size():
                result._dedupe_sparse()
                if result.idx > result._get_sparse_size() * 7 // 8:
                    result._sparse_to_dense()
        
        return result
    
    def copy(self) -> 'HLLCounter':
        """Create a copy of the counter"""
        new_counter = HLLCounter.__new__(HLLCounter)
        new_counter.__dict__.update(self.__dict__)
        new_counter.data = self.data.copy()
        return new_counter
    
    def reset(self):
        """Reset the counter"""
        if self.idx == -1:
            self.data = [0] * len(self.data)
        else:
            self.data = []
            self.idx = 0
    
    def compress(self) -> 'HLLCounter':
        """Compress the counter data"""
        if self.compressed:
            return self
        
        if self.idx == -1:  # Dense
            # Convert to bytes and compress
            data_bytes = bytes(self.data)
            compressed_data = zlib.compress(data_bytes)
            
            # Only keep compression if it saves space
            if len(compressed_data) < len(data_bytes):
                self.data = compressed_data
                self.compressed = True
                self.b = -self.b  # Mark as compressed
        else:  # Sparse
            # For sparse, just dedupe
            self._dedupe_sparse()
        
        return self
    
    def decompress(self) -> 'HLLCounter':
        """Decompress the counter data"""
        if not self.compressed or self.b > 0:
            return self
        
        if self.idx == -1:  # Dense compressed
            # Decompress data
            decompressed_data = zlib.decompress(self.data)
            self.data = list(decompressed_data)
            self.compressed = False
            self.b = -self.b  # Restore positive b
        
        return self
    
    def __eq__(self, other: 'HLLCounter') -> bool:
        """Check equality of two counters"""
        if not isinstance(other, HLLCounter):
            return False
        
        # Check compatibility
        if self.b != other.b or self.binbits != other.binbits:
            return False
        
        # Compare data
        if self.idx == -1 and other.idx == -1:
            return self.data == other.data
        elif self.idx != -1 and other.idx != -1:
            self_copy = self.copy()
            other_copy = other.copy()
            self_copy._dedupe_sparse()
            other_copy._dedupe_sparse()
            return (self_copy.idx == other_copy.idx and 
                   sorted(self_copy.data[:self_copy.idx]) == sorted(other_copy.data[:other_copy.idx]))
        else:
            # Convert both to dense for comparison
            self_dense = self.copy()
            other_dense = other.copy()
            if self_dense.idx != -1:
                self_dense._sparse_to_dense()
            if other_dense.idx != -1:
                other_dense._sparse_to_dense()
            return self_dense.data == other_dense.data
    
    def get_size(self) -> int:
        """Get the size of the counter in bytes"""
        if self.idx == -1:
            return len(self.data) * 4  # Assuming 4 bytes per entry
        else:
            return len(self.data) * 4 + 64  # Base overhead + sparse data


# Example usage and testing
def main():
    # Create HLL counter
    hll = HLLCounter(10000, 0.01)
    
    # Add some elements
    elements = [f"element_{i}" for i in range(1000)]
    for element in elements:
        hll.add_element(element)
    
    # Estimate cardinality
    estimate = hll.estimate()
    print(f"Estimated cardinality: {estimate:.2f}")
    print(f"Actual cardinality: {len(set(elements))}")
    print(f"Error: {abs(estimate - len(set(elements))) / len(set(elements)) * 100:.2f}%")
    
    # Test merging
    hll2 = HLLCounter(10000, 0.01)
    elements2 = [f"element_{i}" for i in range(500, 1500)]
    for element in elements2:
        hll2.add_element(element)
    
    merged = hll.merge(hll2)
    merged_estimate = merged.estimate()
    actual_union = len(set(elements + elements2))
    
    print(f"\nMerged estimate: {merged_estimate:.2f}")
    print(f"Actual union size: {actual_union}")
    print(f"Merge error: {abs(merged_estimate - actual_union) / actual_union * 100:.2f}%")

if __name__ == "__main__":
    main()