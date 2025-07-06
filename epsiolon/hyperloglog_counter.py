"""
HyperLogLog implementation in Python - converted from PostgreSQL C extension

This module provides a probabilistic data structure for estimating cardinality
(number of distinct elements) in large datasets with low memory usage.
"""

import struct
import math
import hashlib
import base64
import json
from typing import Union, Optional, Any, List
from enum import Enum


class HLLFormat(Enum):
    """HyperLogLog format types"""
    PACKED = 0
    UNPACKED = 1
    PACKED_UNPACKED = 2


class HyperLogLog:
    """
    HyperLogLog probabilistic cardinality estimator
    
    This implementation mirrors the PostgreSQL extension functionality,
    providing methods for adding elements, merging counters, and estimating
    cardinality with configurable error rates.
    """
    
    # Constants matching the C implementation
    DEFAULT_NDISTINCT = 1 << 63  # 2^63 distinct items
    DEFAULT_ERROR = 0.008125     # 0.8125% error rate
    STRUCT_VERSION = 1
    MAX_INDEX_BITS = 16
    
    def __init__(self, ndistinct: float = None, error_rate: float = None, 
                 format_type: HLLFormat = HLLFormat.PACKED):
        """
        Initialize HyperLogLog counter
        
        Args:
            ndistinct: Expected number of distinct elements (default: 2^63)
            error_rate: Target error rate between 0 and 1 (default: 0.008125)
            format_type: Storage format (PACKED, UNPACKED, or PACKED_UNPACKED)
        """
        self.ndistinct = ndistinct if ndistinct is not None else self.DEFAULT_NDISTINCT
        self.error_rate = error_rate if error_rate is not None else self.DEFAULT_ERROR
        self.format = format_type
        self.version = self.STRUCT_VERSION
        
        # Validate error rate
        if not (0 < self.error_rate <= 1):
            raise ValueError("error rate has to be between 0 and 1")
            
        # Calculate parameters
        self.b = self._calculate_b()
        self.m = 1 << self.b  # 2^b buckets
        self.binbits = 4  # bits per bin
        self.idx = -1  # -1 for dense, >= 0 for sparse
        self.compressed = False
        
        # Initialize buckets
        self.buckets = [0] * self.m
        
    def _calculate_b(self) -> int:
        """Calculate the number of index bits needed"""
        # Standard HyperLogLog formula: b = log2(1.04 / error_rate)^2
        b = math.ceil(math.log2((1.04 / self.error_rate) ** 2))
        return max(4, min(b, self.MAX_INDEX_BITS))
    
    def _hash_element(self, data: bytes) -> int:
        """Hash element to get bucket index and leading zeros"""
        # Use SHA-256 for hashing (similar to PostgreSQL's approach)
        hash_obj = hashlib.sha256(data)
        hash_bytes = hash_obj.digest()
        # Convert first 8 bytes to integer
        hash_int = struct.unpack('>Q', hash_bytes[:8])[0]
        return hash_int
    
    def _get_bucket_and_value(self, hash_val: int) -> tuple:
        """Extract bucket index and value from hash"""
        # Use rightmost b bits for bucket index
        bucket = hash_val & ((1 << self.b) - 1)
        # Use remaining bits for counting leading zeros
        w = hash_val >> self.b
        # Count leading zeros + 1
        if w == 0:
            value = 64 - self.b + 1
        else:
            value = self._count_leading_zeros(w) + 1
        return bucket, min(value, 63)  # Cap at 63 to fit in 6 bits
    
    def _count_leading_zeros(self, val: int) -> int:
        """Count leading zeros in a 64-bit integer"""
        if val == 0:
            return 64
        count = 0
        # Check 32-bit chunks first
        if val >> 32 == 0:
            count += 32
            val <<= 32
        if val >> 48 == 0:
            count += 16
            val <<= 16
        if val >> 56 == 0:
            count += 8
            val <<= 8
        if val >> 60 == 0:
            count += 4
            val <<= 4
        if val >> 62 == 0:
            count += 2
            val <<= 2
        if val >> 63 == 0:
            count += 1
        return count
    
    def add_element(self, data: Union[str, bytes, int, float]) -> 'HyperLogLog':
        """
        Add an element to the HyperLogLog counter
        
        Args:
            data: Element to add (will be converted to bytes for hashing)
            
        Returns:
            Self for method chaining
        """
        # Convert data to bytes for hashing
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        elif isinstance(data, bytes):
            data_bytes = data
        elif isinstance(data, (int, float)):
            data_bytes = str(data).encode('utf-8')
        else:
            data_bytes = str(data).encode('utf-8')
            
        # Hash and get bucket/value
        hash_val = self._hash_element(data_bytes)
        bucket, value = self._get_bucket_and_value(hash_val)
        
        # Update bucket with maximum value
        self.buckets[bucket] = max(self.buckets[bucket], value)
        
        return self
    
    def merge(self, other: 'HyperLogLog') -> 'HyperLogLog':
        """
        Merge another HyperLogLog counter into this one
        
        Args:
            other: Another HyperLogLog counter to merge
            
        Returns:
            New HyperLogLog with merged data
        """
        if self.b != other.b:
            raise ValueError("Cannot merge HyperLogLog counters with different parameters")
            
        # Create new counter with merged data
        merged = HyperLogLog(self.ndistinct, self.error_rate, self.format)
        merged.b = self.b
        merged.m = self.m
        merged.buckets = [max(a, b) for a, b in zip(self.buckets, other.buckets)]
        
        return merged
    
    def estimate(self) -> float:
        """
        Estimate the cardinality (number of distinct elements)
        
        Returns:
            Estimated number of distinct elements
        """
        # Standard HyperLogLog estimation formula
        raw_estimate = self._alpha_m() * (self.m ** 2) / sum(2 ** (-x) for x in self.buckets)
        
        # Apply small range correction
        if raw_estimate <= 2.5 * self.m:
            # Count zero buckets
            zero_count = sum(1 for x in self.buckets if x == 0)
            if zero_count != 0:
                return self.m * math.log(self.m / zero_count)
        
        # Apply large range correction
        if raw_estimate <= (1.0/30.0) * (1 << 32):
            return raw_estimate
        else:
            return -1 * (1 << 32) * math.log(1 - raw_estimate / (1 << 32))
    
    def _alpha_m(self) -> float:
        """Calculate alpha constant for HyperLogLog"""
        if self.m == 16:
            return 0.673
        elif self.m == 32:
            return 0.697
        elif self.m == 64:
            return 0.709
        else:
            return 0.7213 / (1 + 1.079 / self.m)
    
    def reset(self) -> None:
        """Reset the counter to empty state"""
        self.buckets = [0] * self.m
    
    def get_size(self) -> int:
        """Get the size of the counter in bytes"""
        # Approximate size: header + buckets
        header_size = 32  # version, b, m, format, etc.
        bucket_size = len(self.buckets) * 4  # 4 bits per bucket, but stored as bytes
        return header_size + bucket_size
    
    def compress(self) -> 'HyperLogLog':
        """Compress the counter (simulation of compression)"""
        compressed = HyperLogLog(self.ndistinct, self.error_rate, self.format)
        compressed.b = -self.b if self.b > 0 else self.b  # Negative b indicates compression
        compressed.m = self.m
        compressed.buckets = self.buckets.copy()
        compressed.compressed = True
        return compressed
    
    def decompress(self) -> 'HyperLogLog':
        """Decompress the counter"""
        if not self.compressed and self.b >= 0:
            return self
            
        decompressed = HyperLogLog(self.ndistinct, self.error_rate, self.format)
        decompressed.b = abs(self.b)
        decompressed.m = self.m
        decompressed.buckets = self.buckets.copy()
        decompressed.compressed = False
        return decompressed
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            'version': self.version,
            'ndistinct': self.ndistinct,
            'error_rate': self.error_rate,
            'format': self.format.value,
            'b': self.b,
            'm': self.m,
            'buckets': self.buckets,
            'compressed': self.compressed
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'HyperLogLog':
        """Create HyperLogLog from dictionary"""
        hll = cls(data['ndistinct'], data['error_rate'], HLLFormat(data['format']))
        hll.version = data['version']
        hll.b = data['b']
        hll.m = data['m']
        hll.buckets = data['buckets']
        hll.compressed = data['compressed']
        return hll
    
    def to_base64(self) -> str:
        """Convert to base64 string (similar to hyperloglog_out)"""
        data = json.dumps(self.to_dict())
        return base64.b64encode(data.encode('utf-8')).decode('utf-8')
    
    @classmethod
    def from_base64(cls, b64_str: str) -> 'HyperLogLog':
        """Create HyperLogLog from base64 string (similar to hyperloglog_in)"""
        data = json.loads(base64.b64decode(b64_str.encode('utf-8')).decode('utf-8'))
        return cls.from_dict(data)
    
    def info(self) -> str:
        """Get counter information (similar to hyperloglog_info)"""
        comp_str = "yes" if self.compressed else "no"
        corrected_b = abs(self.b)
        
        if self.b < 0 and abs(self.b) > self.MAX_INDEX_BITS:
            corrected_b = abs(self.b) - self.MAX_INDEX_BITS
        
        encoding = "sparse" if self.idx >= 0 else "dense"
        format_str = self.format.name.lower()
        
        return f"""Counter Summary
struct version: {self.version}
size on disk (bytes): {self.get_size()}
bits per bin: {self.binbits}
index bits: {corrected_b}
number of bins: {self.m}
compressed?: {comp_str}
encoding: {encoding}
format: {format_str}
--------------------------"""
    
    def __eq__(self, other: 'HyperLogLog') -> bool:
        """Check equality with another HyperLogLog"""
        if not isinstance(other, HyperLogLog):
            return False
        return (self.b == other.b and 
                self.m == other.m and 
                self.buckets == other.buckets)
    
    def __ne__(self, other: 'HyperLogLog') -> bool:
        """Check inequality with another HyperLogLog"""
        return not self.__eq__(other)


class HyperLogLogAggregator:
    """
    Aggregator class that mimics the PostgreSQL aggregate functions
    """
    
    @staticmethod
    def create_default() -> HyperLogLog:
        """Create HyperLogLog with default parameters"""
        return HyperLogLog()
    
    @staticmethod
    def create_with_error(error_rate: float) -> HyperLogLog:
        """Create HyperLogLog with specified error rate"""
        return HyperLogLog(error_rate=error_rate)
    
    @staticmethod
    def create_with_params(error_rate: float, ndistinct: float) -> HyperLogLog:
        """Create HyperLogLog with specified parameters"""
        return HyperLogLog(ndistinct=ndistinct, error_rate=error_rate)
    
    @staticmethod
    def union(hll1: Optional[HyperLogLog], hll2: Optional[HyperLogLog]) -> float:
        """Calculate union cardinality estimate"""
        if hll1 is None and hll2 is None:
            return 0.0
        elif hll1 is None:
            return hll2.estimate()
        elif hll2 is None:
            return hll1.estimate()
        else:
            return hll1.merge(hll2).estimate()
    
    @staticmethod
    def intersection(hll1: HyperLogLog, hll2: HyperLogLog) -> float:
        """Calculate intersection cardinality estimate using inclusion-exclusion"""
        a = hll1.estimate()
        b = hll2.estimate()
        union = hll1.merge(hll2).estimate()
        return a + b - union
    
    @staticmethod
    def complement(hll1: HyperLogLog, hll2: HyperLogLog) -> float:
        """Calculate complement cardinality estimate"""
        b = hll2.estimate()
        union = hll1.merge(hll2).estimate()
        return union - b
    
    @staticmethod
    def symmetric_difference(hll1: HyperLogLog, hll2: HyperLogLog) -> float:
        """Calculate symmetric difference cardinality estimate"""
        a = hll1.estimate()
        b = hll2.estimate()
        union = hll1.merge(hll2).estimate()
        return 2 * union - a - b


# Utility functions to match the C extension API
def hll_create(ndistinct: float = None, error_rate: float = None, 
               format_type: HLLFormat = HLLFormat.PACKED) -> HyperLogLog:
    """Create a new HyperLogLog counter"""
    return HyperLogLog(ndistinct, error_rate, format_type)


def hll_add_element(hll: HyperLogLog, data: Any) -> HyperLogLog:
    """Add an element to HyperLogLog counter"""
    return hll.add_element(data)


def hll_merge(hll1: HyperLogLog, hll2: HyperLogLog) -> HyperLogLog:
    """Merge two HyperLogLog counters"""
    return hll1.merge(hll2)


def hll_estimate(hll: HyperLogLog) -> float:
    """Get cardinality estimate from HyperLogLog"""
    return hll.estimate()


def hll_get_size(ndistinct: float = None, error_rate: float = None) -> int:
    """Get the size needed for HyperLogLog with given parameters"""
    temp_hll = HyperLogLog(ndistinct, error_rate)
    return temp_hll.get_size()


# Example usage and testing
if __name__ == "__main__":
    # Create HyperLogLog with default parameters
    hll = HyperLogLog()
    
    # Add some elements
    for i in range(1000):
        hll.add_element(f"element_{i}")
    
    # Get estimate
    print(f"Estimated cardinality: {hll.estimate()}")
    print(f"Actual cardinality: 1000")
    print(f"Error: {abs(hll.estimate() - 1000) / 1000 * 100:.2f}%")
    
    # Create another HyperLogLog and merge
    hll2 = HyperLogLog()
    for i in range(500, 1500):
        hll2.add_element(f"element_{i}")
    
    merged = hll.merge(hll2)
    print(f"Merged estimate: {merged.estimate()}")
    print(f"Expected (union): 1500")
    
    # Test set operations
    intersection = HyperLogLogAggregator.intersection(hll, hll2)
    print(f"Intersection estimate: {intersection}")
    print(f"Expected intersection: 500")
    
    # Print counter info
    print("\n" + hll.info())
    
    # Test serialization
    b64_str = hll.to_base64()
    restored_hll = HyperLogLog.from_base64(b64_str)
    print(f"Serialization test - Original: {hll.estimate()}, Restored: {restored_hll.estimate()}")