package erasure

import (
	"errors"
	"fmt"

	"lukechampine.com/blake3"
)

// VerifyShard checks whether the shard's BLAKE3 checksum matches its internal payload.
func VerifyShard(s Shard) bool {
	sum := blake3.Sum256(s.Data)
	return sum == s.Checksum
}

// ValidateShardBatch validates an entire collection of shards before passing to the decoder.
func ValidateShardBatch(shards []Shard, expectedTotal int) error {
	if len(shards) == 0 {
		return errors.New("empty shard batch")
	}

	seenIndices := make(map[uint8]bool)
	for _, s := range shards {
		if int(s.Index) >= expectedTotal {
			return fmt.Errorf("shard index %d out of bounds (max %d)", s.Index, expectedTotal-1)
		}
		if seenIndices[s.Index] {
			return fmt.Errorf("duplicate shard index detected: %d", s.Index)
		}
		seenIndices[s.Index] = true

		if !VerifyShard(s) {
			return fmt.Errorf("shard %d failed cryptographic integrity check", s.Index)
		}
	}
	return nil
}
