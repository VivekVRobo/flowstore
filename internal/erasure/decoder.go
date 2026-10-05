package erasure

import (
	"bytes"
	"errors"
	"fmt"

	"lukechampine.com/blake3"
)

var (
	ErrInsufficientShards = errors.New("insufficient shards for reconstruction: need at least 6 surviving shards")
	ErrCorruptShard       = errors.New("shard failed BLAKE3 checksum verification")
	ErrInvalidShardIndex  = errors.New("shard index out of bounds")
)

// Decode accepts any subset of surviving shards and recovers the exact original payload.
func (e *Engine) Decode(surviving []Shard) ([]byte, error) {
	reconstructedShards, originalSize, err := e.reconstructAll(surviving)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := e.rs.Join(&buf, reconstructedShards, int(originalSize)); err != nil {
		return nil, fmt.Errorf("failed to join reconstructed shards: %w", err)
	}

	return buf.Bytes(), nil
}

// ReconstructMissing identifies any missing shards from a surviving set,
// reconstructs them using Reed-Solomon, and returns the missing Shards ready for peer redistribution.
func (e *Engine) ReconstructMissing(surviving []Shard) ([]Shard, error) {
	reconstructedRaw, originalSize, err := e.reconstructAll(surviving)
	if err != nil {
		return nil, err
	}

	present := make(map[uint8]bool)
	for _, s := range surviving {
		present[s.Index] = true
	}

	var missing []Shard
	for i := 0; i < e.TotalShards(); i++ {
		idx := uint8(i)
		if !present[idx] {
			data := reconstructedRaw[i]
			missing = append(missing, Shard{
				Index:        idx,
				Data:         data,
				Checksum:     blake3.Sum256(data),
				OriginalSize: originalSize,
			})
		}
	}

	return missing, nil
}

// reconstructAll fills in missing shards and verifies the complete set.
func (e *Engine) reconstructAll(surviving []Shard) ([][]byte, uint64, error) {
	total := e.TotalShards()
	rawShards := make([][]byte, total)

	validCount := 0
	var originalSize uint64

	for _, s := range surviving {
		if int(s.Index) >= total {
			return nil, 0, fmt.Errorf("%w: index %d >= total %d", ErrInvalidShardIndex, s.Index, total)
		}

		// Verify checksum
		actual := blake3.Sum256(s.Data)
		if actual != s.Checksum {
			return nil, 0, fmt.Errorf("%w: shard %d checksum mismatch", ErrCorruptShard, s.Index)
		}

		rawShards[s.Index] = append([]byte(nil), s.Data...)
		validCount++
		if originalSize == 0 {
			originalSize = s.OriginalSize
		}
	}

	if validCount < e.dataShards {
		return nil, 0, fmt.Errorf("%w: have %d valid, need %d", ErrInsufficientShards, validCount, e.dataShards)
	}

	// If any shard is missing, reconstruct
	if validCount < total {
		if err := e.rs.Reconstruct(rawShards); err != nil {
			return nil, 0, fmt.Errorf("reed-solomon reconstruction failed: %w", err)
		}
	}

	// Verify all shards are mathematically consistent
	ok, err := e.rs.Verify(rawShards)
	if err != nil || !ok {
		return nil, 0, fmt.Errorf("erasure verification failed after reconstruction: %w", err)
	}

	return rawShards, originalSize, nil
}
