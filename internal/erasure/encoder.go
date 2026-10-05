package erasure

import (
	"fmt"

	"github.com/klauspost/reedsolomon"
	"lukechampine.com/blake3"
)

const (
	DefaultDataShards   = 6
	DefaultParityShards = 4
	DefaultTotalShards  = DefaultDataShards + DefaultParityShards
)

// Shard represents a discrete, self-verifying erasure shard.
type Shard struct {
	Index        uint8    `json:"index"`         // Shard index: 0..5 (data), 6..9 (parity)
	Data         []byte   `json:"data"`          // Raw shard payload
	Checksum     [32]byte `json:"checksum"`      // BLAKE3 checksum of Data
	OriginalSize uint64   `json:"original_size"` // Byte length of the original pre-erasure payload
}

// Engine encapsulates Reed-Solomon encoding and reconstruction parameters.
type Engine struct {
	dataShards   int
	parityShards int
	rs           reedsolomon.Encoder
}

// NewEngine creates a new Reed-Solomon engine with specified data and parity shard counts.
func NewEngine(dataShards, parityShards int) (*Engine, error) {
	rs, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to create reed-solomon encoder: %w", err)
	}
	return &Engine{
		dataShards:   dataShards,
		parityShards: parityShards,
		rs:           rs,
	}, nil
}

// DefaultEngine creates a 6+4 Reed-Solomon engine.
func DefaultEngine() (*Engine, error) {
	return NewEngine(DefaultDataShards, DefaultParityShards)
}

// TotalShards returns total shards (data + parity).
func (e *Engine) TotalShards() int {
	return e.dataShards + e.parityShards
}

// DataShards returns data shards count.
func (e *Engine) DataShards() int {
	return e.dataShards
}

// ParityShards returns parity shards count.
func (e *Engine) ParityShards() int {
	return e.parityShards
}

// Encode splits a payload into data shards and computes parity shards.
// Returns a slice of totalShards (e.g. 10) Shard objects with BLAKE3 checksums attached.
func (e *Engine) Encode(data []byte) ([]Shard, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot encode empty data payload")
	}

	rawShards, err := e.rs.Split(data)
	if err != nil {
		return nil, fmt.Errorf("failed to split data into shards: %w", err)
	}

	if err := e.rs.Encode(rawShards); err != nil {
		return nil, fmt.Errorf("failed to encode parity shards: %w", err)
	}

	originalSize := uint64(len(data))
	total := len(rawShards)
	shards := make([]Shard, total)

	for i := 0; i < total; i++ {
		checksum := blake3.Sum256(rawShards[i])
		shards[i] = Shard{
			Index:        uint8(i),
			Data:         rawShards[i],
			Checksum:     checksum,
			OriginalSize: originalSize,
		}
	}

	return shards, nil
}
