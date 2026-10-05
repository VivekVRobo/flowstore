package erasure

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func TestEncodeDecodeRoundtrip(t *testing.T) {
	engine, err := DefaultEngine()
	if err != nil {
		t.Fatalf("DefaultEngine failed: %v", err)
	}

	payload := make([]byte, 1024*1024) // 1 MiB test payload
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		t.Fatal(err)
	}

	shards, err := engine.Encode(payload)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if len(shards) != 10 {
		t.Fatalf("expected 10 shards, got %d", len(shards))
	}

	// Direct decode with all 10 shards
	recovered, err := engine.Decode(shards)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if !bytes.Equal(payload, recovered) {
		t.Fatal("recovered payload does not match original")
	}
}

func TestCombinatorialFourShardLoss(t *testing.T) {
	engine, err := DefaultEngine()
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("FlowStore 6+4 Reed-Solomon combinatorial test payload covering every drop combination.")
	shards, err := engine.Encode(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Total combinations of dropping 4 shards out of 10: 10! / (4! * 6!) = 210
	totalCombinations := 0
	for i := 0; i < 10; i++ {
		for j := i + 1; j < 10; j++ {
			for k := j + 1; k < 10; k++ {
				for l := k + 1; l < 10; l++ {
					totalCombinations++
					dropped := map[int]bool{i: true, j: true, k: true, l: true}

					var surviving []Shard
					for idx, s := range shards {
						if !dropped[idx] {
							surviving = append(surviving, s)
						}
					}

					recovered, err := engine.Decode(surviving)
					if err != nil {
						t.Fatalf("combination (%d,%d,%d,%d) failed reconstruction: %v", i, j, k, l, err)
					}
					if !bytes.Equal(payload, recovered) {
						t.Fatalf("combination (%d,%d,%d,%d) recovered payload mismatch", i, j, k, l)
					}
				}
			}
		}
	}

	if totalCombinations != 210 {
		t.Fatalf("expected 210 combinations, ran %d", totalCombinations)
	}
	t.Logf("Successfully verified all %d 4-shard loss permutations!", totalCombinations)
}

func TestInsufficientShardsRejection(t *testing.T) {
	engine, err := DefaultEngine()
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("Insufficient shards test")
	shards, err := engine.Encode(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Keep only 5 shards (5 lost)
	surviving := shards[:5]
	_, err = engine.Decode(surviving)
	if !errors.Is(err, ErrInsufficientShards) {
		t.Fatalf("expected ErrInsufficientShards, got: %v", err)
	}
}

func TestCorruptShardDetection(t *testing.T) {
	engine, err := DefaultEngine()
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("Integrity verification test payload")
	shards, err := engine.Encode(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt shard 2
	shards[2].Data[0] ^= 0xFF

	if VerifyShard(shards[2]) {
		t.Fatal("VerifyShard returned true for corrupt shard")
	}

	// Decode should reject the corrupted shard
	_, err = engine.Decode(shards)
	if !errors.Is(err, ErrCorruptShard) {
		t.Fatalf("expected ErrCorruptShard, got: %v", err)
	}
}

func TestReconstructMissingShards(t *testing.T) {
	engine, err := DefaultEngine()
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("Self-healing Swarm: reconstruct missing shards for new peer placement.")
	shards, err := engine.Encode(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Drop shards 1, 4, 7, 9 (4 missing)
	dropped := map[int]bool{1: true, 4: true, 7: true, 9: true}
	var surviving []Shard
	for idx, s := range shards {
		if !dropped[idx] {
			surviving = append(surviving, s)
		}
	}

	missing, err := engine.ReconstructMissing(surviving)
	if err != nil {
		t.Fatalf("ReconstructMissing failed: %v", err)
	}

	if len(missing) != 4 {
		t.Fatalf("expected 4 missing shards, got %d", len(missing))
	}

	// Check each reconstructed shard matches the original
	for _, m := range missing {
		orig := shards[m.Index]
		if !bytes.Equal(orig.Data, m.Data) {
			t.Fatalf("reconstructed shard %d data does not match original", m.Index)
		}
		if orig.Checksum != m.Checksum {
			t.Fatalf("reconstructed shard %d checksum does not match original", m.Index)
		}
	}
}
