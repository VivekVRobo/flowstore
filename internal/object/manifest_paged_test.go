package object

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"flowstore/internal/crypto"
	"flowstore/internal/erasure"
)

func TestPagedManifestRoundtrip(t *testing.T) {
	secret, _ := crypto.GenerateMasterSecret()
	kr, _ := crypto.DeriveKeyring(secret)
	p, err := NewPipeline(kr, 32*1024, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 100*1024)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		t.Fatal(err)
	}
	// Collect chunks in memory for getter; pages encrypted via pageSink.
	shardStore := make(map[string]erasure.Shard)
	var pages [][]byte
	header, err := p.IngestStreamPaged(bytes.NewReader(payload), "big/file.bin", 2,
		func(chunk EncodedChunk) error {
			for i, s := range chunk.Shards {
				shardStore[chunk.Ref.Shards[i].RoutingID] = s
			}
			return nil
		},
		func(pageIndex uint32, enc []byte) error {
			pages = append(pages, enc)
			return nil
		})
	if err != nil {
		t.Fatalf("IngestStreamPaged failed: %v", err)
	}
	if header.ChunkCount != 4 {
		t.Fatalf("expected 4 chunks for 100KiB/32KiB, got %d", header.ChunkCount)
	}
	if header.PageCount != 2 {
		t.Fatalf("expected 2 pages with pageSize 2, got %d", header.PageCount)
	}
	if uint32(len(pages)) != header.PageCount {
		t.Fatalf("expected %d encrypted pages, got %d", header.PageCount, len(pages))
	}
	getter := func(routingID string) (*erasure.Shard, error) {
		s, ok := shardStore[routingID]
		if !ok {
			return nil, erasure.ErrInsufficientShards
		}
		c := s
		return &c, nil
	}
	loader := func(idx uint32) (*ManifestPage, error) {
		return UnmarshalEncryptedPage(pages[idx], kr.CatalogKey[:])
	}
	var out bytes.Buffer
	if err := p.ReconstructPaged(&out, header, loader, getter); err != nil {
		t.Fatalf("ReconstructPaged failed: %v", err)
	}
	if !bytes.Equal(payload, out.Bytes()) {
		t.Fatal("paged reconstruction mismatch")
	}
}

func TestSplitJoinManifest(t *testing.T) {
	secret, _ := crypto.GenerateMasterSecret()
	kr, _ := crypto.DeriveKeyring(secret)
	p, _ := NewPipeline(kr, 16*1024, 0)
	payload := make([]byte, 40*1024)
	io.ReadFull(rand.Reader, payload)
	m, _, err := p.Ingest(bytes.NewReader(payload), "a.bin")
	if err != nil {
		t.Fatal(err)
	}
	header, pages := SplitManifest(m, 2)
	if header.ChunkCount != uint32(len(m.Chunks)) {
		t.Fatal("header count mismatch")
	}
	joined, err := JoinPages(header, pages)
	if err != nil {
		t.Fatal(err)
	}
	if len(joined.Chunks) != len(m.Chunks) || joined.ObjectID != m.ObjectID {
		t.Fatal("join mismatch")
	}
	// Page encrypt roundtrip.
	for _, pg := range pages {
		enc, err := MarshalEncryptedPage(pg, kr.CatalogKey[:])
		if err != nil {
			t.Fatal(err)
		}
		dec, err := UnmarshalEncryptedPage(enc, kr.CatalogKey[:])
		if err != nil {
			t.Fatal(err)
		}
		if dec.PageIndex != pg.PageIndex || len(dec.Chunks) != len(pg.Chunks) {
			t.Fatal("page roundtrip mismatch")
		}
	}
}
