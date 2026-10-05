package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"flowstore/internal/crypto"
	"flowstore/internal/object"
)

func TestIngestFailureDoesNotReplaceCommittedManifest(t *testing.T) {
	masterSecret, err := crypto.GenerateMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := crypto.DeriveKeyring(masterSecret)
	if err != nil {
		t.Fatal(err)
	}
	pipeline, err := object.NewPipeline(keyring, 1024, 0)
	if err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(t.TempDir(), "snapshot.flowmanifest.enc")
	priorManifest := []byte("previous committed manifest")
	if err := os.WriteFile(manifestPath, priorManifest, 0600); err != nil {
		t.Fatal(err)
	}

	storeErr := errors.New("simulated shard storage failure")
	sinkCalls := 0
	manifest, err := ingestAndCommitManifest(
		context.Background(),
		pipeline,
		bytes.NewReader(bytes.Repeat([]byte("x"), 3*1024)),
		"snapshot.qcow2",
		manifestPath,
		keyring.CatalogKey[:],
		func(chunk object.EncodedChunk) error {
			sinkCalls++
			if chunk.Ref.Index == 1 {
				return storeErr
			}
			return nil
		},
	)
	if !errors.Is(err, storeErr) {
		t.Fatalf("ingest error = %v, want wrapped storage failure", err)
	}
	if manifest != nil {
		t.Fatalf("failed ingest returned a manifest: %+v", manifest)
	}
	if sinkCalls != 2 {
		t.Fatalf("sink called %d times, want failure on second chunk", sinkCalls)
	}

	gotManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("committed manifest disappeared after failed ingest: %v", err)
	}
	if !bytes.Equal(gotManifest, priorManifest) {
		t.Fatalf("failed ingest replaced the prior manifest: got %q, want %q", gotManifest, priorManifest)
	}
}
