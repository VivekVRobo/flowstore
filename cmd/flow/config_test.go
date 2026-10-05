package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFlowstoreConfigDirOverride(t *testing.T) {
	want, err := filepath.Abs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(configDirEnv, want)

	got, err := flowstoreConfigDir()
	if err != nil {
		t.Fatalf("flowstoreConfigDir returned error: %v", err)
	}
	if got != want {
		t.Fatalf("flowstoreConfigDir() = %q, want %q", got, want)
	}
}

func TestFlowstoreConfigDirDefaultsUnderUserHome(t *testing.T) {
	t.Setenv(configDirEnv, "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}

	got, err := flowstoreConfigDir()
	if err != nil {
		t.Fatalf("flowstoreConfigDir returned error: %v", err)
	}
	want := filepath.Join(home, ".flowstore")
	if got != want {
		t.Fatalf("flowstoreConfigDir() = %q, want %q", got, want)
	}
}
