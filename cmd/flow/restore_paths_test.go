package main

import (
	"path/filepath"
	"strings"
	"testing"

	"flowstore/internal/catalog"
)

func TestPlanRestoreTargetsUsesBasenamesForUniquePaths(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "restore")
	files := map[string]catalog.FileEntry{
		"robotics/arm-design.step": {},
		"notes/swarm-protocol.txt": {},
	}

	targets, err := planRestoreTargets(outDir, files)
	if err != nil {
		t.Fatalf("planRestoreTargets() error = %v", err)
	}
	if got, want := targets["robotics/arm-design.step"], filepath.Join(outDir, "arm-design.step"); got != want {
		t.Errorf("arm target = %q, want %q", got, want)
	}
	if got, want := targets["notes/swarm-protocol.txt"], filepath.Join(outDir, "swarm-protocol.txt"); got != want {
		t.Errorf("notes target = %q, want %q", got, want)
	}
}

func TestPlanRestoreTargetsRejectsDuplicateBasenames(t *testing.T) {
	files := map[string]catalog.FileEntry{
		"robotics/config.json": {},
		"research/config.json": {},
	}

	_, err := planRestoreTargets(t.TempDir(), files)
	if err == nil {
		t.Fatal("planRestoreTargets() accepted duplicate output basenames")
	}
	if !strings.Contains(err.Error(), "refusing to overwrite data") {
		t.Fatalf("error %q does not explain the data-loss guard", err)
	}
	if !strings.Contains(err.Error(), "robotics/config.json") || !strings.Contains(err.Error(), "research/config.json") {
		t.Fatalf("error %q does not identify both colliding catalog paths", err)
	}
}

func TestPlanRestoreTargetsRejectsUnsafeBasenames(t *testing.T) {
	for _, logicalPath := range []string{"", ".", "..", "C:", "C:/outside", "C:\\outside"} {
		t.Run(logicalPath, func(t *testing.T) {
			_, err := planRestoreTargets(t.TempDir(), map[string]catalog.FileEntry{logicalPath: {}})
			if err == nil {
				t.Fatalf("planRestoreTargets() accepted unsafe catalog path %q", logicalPath)
			}
		})
	}
}

func TestPlanRestoreTargetsRejectsNULPath(t *testing.T) {
	_, err := planRestoreTargets(t.TempDir(), map[string]catalog.FileEntry{"bad\x00name": {}})
	if err == nil {
		t.Fatal("planRestoreTargets() accepted a catalog path containing NUL")
	}
}
