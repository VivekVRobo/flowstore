package snapshot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"lukechampine.com/blake3"
)

const FormatVersion = 1

// BlockExtent records a data or explicit-zero range stored in the source image
// itself (depth zero in qemu-img map). For a qcow2 overlay this is the changed
// block set relative to its backing image.
type BlockExtent struct {
	Offset uint64 `json:"offset"`
	Length uint64 `json:"length"`
	Zero   bool   `json:"zero,omitempty"`
}

// Descriptor records the captured disk's portable properties and its changed
// block map. FlowStore encrypts this descriptor when it is ingested.
type Descriptor struct {
	FormatVersion int           `json:"format_version"`
	CapturedAt    time.Time     `json:"captured_at"`
	SourceFormat  string        `json:"source_format"`
	OutputFormat  string        `json:"output_format"`
	VirtualSize   uint64        `json:"virtual_size"`
	ImageSize     int64         `json:"image_size"`
	ImageBLAKE3   string        `json:"image_blake3"`
	ChangedBlocks []BlockExtent `json:"changed_blocks"`
	FlowObjectID  string        `json:"flow_object_id,omitempty"`
}

type imageInfo struct {
	Format      string `json:"format"`
	VirtualSize uint64 `json:"virtual-size"`
}

type mapRange struct {
	Offset  uint64  `json:"offset"`
	Start   *uint64 `json:"start"`
	Length  uint64  `json:"length"`
	Depth   int     `json:"depth"`
	Present bool    `json:"present"`
	Data    bool    `json:"data"`
	Zero    bool    `json:"zero"`
}

// Capture creates a standalone qcow2 image from a stopped guest disk. qemu-img
// enforces image locking; callers should shut the guest down before capture.
// For a qcow2 overlay, ChangedBlocks contains ranges stored in the overlay.
func Capture(ctx context.Context, qemuImg, sourcePath, outputPath string) (*Descriptor, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("the QEMU snapshot adapter runs on Linux; capture must use a local Linux runner")
	}
	if qemuImg == "" {
		qemuImg = "qemu-img"
	}
	sourcePath, err := filepath.Abs(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("resolve source disk path: %w", err)
	}
	outputPath, err = filepath.Abs(outputPath)
	if err != nil {
		return nil, fmt.Errorf("resolve snapshot output path: %w", err)
	}
	if sourcePath == outputPath {
		return nil, errors.New("snapshot output must differ from source disk")
	}
	if _, err := os.Stat(outputPath); err == nil {
		return nil, fmt.Errorf("snapshot output already exists: %s", outputPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("check snapshot output: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return nil, fmt.Errorf("create snapshot output directory: %w", err)
	}

	infoData, err := runOutput(ctx, qemuImg, "info", "--output=json", sourcePath)
	if err != nil {
		return nil, fmt.Errorf("inspect source disk: %w", err)
	}
	var info imageInfo
	if err := json.Unmarshal(infoData, &info); err != nil {
		return nil, fmt.Errorf("parse qemu-img info: %w", err)
	}
	if info.Format == "" || info.VirtualSize == 0 {
		return nil, errors.New("qemu-img info did not return a format and nonzero virtual size")
	}

	if info.Format == "qcow2" {
		if _, err := runOutput(ctx, qemuImg, "check", sourcePath); err != nil {
			return nil, fmt.Errorf("source qcow2 check failed (ensure the VM is shut down): %w", err)
		}
	}
	changedBlocks, err := readChangedBlocks(ctx, qemuImg, sourcePath, info.Format)
	if err != nil {
		return nil, fmt.Errorf("read source block map: %w", err)
	}

	tmpPath := outputPath + ".partial"
	if _, err := os.Stat(tmpPath); err == nil {
		return nil, fmt.Errorf("temporary snapshot path already exists: %s", tmpPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("check temporary snapshot path: %w", err)
	}
	defer os.Remove(tmpPath)
	if _, err := runOutput(ctx, qemuImg, "convert", "-f", info.Format, "-O", "qcow2", "-c", sourcePath, tmpPath); err != nil {
		return nil, fmt.Errorf("create standalone qcow2 snapshot (ensure the VM is shut down): %w", err)
	}
	if _, err := runOutput(ctx, qemuImg, "check", tmpPath); err != nil {
		return nil, fmt.Errorf("captured qcow2 check failed: %w", err)
	}
	if err := os.Rename(tmpPath, outputPath); err != nil {
		return nil, fmt.Errorf("commit qcow2 snapshot file: %w", err)
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(filepath.Dir(outputPath))
		if err != nil {
			return nil, fmt.Errorf("snapshot was renamed but its directory could not be opened for sync: %w", err)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return nil, fmt.Errorf("snapshot was renamed but its directory sync failed: %w", syncErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("snapshot was renamed but its directory close failed: %w", closeErr)
		}
	}

	hash, size, err := hashFile(outputPath)
	if err != nil {
		_ = os.Remove(outputPath)
		return nil, fmt.Errorf("hash captured qcow2 snapshot: %w", err)
	}
	return &Descriptor{
		FormatVersion: FormatVersion,
		CapturedAt:    time.Now().UTC(),
		SourceFormat:  info.Format,
		OutputFormat:  "qcow2",
		VirtualSize:   info.VirtualSize,
		ImageSize:     size,
		ImageBLAKE3:   hash,
		ChangedBlocks: changedBlocks,
	}, nil
}

func readChangedBlocks(ctx context.Context, qemuImg, sourcePath, format string) ([]BlockExtent, error) {
	cmd := exec.CommandContext(ctx, qemuImg, "map", "--output=json", "-f", format, sourcePath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start qemu-img map: %w", err)
	}
	decoder := json.NewDecoder(stdout)
	token, err := decoder.Token()
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("parse qemu-img map JSON array: %w", err)
	}
	if token != json.Delim('[') {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, errors.New("qemu-img map output is not a JSON array")
	}
	var changed []BlockExtent
	for decoder.More() {
		var r mapRange
		if err := decoder.Decode(&r); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil, fmt.Errorf("parse qemu-img map range: %w", err)
		}
		// present is emitted by current qemu-img versions; data/zero also
		// support older versions and explicit zero clusters in qcow2 overlays.
		if r.Depth == 0 && (r.Present || r.Data || r.Zero) {
			offset := r.Offset
			if r.Start != nil {
				offset = *r.Start
			}
			changed = append(changed, BlockExtent{Offset: offset, Length: r.Length, Zero: r.Zero})
		}
	}
	if _, err := decoder.Token(); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("finish parsing qemu-img map JSON: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("qemu-img map failed: %w: %s", err, stderr.String())
	}
	return changed, nil
}

func runOutput(ctx context.Context, executable string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %v failed: %w: %s", executable, args, err, output)
	}
	return output, nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := blake3.New(32, nil)
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), size, nil
}
