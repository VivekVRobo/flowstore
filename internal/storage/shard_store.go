package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"flowstore/internal/erasure"
)

var (
	ErrShardNotFound = errors.New("shard not found in local store")
	ErrQuotaExceeded = errors.New("shard storage quota exceeded")
)

// ShardStore defines the storage interface exposed by each peer node.
type ShardStore interface {
	Put(routingID string, shard erasure.Shard) error
	Get(routingID string) (*erasure.Shard, error)
	Has(routingID string) bool
	Delete(routingID string) error
	List() ([]string, error)
	Close() error
}

// FileShardStore is a thread-safe, disk-backed shard store.
type FileShardStore struct {
	rootDir     string
	quotaBytes  int64
	usedBytes   int64
	shardBytes  map[string]int64
	directWrite bool
	mu          sync.RWMutex
}

// NewFileShardStore initializes the local directory for shard storage. A zero
// quota means unlimited, which keeps the constructor compatible for local tools.
func NewFileShardStore(rootDir string, quotaBytes ...int64) (*FileShardStore, error) {
	return newFileShardStore(rootDir, false, quotaBytes...)
}

// NewDirectWriteShardStore writes to final shard names without filesystem
// rename. It appends a small completion trailer to each file; interrupted
// writes without a full trailer are ignored on restart. This mode is intended
// for mounted filesystems that do not implement rename reliably.
func NewDirectWriteShardStore(rootDir string, quotaBytes ...int64) (*FileShardStore, error) {
	return newFileShardStore(rootDir, true, quotaBytes...)
}

func newFileShardStore(rootDir string, directWrite bool, quotaBytes ...int64) (*FileShardStore, error) {
	if len(quotaBytes) > 1 {
		return nil, errors.New("shard store accepts at most one quota value")
	}
	if err := os.MkdirAll(rootDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create shard store root: %w", err)
	}
	var quota int64
	if len(quotaBytes) > 0 {
		quota = quotaBytes[0]
	}
	if quota < 0 {
		return nil, errors.New("shard store quota cannot be negative")
	}
	s := &FileShardStore{rootDir: rootDir, quotaBytes: quota, shardBytes: make(map[string]int64), directWrite: directWrite}
	if err := s.scanUsage(); err != nil {
		return nil, fmt.Errorf("failed to scan existing shard usage: %w", err)
	}
	return s, nil
}

const shardHeaderBytes int64 = 1 + 8 + 32

func (s *FileShardStore) scanUsage() error {
	return filepath.Walk(s.rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".shard" {
			return nil
		}
		if s.directWrite && !s.hasCommitMarker(path) {
			return nil
		}
		base := filepath.Base(path)
		routingID := base[:len(base)-len(".shard")]
		s.shardBytes[routingID] = info.Size()
		s.usedBytes += info.Size()
		return nil
	})
}

const shardCommitMarker = "flowstore-shard-commit-v1"

func (s *FileShardStore) commitPath(shardPath string) string {
	return shardPath + ".ok"
}

func (s *FileShardStore) hasCommitMarker(shardPath string) bool {
	f, err := os.Open(shardPath)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() < shardHeaderBytes+int64(len(shardCommitMarker)) {
		return false
	}
	if _, err := f.Seek(-int64(len(shardCommitMarker)), io.SeekEnd); err != nil {
		return false
	}
	marker := make([]byte, len(shardCommitMarker))
	if _, err := io.ReadFull(f, marker); err != nil {
		return false
	}
	return string(marker) == shardCommitMarker
}

// UsageBytes reports persisted shard-file bytes and the configured quota.
func (s *FileShardStore) UsageBytes() (used, quota int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.usedBytes, s.quotaBytes
}

func (s *FileShardStore) shardPath(routingID string) string {
	if len(routingID) < 4 {
		return filepath.Join(s.rootDir, routingID+".shard")
	}
	// Fan-out: 2-char directory prefix to avoid huge single-directory listings on Windows
	prefix := routingID[:2]
	return filepath.Join(s.rootDir, prefix, routingID+".shard")
}

// Put writes an opaque shard atomically to disk.
// Shard file format:
// [1 byte: Index] + [8 bytes: OriginalSize] + [32 bytes: Checksum] + [N bytes: Data]
func (s *FileShardStore) Put(routingID string, shard erasure.Shard) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !erasure.VerifyShard(shard) {
		return erasure.ErrCorruptShard
	}
	newSize := shardHeaderBytes + int64(len(shard.Data))
	if s.directWrite {
		newSize += int64(len(shardCommitMarker))
	}
	oldSize := s.shardBytes[routingID]
	if s.quotaBytes > 0 && s.usedBytes-oldSize+newSize > s.quotaBytes {
		return fmt.Errorf("%w: used %d bytes, replacing %d bytes with %d would exceed %d bytes", ErrQuotaExceeded, s.usedBytes, oldSize, newSize, s.quotaBytes)
	}

	p := s.shardPath(routingID)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		return fmt.Errorf("failed to create shard subdirectory: %w", err)
	}
	if s.directWrite {
		return s.putDirect(routingID, shard, p, oldSize, newSize)
	}

	tmpPath := p + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open temp shard file: %w", err)
	}

	header := make([]byte, 1+8+32)
	header[0] = shard.Index
	binary.BigEndian.PutUint64(header[1:9], shard.OriginalSize)
	copy(header[9:41], shard.Checksum[:])

	if _, err := f.Write(header); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}

	if _, err := f.Write(shard.Data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	// Atomic replace
	if err := os.Rename(tmpPath, p); err != nil {
		return err
	}
	s.usedBytes = s.usedBytes - oldSize + newSize
	s.shardBytes[routingID] = newSize
	if runtime.GOOS != "windows" {
		directory, err := os.Open(filepath.Dir(p))
		if err != nil {
			return fmt.Errorf("shard was renamed but storage directory could not be opened for sync: %w", err)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return fmt.Errorf("shard was renamed but storage directory sync failed: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("shard was renamed but storage directory close failed: %w", closeErr)
		}
	}
	return nil
}

func (s *FileShardStore) putDirect(routingID string, shard erasure.Shard, path string, oldSize, newSize int64) error {
	if oldSize > 0 {
		s.usedBytes -= oldSize
		delete(s.shardBytes, routingID)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open final shard file: %w", err)
	}
	writeErr := writeShardFile(f, shard, true)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return fmt.Errorf("failed to close final shard file: %w", closeErr)
	}
	if err := s.waitForDirectWrite(path, newSize); err != nil {
		return err
	}
	s.usedBytes += newSize
	s.shardBytes[routingID] = newSize
	return nil
}

func (s *FileShardStore) waitForDirectWrite(path string, expectedSize int64) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		info, err := os.Stat(path)
		if err == nil && info.Size() == expectedSize && s.hasCommitMarker(path) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("direct-written shard did not become visible with its completion marker at %s", path)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func writeShardFile(f *os.File, shard erasure.Shard, addCommitMarker bool) error {
	header := make([]byte, 1+8+32)
	header[0] = shard.Index
	binary.BigEndian.PutUint64(header[1:9], shard.OriginalSize)
	copy(header[9:41], shard.Checksum[:])
	if _, err := f.Write(header); err != nil {
		return err
	}
	if _, err := f.Write(shard.Data); err != nil {
		return err
	}
	if addCommitMarker {
		if _, err := io.WriteString(f, shardCommitMarker); err != nil {
			return err
		}
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync final shard file: %w", err)
	}
	return nil
}

// Get reads and validates a shard from disk.
func (s *FileShardStore) Get(routingID string) (*erasure.Shard, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p := s.shardPath(routingID)
	if s.directWrite && !s.hasCommitMarker(p) {
		return nil, fmt.Errorf("%w: direct-write completion trailer missing or incomplete at %s", ErrShardNotFound, p)
	}
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			if s.directWrite {
				return nil, fmt.Errorf("%w: shard file is not visible at %s", ErrShardNotFound, p)
			}
			return nil, ErrShardNotFound
		}
		return nil, fmt.Errorf("failed to open shard file: %w", err)
	}
	defer f.Close()

	header := make([]byte, 1+8+32)
	if _, err := io.ReadFull(f, header); err != nil {
		return nil, fmt.Errorf("corrupt shard header: %w", err)
	}

	index := header[0]
	origSize := binary.BigEndian.Uint64(header[1:9])
	var checksum [32]byte
	copy(checksum[:], header[9:41])

	var data []byte
	if s.directWrite {
		info, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("failed to stat direct-written shard file: %w", err)
		}
		dataSize := info.Size() - shardHeaderBytes - int64(len(shardCommitMarker))
		if dataSize < 0 {
			return nil, errors.New("corrupt direct-written shard size")
		}
		data, err = io.ReadAll(io.LimitReader(f, dataSize))
		if err == nil && int64(len(data)) != dataSize {
			err = io.ErrUnexpectedEOF
		}
	} else {
		data, err = io.ReadAll(f)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read shard body: %w", err)
	}

	shard := &erasure.Shard{
		Index:        index,
		OriginalSize: origSize,
		Checksum:     checksum,
		Data:         data,
	}

	if !erasure.VerifyShard(*shard) {
		return nil, erasure.ErrCorruptShard
	}

	return shard, nil
}

// Has checks if a shard exists in storage.
func (s *FileShardStore) Has(routingID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p := s.shardPath(routingID)
	if s.directWrite && !s.hasCommitMarker(p) {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

// Delete removes a shard.
func (s *FileShardStore) Delete(routingID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.shardPath(routingID)
	err := os.Remove(p)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	markerErr := os.Remove(s.commitPath(p))
	if markerErr != nil && !os.IsNotExist(markerErr) {
		return markerErr
	}
	if err == nil || markerErr == nil {
		s.usedBytes -= s.shardBytes[routingID]
		if s.usedBytes < 0 {
			s.usedBytes = 0
		}
		delete(s.shardBytes, routingID)
	}
	return nil
}

// List returns all routing IDs currently present in this store.
func (s *FileShardStore) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var ids []string
	err := filepath.Walk(s.rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".shard" && (!s.directWrite || s.hasCommitMarker(path)) {
			base := filepath.Base(path)
			routingID := base[:len(base)-len(".shard")]
			ids = append(ids, routingID)
		}
		return nil
	})
	return ids, err
}

func (s *FileShardStore) Close() error {
	return nil
}
