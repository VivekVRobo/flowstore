package network

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"flowstore/internal/erasure"
	"flowstore/internal/storage"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"lukechampine.com/blake3"
)

const (
	ProtocolStore  = protocol.ID("/flowstore/store/1.0")
	ProtocolGet    = protocol.ID("/flowstore/get/1.0")
	ProtocolProbe  = protocol.ID("/flowstore/probe/1.0")
	ProtocolDelete = protocol.ID("/flowstore/delete/1.0")
	ProtocolRepair = protocol.ID("/flowstore/repair/1.0")
)

// StoreRequest carries an opaque shard to a storage peer.
type StoreRequest struct {
	RoutingID     string   `json:"routing_id"`
	Index         uint8    `json:"index"`
	OriginalSize  uint64   `json:"original_size"`
	Checksum      [32]byte `json:"checksum"`
	Data          []byte   `json:"data"`
	LeaseDuration int64    `json:"lease_seconds"` // in seconds
}

// StoreResponse acknowledges shard storage.
type StoreResponse struct {
	Success            bool     `json:"success"`
	Error              string   `json:"error,omitempty"`
	Proof              [32]byte `json:"proof,omitempty"`
	DiscoveryAnnounced bool     `json:"discovery_announced,omitempty"`
	DiscoveryError     string   `json:"discovery_error,omitempty"`
}

// GetRequest queries a shard by oblivious RoutingID.
type GetRequest struct {
	RoutingID string `json:"routing_id"`
}

// GetResponse returns the shard contents or error.
type GetResponse struct {
	Success      bool     `json:"success"`
	Error        string   `json:"error,omitempty"`
	Index        uint8    `json:"index"`
	OriginalSize uint64   `json:"original_size"`
	Checksum     [32]byte `json:"checksum"`
	Data         []byte   `json:"data"`
}

// ProbeRequest challenges a peer to prove possession of a shard without transferring payload.
type ProbeRequest struct {
	RoutingID string   `json:"routing_id"`
	Nonce     [32]byte `json:"nonce"`
}

// ProbeResponse returns the cryptographic possession proof: BLAKE3(Checksum || Nonce).
type ProbeResponse struct {
	Has   bool     `json:"has"`
	Proof [32]byte `json:"proof,omitempty"`
	Error string   `json:"error,omitempty"`
}

// DeleteRequest explicitly reclaims a leased shard by oblivious RoutingID.
type DeleteRequest struct {
	RoutingID string `json:"routing_id"`
}

// DeleteResponse reports whether the shard existed before deletion.
// Delete is idempotent: deleting a missing shard succeeds with Existed=false.
type DeleteResponse struct {
	Success bool   `json:"success"`
	Existed bool   `json:"existed,omitempty"`
	Error   string `json:"error,omitempty"`
}

// RepairRequest coordinates swarm health without moving bulk data.
// Check lists RoutingIDs the caller wants presence for (batch probe).
// Reannounce asks the peer to re-announce held shards on the DHT.
type RepairRequest struct {
	Check      []string `json:"check,omitempty"`
	Reannounce bool     `json:"reannounce,omitempty"`
}

// RepairResponse reports peer storage health for repair coordination.
type RepairResponse struct {
	Success       bool     `json:"success"`
	Held          []string `json:"held,omitempty"`
	Missing       []string `json:"missing,omitempty"`
	ShardCount    int      `json:"shard_count,omitempty"`
	UsedBytes     int64    `json:"used_bytes,omitempty"`
	QuotaBytes    int64    `json:"quota_bytes,omitempty"`
	Reannounced   int      `json:"reannounced,omitempty"`
	FailureDomain string   `json:"failure_domain,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// FrameRead reads a 4-byte length-prefixed JSON message from a stream.
func FrameRead(r io.Reader, v interface{}) error {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return err
	}
	if length > 128*1024*1024 { // 128 MiB safety limit
		return errors.New("frame length exceeds 128 MiB maximum")
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}

// FrameWrite writes a 4-byte length-prefixed JSON message to a stream.
func FrameWrite(w io.Writer, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}

	length := uint32(len(data))
	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// ProtocolHandler handles incoming libp2p streams and interacts with local storage.
type ProtocolHandler struct {
	store  storage.ShardStore
	db     *storage.NodeDB
	dht    *ShardRouting
	domain string
}

// SetFailureDomain sets the advertised failure-domain tag for repair coordination.
func (ph *ProtocolHandler) SetFailureDomain(domain string) {
	if domain == "" {
		domain = "default"
	}
	ph.domain = domain
}

// NewProtocolHandler registers FlowStore stream handlers on the libp2p host.
func NewProtocolHandler(h host.Host, store storage.ShardStore, db *storage.NodeDB, routing ...*ShardRouting) *ProtocolHandler {
	handler := &ProtocolHandler{
		store: store,
		db:    db,
	}
	if len(routing) > 0 {
		handler.dht = routing[0]
	}

	h.SetStreamHandler(ProtocolStore, handler.handleStore)
	h.SetStreamHandler(ProtocolGet, handler.handleGet)
	h.SetStreamHandler(ProtocolProbe, handler.handleProbe)
	h.SetStreamHandler(ProtocolDelete, handler.handleDelete)
	h.SetStreamHandler(ProtocolRepair, handler.handleRepair)

	return handler
}

func (ph *ProtocolHandler) handleStore(s network.Stream) {
	defer s.Close()

	var req StoreRequest
	if err := FrameRead(s, &req); err != nil {
		_ = FrameWrite(s, StoreResponse{Success: false, Error: err.Error()})
		return
	}

	shard := erasure.Shard{
		Index:        req.Index,
		OriginalSize: req.OriginalSize,
		Checksum:     req.Checksum,
		Data:         req.Data,
	}

	// Cryptographic validation
	if !erasure.VerifyShard(shard) {
		_ = FrameWrite(s, StoreResponse{Success: false, Error: "corrupt shard payload failed blake3 checksum"})
		return
	}

	if err := ph.store.Put(req.RoutingID, shard); err != nil {
		_ = FrameWrite(s, StoreResponse{Success: false, Error: err.Error()})
		return
	}
	stored, err := ph.store.Get(req.RoutingID)
	if err != nil {
		_ = ph.store.Delete(req.RoutingID)
		_ = FrameWrite(s, StoreResponse{Success: false, Error: fmt.Sprintf("stored shard read-back failed: %v", err)})
		return
	}
	if stored == nil || !erasure.VerifyShard(*stored) || stored.Index != shard.Index || stored.OriginalSize != shard.OriginalSize || stored.Checksum != shard.Checksum {
		_ = ph.store.Delete(req.RoutingID)
		_ = FrameWrite(s, StoreResponse{Success: false, Error: "stored shard read-back metadata mismatch"})
		return
	}

	if ph.db != nil {
		lease := time.Duration(req.LeaseDuration) * time.Second
		if lease <= 0 {
			lease = 30 * 24 * time.Hour // Default 30-day lease
		}
		if err := ph.db.RecordShard(req.RoutingID, int64(len(shard.Data)), fmt.Sprintf("%x", shard.Checksum), lease); err != nil {
			_ = FrameWrite(s, StoreResponse{Success: false, Error: fmt.Sprintf("shard bytes were stored but lease metadata could not be committed: %v", err)})
			return
		}
	}
	announced := false
	var announceErr string
	if ph.dht != nil {
		// Providers must announce from the peer that actually owns the bytes.
		// The requesting client cannot truthfully advertise this shard.
		announceCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := ph.dht.Provide(announceCtx, req.RoutingID); err != nil {
			announceErr = err.Error()
		} else {
			announced = true
		}
		cancel()
	}

	_ = FrameWrite(s, StoreResponse{
		Success:            true,
		Proof:              stored.Checksum,
		DiscoveryAnnounced: announced,
		DiscoveryError:     announceErr,
	})
}

// isExpired reports whether the routing ID has a passed lease in the index.
// Missing records mean the shard was stored without an index entry (local
// tools) or predates leases, so they are treated as live; Reconcile cleans
// daemon orphans separately.
func (ph *ProtocolHandler) isExpired(routingID string) bool {
	if ph.db == nil {
		return false
	}
	meta, err := ph.db.GetShardMeta(routingID)
	if err != nil {
		return false
	}
	return !meta.LeaseExpiresAt.After(time.Now().UTC())
}

// expireIfNeeded deletes expired shards and reports true when expired.
func (ph *ProtocolHandler) expireIfNeeded(routingID string) bool {
	if !ph.isExpired(routingID) {
		return false
	}
	_ = ph.store.Delete(routingID)
	if ph.db != nil {
		_ = ph.db.DeleteShard(routingID)
	}
	return true
}

// hasLive reports presence excluding expired leases.
func (ph *ProtocolHandler) hasLive(routingID string) bool {
	if routingID == "" {
		return false
	}
	if ph.expireIfNeeded(routingID) {
		return false
	}
	return ph.store.Has(routingID)
}

func (ph *ProtocolHandler) handleGet(s network.Stream) {
	defer s.Close()

	var req GetRequest
	if err := FrameRead(s, &req); err != nil {
		_ = FrameWrite(s, GetResponse{Success: false, Error: err.Error()})
		return
	}

	if ph.expireIfNeeded(req.RoutingID) {
		_ = FrameWrite(s, GetResponse{Success: false, Error: storage.ErrShardNotFound.Error()})
		return
	}
	shard, err := ph.store.Get(req.RoutingID)
	if err != nil {
		_ = FrameWrite(s, GetResponse{Success: false, Error: err.Error()})
		return
	}

	_ = FrameWrite(s, GetResponse{
		Success:      true,
		Index:        shard.Index,
		OriginalSize: shard.OriginalSize,
		Checksum:     shard.Checksum,
		Data:         shard.Data,
	})
}

func (ph *ProtocolHandler) handleProbe(s network.Stream) {
	defer s.Close()

	var req ProbeRequest
	if err := FrameRead(s, &req); err != nil {
		_ = FrameWrite(s, ProbeResponse{Has: false, Error: err.Error()})
		return
	}

	if ph.expireIfNeeded(req.RoutingID) {
		_ = FrameWrite(s, ProbeResponse{Has: false})
		return
	}
	shard, err := ph.store.Get(req.RoutingID)
	if err != nil {
		_ = FrameWrite(s, ProbeResponse{Has: false})
		return
	}

	// Compute proof: BLAKE3(Checksum || Nonce)
	hasher := blake3.New(32, nil)
	hasher.Write(shard.Checksum[:])
	hasher.Write(req.Nonce[:])
	var proof [32]byte
	copy(proof[:], hasher.Sum(nil))

	_ = FrameWrite(s, ProbeResponse{
		Has:   true,
		Proof: proof,
	})
}

func (ph *ProtocolHandler) handleDelete(s network.Stream) {
	defer s.Close()

	var req DeleteRequest
	if err := FrameRead(s, &req); err != nil {
		_ = FrameWrite(s, DeleteResponse{Success: false, Error: err.Error()})
		return
	}
	if req.RoutingID == "" {
		_ = FrameWrite(s, DeleteResponse{Success: false, Error: "empty routing ID"})
		return
	}

	existed := ph.store.Has(req.RoutingID)
	if err := ph.store.Delete(req.RoutingID); err != nil {
		_ = FrameWrite(s, DeleteResponse{Success: false, Error: err.Error()})
		return
	}
	if ph.db != nil {
		_ = ph.db.DeleteShard(req.RoutingID)
	}
	_ = FrameWrite(s, DeleteResponse{Success: true, Existed: existed})
}

func (ph *ProtocolHandler) handleRepair(s network.Stream) {
	defer s.Close()

	var req RepairRequest
	if err := FrameRead(s, &req); err != nil {
		_ = FrameWrite(s, RepairResponse{Success: false, Error: err.Error()})
		return
	}
	if len(req.Check) > 1000 {
		_ = FrameWrite(s, RepairResponse{Success: false, Error: "check list exceeds 1000 routing IDs"})
		return
	}

	resp := RepairResponse{Success: true, Held: []string{}, Missing: []string{}}
	if ph.domain != "" {
		resp.FailureDomain = ph.domain
	} else {
		resp.FailureDomain = "default"
	}
	for _, routingID := range req.Check {
		if routingID == "" {
			continue
		}
		if ph.hasLive(routingID) {
			resp.Held = append(resp.Held, routingID)
		} else {
			resp.Missing = append(resp.Missing, routingID)
		}
	}

	if ids, err := ph.store.List(); err == nil {
		resp.ShardCount = len(ids)
	}
	type usageReporter interface {
		UsageBytes() (used, quota int64)
	}
	if reporter, ok := ph.store.(usageReporter); ok {
		used, quota := reporter.UsageBytes()
		resp.UsedBytes = used
		resp.QuotaBytes = quota
	}

	if req.Reannounce && ph.dht != nil {
		targets := resp.Held
		if len(req.Check) == 0 {
			if ids, err := ph.store.List(); err == nil {
				targets = make([]string, 0, min(len(ids), 1000))
				for _, routingID := range ids {
					if ph.hasLive(routingID) {
						targets = append(targets, routingID)
						if len(targets) == 1000 {
							break
						}
					}
				}
			}
		}
		for _, routingID := range targets {
			announceCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := ph.dht.Provide(announceCtx, routingID); err == nil {
				resp.Reannounced++
			}
			cancel()
		}
	}

	_ = FrameWrite(s, resp)
}

// Client RPC Helpers:

// SendStoreShard transfers a shard to a target peer via libp2p stream.
func SendStoreShard(ctx context.Context, h host.Host, target peer.ID, routingID string, shard erasure.Shard, leaseSeconds int64, requireDiscovery ...bool) error {
	s, err := h.NewStream(ctx, target, ProtocolStore)
	if err != nil {
		return fmt.Errorf("failed to open store stream to %s: %w", target, err)
	}
	defer s.Close()

	req := StoreRequest{
		RoutingID:     routingID,
		Index:         shard.Index,
		OriginalSize:  shard.OriginalSize,
		Checksum:      shard.Checksum,
		Data:          shard.Data,
		LeaseDuration: leaseSeconds,
	}

	if err := FrameWrite(s, req); err != nil {
		return fmt.Errorf("failed to write store request: %w", err)
	}

	var resp StoreResponse
	if err := FrameRead(s, &resp); err != nil {
		return fmt.Errorf("failed to read store response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("peer rejected store request: %s", resp.Error)
	}
	if resp.Proof != shard.Checksum {
		return errors.New("peer store acknowledgment checksum mismatch")
	}
	if len(requireDiscovery) > 0 && requireDiscovery[0] && !resp.DiscoveryAnnounced {
		if resp.DiscoveryError != "" {
			return fmt.Errorf("peer stored shard but failed to announce it for discovery: %s", resp.DiscoveryError)
		}
		return errors.New("peer stored shard but did not confirm a DHT provider announcement")
	}

	return nil
}

// FetchShard retrieves a shard from a target peer via libp2p stream.
func FetchShard(ctx context.Context, h host.Host, target peer.ID, routingID string) (*erasure.Shard, error) {
	s, err := h.NewStream(ctx, target, ProtocolGet)
	if err != nil {
		return nil, fmt.Errorf("failed to open get stream to %s: %w", target, err)
	}
	defer s.Close()

	if err := FrameWrite(s, GetRequest{RoutingID: routingID}); err != nil {
		return nil, fmt.Errorf("failed to write get request: %w", err)
	}

	var resp GetResponse
	if err := FrameRead(s, &resp); err != nil {
		return nil, fmt.Errorf("failed to read get response: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("peer get failed: %s", resp.Error)
	}

	shard := &erasure.Shard{
		Index:        resp.Index,
		OriginalSize: resp.OriginalSize,
		Checksum:     resp.Checksum,
		Data:         resp.Data,
	}

	if !erasure.VerifyShard(*shard) {
		return nil, erasure.ErrCorruptShard
	}

	return shard, nil
}

// ProbeShard executes a possession challenge against a remote peer.
func ProbeShard(ctx context.Context, h host.Host, target peer.ID, routingID string, nonce [32]byte, expectedChecksum [32]byte) (bool, error) {
	s, err := h.NewStream(ctx, target, ProtocolProbe)
	if err != nil {
		return false, fmt.Errorf("failed to open probe stream: %w", err)
	}
	defer s.Close()

	if err := FrameWrite(s, ProbeRequest{RoutingID: routingID, Nonce: nonce}); err != nil {
		return false, fmt.Errorf("failed to write probe request: %w", err)
	}

	var resp ProbeResponse
	if err := FrameRead(s, &resp); err != nil {
		return false, fmt.Errorf("failed to read probe response: %w", err)
	}

	if !resp.Has {
		return false, nil
	}

	// Verify proof
	hasher := blake3.New(32, nil)
	hasher.Write(expectedChecksum[:])
	hasher.Write(nonce[:])
	expectedProof := hasher.Sum(nil)

	var proofArr [32]byte
	copy(proofArr[:], expectedProof)

	if resp.Proof != proofArr {
		return false, errors.New("cryptographic proof of possession failed: hash mismatch")
	}

	return true, nil
}

// SendDeleteShard explicitly reclaims a shard on a target peer.
// Delete is idempotent: missing shards return Existed=false without error.
func SendDeleteShard(ctx context.Context, h host.Host, target peer.ID, routingID string) (bool, error) {
	if routingID == "" {
		return false, errors.New("empty routing ID")
	}
	s, err := h.NewStream(ctx, target, ProtocolDelete)
	if err != nil {
		return false, fmt.Errorf("failed to open delete stream to %s: %w", target, err)
	}
	defer s.Close()

	if err := FrameWrite(s, DeleteRequest{RoutingID: routingID}); err != nil {
		return false, fmt.Errorf("failed to write delete request: %w", err)
	}

	var resp DeleteResponse
	if err := FrameRead(s, &resp); err != nil {
		return false, fmt.Errorf("failed to read delete response: %w", err)
	}
	if !resp.Success {
		return false, fmt.Errorf("peer delete failed: %s", resp.Error)
	}
	return resp.Existed, nil
}

// RequestRepair queries a peer for storage health and optionally asks it
// to re-announce held shards on the DHT for repair coordination.
func RequestRepair(ctx context.Context, h host.Host, target peer.ID, check []string, reannounce bool) (*RepairResponse, error) {
	if len(check) > 1000 {
		return nil, errors.New("check list exceeds 1000 routing IDs")
	}
	s, err := h.NewStream(ctx, target, ProtocolRepair)
	if err != nil {
		return nil, fmt.Errorf("failed to open repair stream to %s: %w", target, err)
	}
	defer s.Close()

	if err := FrameWrite(s, RepairRequest{Check: check, Reannounce: reannounce}); err != nil {
		return nil, fmt.Errorf("failed to write repair request: %w", err)
	}

	var resp RepairResponse
	if err := FrameRead(s, &resp); err != nil {
		return nil, fmt.Errorf("failed to read repair response: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("peer repair failed: %s", resp.Error)
	}
	return &resp, nil
}
