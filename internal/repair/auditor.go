package repair

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"

	"flowstore/internal/network"
	"flowstore/internal/object"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

// HealthState classifies the availability level of a chunk.
type HealthState string

const (
	StateHealthy     HealthState = "HEALTHY"     // 10/10 shards available
	StateDegraded    HealthState = "DEGRADED"    // 7-9/10 shards available (safe, repair recommended)
	StateCritical    HealthState = "CRITICAL"    // 6/10 shards available (last surviving line)
	StateUnavailable HealthState = "UNAVAILABLE" // <6 shards available
)

// ShardLocation maps a shard reference to the peer storing it.
type ShardLocation struct {
	Ref    object.ShardRef
	PeerID peer.ID
}

// ChunkHealth tracks probe results for a single 64 MiB chunk.
type ChunkHealth struct {
	ChunkIndex       uint32
	State            HealthState
	HealthyShards    int
	MissingIndices   []uint8
	SurvivingPeers   map[uint8]peer.ID
	UnreachablePeers map[uint8]peer.ID
}

// SwarmReport summarizes the global health metrics across all audited objects.
type SwarmReport struct {
	TotalChunks       int
	HealthyChunks     int
	DegradedChunks    int
	CriticalChunks    int
	UnavailableChunks int
	HealthPercent     float64
	AuditDuration     time.Duration
}

// Auditor conducts zero-transfer cryptographic health inspections over libp2p.
type Auditor struct {
	host host.Host
}

// NewAuditor creates a new Swarm Health Auditor.
func NewAuditor(h host.Host) *Auditor {
	return &Auditor{
		host: h,
	}
}

// AuditChunk issues parallel /flowstore/probe/1.0 challenges to verify every shard in a chunk.
func (a *Auditor) AuditChunk(ctx context.Context, chunkRef object.ChunkRef, locations map[uint8]peer.ID) ChunkHealth {
	health := ChunkHealth{
		ChunkIndex:       chunkRef.Index,
		SurvivingPeers:   make(map[uint8]peer.ID),
		UnreachablePeers: make(map[uint8]peer.ID),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, sRef := range chunkRef.Shards {
		targetPeer, ok := locations[sRef.ShardIndex]
		if !ok {
			health.MissingIndices = append(health.MissingIndices, sRef.ShardIndex)
			continue
		}

		wg.Add(1)
		go func(ref object.ShardRef, pID peer.ID) {
			defer wg.Done()

			var nonce [32]byte
			_, _ = io.ReadFull(rand.Reader, nonce[:])

			probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()

			hasProof, err := network.ProbeShard(probeCtx, a.host, pID, ref.RoutingID, nonce, ref.Checksum)
			mu.Lock()
			defer mu.Unlock()

			if err == nil && hasProof {
				health.HealthyShards++
				health.SurvivingPeers[ref.ShardIndex] = pID
			} else {
				health.MissingIndices = append(health.MissingIndices, ref.ShardIndex)
				health.UnreachablePeers[ref.ShardIndex] = pID
			}
		}(sRef, targetPeer)
	}

	wg.Wait()

	// Classify health state based on Reed-Solomon 6+4 parameters
	switch {
	case health.HealthyShards == len(chunkRef.Shards):
		health.State = StateHealthy
	case health.HealthyShards > 6:
		health.State = StateDegraded
	case health.HealthyShards == 6:
		health.State = StateCritical
	default:
		health.State = StateUnavailable
	}

	return health
}

// AuditManifest inspects all chunks in an object manifest and produces a SwarmReport.
func (a *Auditor) AuditManifest(ctx context.Context, m *object.Manifest, locations map[uint32]map[uint8]peer.ID) ([]ChunkHealth, SwarmReport) {
	start := time.Now()
	var chunkReports []ChunkHealth
	report := SwarmReport{
		TotalChunks: len(m.Chunks),
	}

	for _, chunk := range m.Chunks {
		chunkLocs := locations[chunk.Index]
		ch := a.AuditChunk(ctx, chunk, chunkLocs)
		chunkReports = append(chunkReports, ch)

		switch ch.State {
		case StateHealthy:
			report.HealthyChunks++
		case StateDegraded:
			report.DegradedChunks++
		case StateCritical:
			report.CriticalChunks++
		case StateUnavailable:
			report.UnavailableChunks++
		}
	}

	if report.TotalChunks > 0 {
		report.HealthPercent = (float64(report.HealthyChunks) / float64(report.TotalChunks)) * 100.0
	}
	report.AuditDuration = time.Since(start)

	return chunkReports, report
}

// FormatReport outputs human-readable swarm health metrics.
func (r SwarmReport) FormatReport() string {
	return fmt.Sprintf(`FlowStore Swarm Health Report:
  Total Chunks:        %d
  Healthy (10/10):     %d
  Degraded (7-9/10):   %d
  Critical (6/10):     %d
  Unavailable (<6/10): %d
  Verified Health:     %.2f%%
  Audit Latency:       %v`,
		r.TotalChunks, r.HealthyChunks, r.DegradedChunks, r.CriticalChunks, r.UnavailableChunks, r.HealthPercent, r.AuditDuration)
}
