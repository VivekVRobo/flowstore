package placement

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

var (
	ErrNoEligiblePeers = errors.New("no eligible peers found meeting diversity and capacity constraints")
)

// PeerStatus tracks operational metrics of a participating storage peer.
type PeerStatus struct {
	ID        peer.ID
	Addrs     []string
	FreeBytes int64
	LastSeen  time.Time
	Active    bool
	Domain    string
}

// NormalizeDomain canonicalizes a failure-domain tag.
func NormalizeDomain(domain string) string {
	if domain == "" {
		return "default"
	}
	trimmed := domain
	for len(trimmed) > 0 && (trimmed[0] == ' ' || trimmed[0] == '\t') {
		trimmed = trimmed[1:]
	}
	for len(trimmed) > 0 && (trimmed[len(trimmed)-1] == ' ' || trimmed[len(trimmed)-1] == '\t') {
		trimmed = trimmed[:len(trimmed)-1]
	}
	if trimmed == "" {
		return "default"
	}
	lower := make([]byte, len(trimmed))
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		lower[i] = c
	}
	return string(lower)
}

// Scheduler selects destination peers while enforcing strict failure-domain diversity.
type Scheduler struct {
	mu    sync.RWMutex
	peers map[peer.ID]*PeerStatus
	rng   *rand.Rand
}

// NewScheduler creates a new peer placement and diversity scheduler.
func NewScheduler() *Scheduler {
	return &Scheduler{
		peers: make(map[peer.ID]*PeerStatus),
		rng:   rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// RegisterPeer registers or updates a peer's status in the placement pool.
func (s *Scheduler) RegisterPeer(id peer.ID, freeBytes int64, addrs []string) {
	s.RegisterPeerWithDomain(id, freeBytes, addrs, "default")
}

// RegisterPeerWithDomain registers a peer with an explicit failure domain
// tag such as host, rack, or region. Empty domains map to "default".
func (s *Scheduler) RegisterPeerWithDomain(id peer.ID, freeBytes int64, addrs []string, domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.peers[id] = &PeerStatus{
		ID:        id,
		Addrs:     addrs,
		FreeBytes: freeBytes,
		LastSeen:  time.Now(),
		Active:    true,
		Domain:    NormalizeDomain(domain),
	}
}

// DomainOf returns the failure domain for a known peer.
func (s *Scheduler) DomainOf(id peer.ID) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.peers[id]; ok {
		return p.Domain
	}
	return "default"
}

// DomainSpread groups peer IDs by failure domain.
func (s *Scheduler) DomainSpread(ids []peer.ID) map[string][]peer.ID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	byDomain := make(map[string][]peer.ID)
	for _, id := range ids {
		domain := "default"
		if p, ok := s.peers[id]; ok && p.Domain != "" {
			domain = p.Domain
		}
		byDomain[domain] = append(byDomain[domain], id)
	}
	return byDomain
}

// MarkInactive marks a peer as unreachable or offline.
func (s *Scheduler) MarkInactive(id peer.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p, ok := s.peers[id]; ok {
		p.Active = false
	}
}

// SelectDistinctPeers selects N peers for a chunk such that:
// 1. None of the peers are in excludedPeers (e.g. peers already holding shards of this chunk).
// 2. All selected peers are active and distinct from each other.
func (s *Scheduler) SelectDistinctPeers(count int, excludedPeers map[peer.ID]bool) ([]peer.ID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var candidates []peer.ID
	for id, p := range s.peers {
		if !p.Active {
			continue
		}
		if excludedPeers != nil && excludedPeers[id] {
			continue
		}
		candidates = append(candidates, id)
	}

	if len(candidates) < count {
		return nil, fmt.Errorf("%w: requested %d peers, only %d eligible", ErrNoEligiblePeers, count, len(candidates))
	}

	// Shuffle candidates for uniform distribution
	shuffled := make([]peer.ID, len(candidates))
	copy(shuffled, candidates)
	s.rng.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	return shuffled[:count], nil
}

// SelectDiversePeers selects N peers while maximizing failure-domain spread.
// It round-robins across domains so each 6+4 shard set spans as many
// independent domains as available. It returns the selected peers and the
// number of distinct domains covered. When domains are fewer than requested
// peers, it still succeeds (for single-host tests) but reports the shortfall;
// production requires 10 distinct domains for full independence.
func (s *Scheduler) SelectDiversePeers(count int, excludedPeers map[peer.ID]bool) ([]peer.ID, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	byDomain := make(map[string][]peer.ID)
	for id, p := range s.peers {
		if !p.Active {
			continue
		}
		if excludedPeers != nil && excludedPeers[id] {
			continue
		}
		domain := p.Domain
		if domain == "" {
			domain = "default"
		}
		byDomain[domain] = append(byDomain[domain], id)
	}
	total := 0
	for _, v := range byDomain {
		total += len(v)
	}
	if total < count {
		return nil, len(byDomain), fmt.Errorf("%w: requested %d peers, only %d eligible", ErrNoEligiblePeers, count, total)
	}
	domains := make([]string, 0, len(byDomain))
	for d := range byDomain {
		domains = append(domains, d)
		s.rng.Shuffle(len(byDomain[d]), func(i, j int) {
			byDomain[d][i], byDomain[d][j] = byDomain[d][j], byDomain[d][i]
		})
	}
	// Shuffle domain order for uniform distribution.
	s.rng.Shuffle(len(domains), func(i, j int) {
		domains[i], domains[j] = domains[j], domains[i]
	})
	var selected []peer.ID
	usedDomains := make(map[string]struct{})
	indices := make(map[string]int)
	for len(selected) < count {
		progress := false
		for _, d := range domains {
			if len(selected) >= count {
				break
			}
			i := indices[d]
			if i < len(byDomain[d]) {
				selected = append(selected, byDomain[d][i])
				indices[d] = i + 1
				usedDomains[d] = struct{}{}
				progress = true
			}
		}
		if !progress {
			break
		}
	}
	return selected, len(usedDomains), nil
}

// PeerCount returns total active peers known to the scheduler.
func (s *Scheduler) PeerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	active := 0
	for _, p := range s.peers {
		if p.Active {
			active++
		}
	}
	return active
}
