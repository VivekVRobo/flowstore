package placement

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestSelectDiversePeersMaximizesSpread(t *testing.T) {
	s := NewScheduler()
	var ids []peer.ID
	for i := 0; i < 6; i++ {
		id := peer.ID(string(rune('a'+i)) + "test-peer-id")
		ids = append(ids, id)
	}
	domains := []string{"rack-a", "rack-a", "rack-b", "rack-b", "rack-c", "rack-c"}
	for i, id := range ids {
		s.RegisterPeerWithDomain(id, 1<<30, nil, domains[i])
	}
	selected, distinct, err := s.SelectDiversePeers(3, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(selected))
	}
	if distinct != 3 {
		t.Fatalf("expected 3 distinct domains, got %d covering %v", distinct, s.DomainSpread(selected))
	}
	// Requesting more than available domains still succeeds with shortfall reported.
	selected, distinct, err = s.SelectDiversePeers(6, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 6 || distinct != 3 {
		t.Fatalf("expected 6 peers across 3 domains, got %d across %d", len(selected), distinct)
	}
	// Exclusion is respected.
	excluded := map[peer.ID]bool{ids[0]: true, ids[1]: true, ids[2]: true, ids[3]: true, ids[4]: true}
	selected, _, err = s.SelectDiversePeers(1, excluded)
	if err != nil {
		t.Fatal(err)
	}
	if selected[0] != ids[5] {
		t.Fatalf("expected only remaining peer, got %s", selected[0])
	}
}
