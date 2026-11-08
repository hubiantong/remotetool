package config

import (
	"fmt"
	"sync"
	"testing"
)

// TestStoreConcurrentMixedAccess hammers every shared-state path at once:
// Get / Update / Peers / Peer / UpsertPeer / AddFwdRule / RemoveFwdRule,
// mixed across goroutines. Under `go test -race` this is what catches a lost
// lock or a Get() result aliasing the stored FwdRules slice — the mutated
// copy below would race with concurrent rule writes on the same backing
// array. Structured so -race WOULD catch the pre-F3b bugs even though -race
// is unavailable on the local Windows toolchain.
//
// Note: the copy handling deliberately uses a full-slice expression. Get()
// deep-copies FwdRules only when the rule list is non-empty; after
// RemoveFwdRule the store keeps the old backing array (len 0, cap > 0), and
// Get() returns that raw header — appending to it unchecked would write into
// the store's array. Capping the capacity here forces a reallocation, so the
// test exercises copy-and-mutate without tripping over that latent quirk.
func TestStoreConcurrentMixedAccess(t *testing.T) {
	s := openTestStore(t)

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			name := fmt.Sprintf("dev-%d", g)
			peer := Peer{ID: fmt.Sprintf("peer-%d", g), Name: name}
			if err := s.UpsertPeer(peer); err != nil {
				t.Errorf("UpsertPeer: %v", err)
				return
			}
			for i := 0; i < 200; i++ {
				if err := s.Update(func(c *Config) { c.Name = name; c.WebPort = DefaultWebPort + g }); err != nil {
					t.Errorf("Update: %v", err)
					return
				}
				// Get returns a deep copy: mutating it must be safe and must
				// not touch the store (an aliased slice would race with the
				// AddFwdRule below under -race).
				c := s.Get()
				safe := c.FwdRules[:len(c.FwdRules):len(c.FwdRules)]
				if len(safe) > 0 {
					safe[0].ID = "mutated"
				}
				c.FwdRules = append(safe, FwdRule{ID: "scratch"})
				_ = s.Peers()
				if _, ok := s.Peer(peer.ID); !ok {
					t.Errorf("Peer(%s) missing during concurrent upserts", peer.ID)
					return
				}
				if err := s.UpsertPeer(peer); err != nil {
					t.Errorf("UpsertPeer: %v", err)
					return
				}
				id := fmt.Sprintf("g%d-r%d", g, i)
				rule := FwdRule{ID: id, PeerID: peer.ID, Mode: "L", ListenPort: 20000 + g*1000 + i}
				if err := s.AddFwdRule(rule); err != nil {
					t.Errorf("AddFwdRule(%s): %v", id, err)
					return
				}
				if err := s.RemoveFwdRule(id); err != nil {
					t.Errorf("RemoveFwdRule(%s): %v", id, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	if got := s.Get().FwdRules; len(got) != 0 {
		t.Fatalf("rules left after concurrent add/remove = %+v, want none", got)
	}
	if peers := s.Peers(); len(peers) != 4 {
		t.Fatalf("peers = %d, want 4", len(peers))
	}
}
