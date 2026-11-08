package config

import (
	"fmt"
	"sync"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func TestStoreFwdRuleAddRemove(t *testing.T) {
	s := openTestStore(t)

	r := FwdRule{ID: "r1", PeerID: "peer1", Mode: "L", ListenPort: 13389, TargetHost: "localhost", TargetPort: 3389}
	if err := s.AddFwdRule(r); err != nil {
		t.Fatalf("AddFwdRule: %v", err)
	}
	if got := s.Get().FwdRules; len(got) != 1 || got[0] != r {
		t.Fatalf("Get after add = %+v, want [%+v]", got, r)
	}

	// Persisted: a store reopened from the same dir sees the rule.
	reopened, err := Open(s.Dir())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := reopened.Get().FwdRules; len(got) != 1 || got[0].ID != "r1" {
		t.Fatalf("reopened rules = %+v, want [r1]", got)
	}

	// Adding a rule with the same ID replaces it instead of duplicating.
	r2 := r
	r2.ListenPort = 13390
	if err := s.AddFwdRule(r2); err != nil {
		t.Fatalf("AddFwdRule (replace): %v", err)
	}
	if got := s.Get().FwdRules; len(got) != 1 || got[0].ListenPort != 13390 {
		t.Fatalf("rules after replace = %+v, want single rule on port 13390", got)
	}

	if err := s.RemoveFwdRule("r1"); err != nil {
		t.Fatalf("RemoveFwdRule: %v", err)
	}
	if err := s.RemoveFwdRule("r1"); err == nil {
		t.Fatal("second RemoveFwdRule for the same id should error")
	}
	if got := s.Get().FwdRules; len(got) != 0 {
		t.Fatalf("rules after remove = %+v, want none", got)
	}
	// Persisted removal.
	reopened2, err := Open(s.Dir())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := reopened2.Get().FwdRules; len(got) != 0 {
		t.Fatalf("reopened rules after remove = %+v, want none", got)
	}
}

func TestStoreGetDeepCopiesFwdRules(t *testing.T) {
	s := openTestStore(t)
	if err := s.AddFwdRule(FwdRule{ID: "r1", PeerID: "p", Mode: "L", ListenPort: 1}); err != nil {
		t.Fatalf("AddFwdRule: %v", err)
	}

	c := s.Get()
	c.FwdRules[0].ID = "mutated"
	c.FwdRules = append(c.FwdRules, FwdRule{ID: "extra"})

	if got := s.Get(); len(got.FwdRules) != 1 || got.FwdRules[0].ID != "r1" {
		t.Fatalf("mutation of Get result leaked into the store: %+v", got.FwdRules)
	}
}

func TestStoreFwdRulesConcurrent(t *testing.T) {
	s := openTestStore(t)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				id := fmt.Sprintf("g%d-r%d", g, i)
				rule := FwdRule{ID: id, PeerID: "p", Mode: "L", ListenPort: 20000 + g*100 + i}
				if err := s.AddFwdRule(rule); err != nil {
					t.Errorf("AddFwdRule(%s): %v", id, err)
					return
				}
				_ = s.Get()
				if err := s.RemoveFwdRule(id); err != nil {
					t.Errorf("RemoveFwdRule(%s): %v", id, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	if got := s.Get().FwdRules; len(got) != 0 {
		t.Fatalf("rules after concurrent add/remove = %+v, want none", got)
	}
}
