package mgrconfig

import (
	"testing"

	_ "github.com/google/syzkaller/sys"
)

func TestDiversityConfig(t *testing.T) {
	cfg, err := LoadPartialData([]byte(`{"target":"test/64"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := DiversityConfig{SyscallCost: 5, CPRWeight: 7, MutationTop: 2, SimilarityThreshold: 0.4}
	if cfg.Diversity != want {
		t.Fatalf("defaults=%+v, want %+v", cfg.Diversity, want)
	}
	cfg, err = LoadPartialData([]byte(`{"target":"test/64","diversity":{"cpr_weight":9,"mutation_top":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Diversity.CPRWeight != 9 || cfg.Diversity.MutationTop != 1 || cfg.Diversity.SyscallCost != 5 {
		t.Fatal("partial override lost defaults")
	}
	for _, input := range []string{
		`{"target":"test/64","diversity":{"cpr_weight":0.3}}`,
		`{"target":"test/64","diversity":{"syscall_cost":0}}`,
		`{"target":"test/64","diversity":{"mutation_top":0}}`,
		`{"target":"test/64","diversity":{"similarity_threshold":1.1}}`,
	} {
		if _, err := LoadPartialData([]byte(input)); err == nil {
			t.Fatalf("accepted invalid configuration: %s", input)
		}
	}
}
