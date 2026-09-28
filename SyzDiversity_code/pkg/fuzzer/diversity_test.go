package fuzzer

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/prog"
)

func newDiversityFuzzer(t *testing.T, enabled bool) (*Fuzzer, *prog.Prog) {
	t.Helper()
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte("test$int(0x1,0x2,0x3,0x4,0x5)"), prog.Strict)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg := &Config{Corpus: corpus.NewCorpus(ctx), WarmupDuration: -1}
	cfg.Corpus.Save(corpus.NewInput{Prog: p})
	if enabled {
		cfg.ClusterInfo = corpus.NewClusterInfo()
		cfg.ClusterInfo.AssignCluster(p, GetProgHash(p))
	}
	return NewFuzzer(ctx, cfg, rand.New(rand.NewSource(8)), target), p
}

func TestDiversityCollectsCoverage(t *testing.T) {
	f, p := newDiversityFuzzer(t, true)
	req := &queue.Request{Prog: p, ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal)}
	f.prepare(req, 0, 0)
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectCover == 0 {
		t.Fatal("mutation execution does not collect raw coverage")
	}
	comparison := &queue.Request{Prog: p, ExecOpts: setFlags(flatrpc.ExecFlagCollectComps)}
	f.prepare(comparison, 0, 0)
	if comparison.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectCover != 0 {
		t.Fatal("comparison execution has incompatible coverage flag")
	}
}

func TestDiversityErrnoIsNotCrash(t *testing.T) {
	f, p := newDiversityFuzzer(t, true)
	hash := GetProgHash(p)
	req := &queue.Request{Prog: p}
	result := &queue.Result{Status: queue.Success, Info: &flatrpc.ProgInfo{
		Elapsed: uint64(time.Millisecond), Calls: []*flatrpc.CallInfo{{Error: 22, Cover: []uint64{1, 1, 2}}},
	}}
	f.recordDiversityResult(req, result, 0)
	if f.ClusterInfo.SeedBugCount[hash] != 0 || f.ClusterInfo.SeedCoverageSize[hash] != 2 {
		t.Fatal("errno or duplicate coverage inflated reward")
	}
	f.recordDiversityResult(req, result, 0)
	if f.ClusterInfo.SeedCoverageSize[hash] != 2 {
		t.Fatal("repeated coverage counted as growth")
	}
	f.recordDiversityResult(req, &queue.Result{Status: queue.Crashed}, 0)
	if f.ClusterInfo.SeedBugCount[hash] != 1 || f.Config.Corpus.Item(hash) == nil {
		t.Fatal("crash without ProgInfo was lost")
	}
}

func TestDiversityTriageDoesNotEarnReward(t *testing.T) {
	f, p := newDiversityFuzzer(t, true)
	req := &queue.Request{Prog: p, OriginSeedHash: GetProgHash(p)}
	res := &queue.Result{Status: queue.Success, Info: &flatrpc.ProgInfo{Calls: []*flatrpc.CallInfo{{Cover: []uint64{90}}}}}
	f.processResult(req, res, progInTriage, 0)
	if f.ClusterInfo.SeedCoverageSize[GetProgHash(p)] != 0 {
		t.Fatal("triage consumed mutant coverage gain")
	}
}

func TestDiversityMutationBatch(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "regular", true: "smash"}[enabled], func(t *testing.T) {
			f, p := newDiversityFuzzer(t, enabled)
			var first *queue.Request
			for i := 0; i < 100; i++ {
				first = f.genFuzz()
				if !first.IsGenerated {
					break
				}
			}
			if first.IsGenerated {
				t.Fatal("no mutation selected")
			}
			requests := []*queue.Request{first}
			for {
				req := f.smashQueue.Next()
				if req == nil {
					break
				}
				requests = append(requests, req)
			}
			want := 1
			if enabled {
				want = 25
			}
			if len(requests) != want {
				t.Fatalf("batch=%d, want %d", len(requests), want)
			}
			for i, req := range requests {
				if req.OriginSeedHash != GetProgHash(p) {
					t.Fatal("lost parent provenance")
				}
				req.Done(&queue.Result{Status: queue.Success, Info: &flatrpc.ProgInfo{
					Elapsed: uint64(time.Second), Calls: []*flatrpc.CallInfo{{Cover: []uint64{1, 1}}},
				}})
				if enabled && i < len(requests)-1 && f.ClusterInfo.SeedSumRewards[GetProgHash(p)] != 0 {
					t.Fatal("reward recorded before batch completion")
				}
			}
			if enabled {
				if f.ClusterInfo.TotalAccess != 1 || f.ClusterInfo.SeedAccessCount[GetProgHash(p)] != 2 {
					t.Fatal("counted offspring as scheduling rounds")
				}
				if got := f.ClusterInfo.SeedSumRewards[GetProgHash(p)]; got != 1.0/25 {
					t.Fatal(got)
				}
			}
		})
	}
}
