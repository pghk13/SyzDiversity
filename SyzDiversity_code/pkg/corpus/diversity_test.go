package corpus

import (
	"encoding/json"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/syzkaller/prog"
)

func diversityProgram(t *testing.T, text string) *prog.Prog {
	t.Helper()
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(text), prog.Strict)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWeightedTEDReference(t *testing.T) {
	// Reference distances were computed independently with edist 1.2.2.
	data, err := os.ReadFile("testdata/weighted_ted.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Left, Right ProgramAST
		Distance    int
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for i, test := range cases {
		x, y := test.Left, test.Right
		if got := CalculateTED(x.Nodes, x.Adj, y.Nodes, y.Adj); got != test.Distance {
			t.Fatalf("case %d: distance=%d, want %d", i, got, test.Distance)
		}
		if got := CalculateTED(y.Nodes, y.Adj, x.Nodes, x.Adj); got != test.Distance {
			t.Fatalf("case %d: reverse distance=%d, want %d", i, got, test.Distance)
		}
	}
}

func TestDiversityAST(t *testing.T) {
	p := diversityProgram(t, "test$int(0x1, 0x2, 0x3, 0x4, 0x5)")
	ast, err := BuildProgramAST(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ast.Nodes) != 7 || len(ast.Adj[1]) != 5 {
		t.Fatalf("argument type and value must occupy one node: %+v", ast)
	}
	q := p.Clone()
	q.Calls[0].Args[0].(*prog.ConstArg).Val++
	other, _ := BuildProgramAST(q)
	if got := ASTSimilarity(ast, other, 5); math.Abs(got-6.0/7) > 1e-12 {
		t.Fatal(got)
	}
	pointer := diversityProgram(t, "test$opt1(&(0x7f0000000000)=0x1)")
	before, _ := BuildProgramAST(pointer)
	pointer.Calls[0].Args[0].(*prog.PointerArg).Address += 64
	after, _ := BuildProgramAST(pointer)
	if got := ASTSimilarity(before, after, 5); got != 1 {
		t.Fatal(got)
	}
	x := &ProgramAST{Nodes: []string{"ProgramAST", "test$a"}, Adj: [][]int{{1}, {}}}
	y := &ProgramAST{Nodes: []string{"ProgramAST", "test$b"}, Adj: [][]int{{1}, {}}}
	if got := CalculateTED(x.Nodes, x.Adj, y.Nodes, y.Adj); got != 5 {
		t.Fatal(got)
	}
}

func TestDiversityAssignment(t *testing.T) {
	info := NewClusterInfo()
	p := diversityProgram(t, "test$int(0x1, 0x2, 0x3, 0x4, 0x5)")
	id, created := info.AssignCluster(p, GetProgHash(p))
	if !created || info.AccessCount[id] != 1 {
		t.Fatal("first seed must create an initialized community")
	}
	q := p.Clone()
	q.Calls[0].Args[0].(*prog.ConstArg).Val++
	joined, created := info.AssignCluster(q, GetProgHash(q))
	if created || joined != id {
		t.Fatal("similar seed did not join its nearest centroid")
	}
	r := diversityProgram(t, "test()")
	other, created := info.AssignCluster(r, GetProgHash(r))
	if !created || other == id {
		t.Fatal("dissimilar seed did not create a community")
	}
	info.AssignCluster(q, GetProgHash(q))
	if info.TotalClusterSize != 3 || info.ClusterSizes[id] != 2 {
		t.Fatal("duplicate assignment changed population")
	}
	if info.ClusterCenters[id].SeedHash != GetProgHash(p) {
		t.Fatal("initial centroid moved")
	}
	if info.CalculateCPR(id) != 1.5 || info.CalculateCPR(other) != 3 {
		t.Fatal("incorrect CPR")
	}
	if info.UseSmash(GetProgHash(p), 1) || !info.UseSmash(GetProgHash(r), 1) {
		t.Fatal("incorrect CPR ranking")
	}
}

func TestDiversityCSV(t *testing.T) {
	p := diversityProgram(t, "test()")
	hash := GetProgHash(p)
	dir := t.TempDir()
	labels := filepath.Join(dir, "cluster_info.csv")
	cores := filepath.Join(dir, "cluster_core.csv")
	os.WriteFile(labels, []byte("ProgramHash,ClusterID\n"+hash+",4\n"+hash+",4\n"), 0600)
	os.WriteFile(cores, []byte("ClusterID,SeedHash\n4,"+hash+"\n"), 0600)
	info := NewClusterInfo()
	if err := info.LoadFromCSV(labels); err != nil {
		t.Fatal(err)
	}
	if err := info.LoadFromCSV(labels); err != nil {
		t.Fatal(err)
	}
	if info.TotalClusterSize != 1 || info.AccessCount[4] != 1 {
		t.Fatal("CSV loading is not idempotent")
	}
	if err := info.LoadClusterCores(cores); err != nil {
		t.Fatal(err)
	}
	if err := info.BindPrograms([]*prog.Prog{p}); err != nil {
		t.Fatal(err)
	}
	if err := info.LoadClusterCores(cores); err != nil {
		t.Fatal(err)
	}
	if info.ClusterCenters[4].Program == nil {
		t.Fatal("reload erased attached centroid")
	}
	os.WriteFile(labels, []byte("ProgramHash,ClusterID\nbroken\n"), 0600)
	if err := info.LoadFromCSV(labels); err == nil {
		t.Fatal("accepted malformed labels")
	}
	if info.TotalClusterSize != 1 {
		t.Fatal("failed load mutated the partition")
	}
}

func TestDiversityRewards(t *testing.T) {
	info := NewClusterInfo()
	p := diversityProgram(t, "test$int(0x1, 0x2, 0x3, 0x4, 0x5)")
	q := diversityProgram(t, "test$int(0x2, 0x2, 0x3, 0x4, 0x5)")
	hash := GetProgHash(p)
	info.AssignCluster(p, hash)
	info.AssignCluster(q, GetProgHash(q))
	info.RecordExecution(p, "", []uint64{1, 2, 3, 4}, time.Second, true, true)
	info.RecordExecution(q, "", []uint64{5, 6}, time.Second, false, true)
	id, _ := info.GetClusterID(hash)
	// Avg(4*(1+1), 2*(1+0)) + 7*1 = 12, not Avg(cov)*(1+Avg(crash)).
	if got := info.CalculateClusterInstantReward(id); got != 12 {
		t.Fatal(got)
	}
	info.ChooseProgram(rand.New(rand.NewSource(1)), []*prog.Prog{p}, false)
	initial := info.ClusterSumRewards[id]
	info.RecordExecution(q, hash, []uint64{7, 7, 8}, 2*time.Second, false, false)
	info.RecordExecution(q, hash, []uint64{8, 9}, time.Second, true, false)
	info.RecordExecution(q, hash, []uint64{9}, time.Second, false, false)
	if got := info.mutants[hash]; got.count != 3 || got.rateSum != 3 {
		t.Fatalf("wrong offspring statistics: %+v", got)
	}
	info.FinishMutationRound(hash)
	if info.SeedSumRewards[hash] != 1 || info.SeedAccessCount[hash] != 2 {
		t.Fatal("Eq. 8/9 did not account one mutation round")
	}
	if info.ClusterSumRewards[id] != initial+info.CalculateClusterInstantReward(id) {
		t.Fatal("community reward history was replaced")
	}
	if got := ucb(info.SeedSumRewards[hash], 2, 2); math.Abs(got-(0.5+math.Sqrt(math.Log(2)))) > 1e-12 {
		t.Fatal(got)
	}
	// No coverage does not justify new membership, but is still a reward sample.
	r := diversityProgram(t, "test()")
	info.RecordExecution(r, hash, nil, time.Second, false, false)
	if _, ok := info.GetClusterID(GetProgHash(r)); ok {
		t.Fatal("zero-gain mutant entered partition")
	}
	info.RecordExecution(r, hash, nil, 0, true, false)
	if _, ok := info.GetClusterID(GetProgHash(r)); !ok {
		t.Fatal("crash-only mutant was discarded")
	}
}

func TestDiversityUCBUsesHistory(t *testing.T) {
	info := NewClusterInfo()
	p := diversityProgram(t, "test()")
	q := diversityProgram(t, "test$int(0x1,0x2,0x3,0x4,0x5)")
	a, _ := info.AssignCluster(p, GetProgHash(p))
	b, _ := info.AssignCluster(q, GetProgHash(q))
	info.started = true
	info.ClusterSumRewards[a] = 100
	info.ClusterSumRewards[b] = 0
	rnd := rand.New(rand.NewSource(3))
	for i := 0; i < 25; i++ {
		if got := info.ChooseProgram(rnd, []*prog.Prog{p, q}, false); got != p {
			t.Fatal("selection did not use argmax of historical UCB")
		}
	}
	if info.TotalAccess != 25 || info.AccessCount[a] != 26 || info.SeedAccessCount[GetProgHash(p)] != 26 {
		t.Fatal("selection counters drifted")
	}
}

func TestDiversityConcurrentAccounting(t *testing.T) {
	info := NewClusterInfo()
	p := diversityProgram(t, "test()")
	hash := GetProgHash(p)
	info.AssignCluster(p, hash)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(int64(seed)))
			for i := 0; i < 50; i++ {
				info.ChooseProgram(rnd, []*prog.Prog{p}, false)
				info.RecordExecution(p, hash, []uint64{1, 1}, time.Millisecond, false, false)
				info.FinishMutationRound(hash)
			}
		}(worker)
	}
	wg.Wait()
	if info.TotalAccess != 400 || info.SeedAccessCount[hash] != 401 || info.SeedCoverageSize[hash] != 1 {
		t.Fatal("concurrent accounting lost or duplicated updates")
	}
}

func TestDiversityCentroidPersistence(t *testing.T) {
	info := NewClusterInfo()
	p := diversityProgram(t, "test()")
	id, _ := info.AssignCluster(p, GetProgHash(p))
	dir := t.TempDir()
	if err := info.SaveClusterLabel(filepath.Join(dir, "cluster_info.csv")); err != nil {
		t.Fatal(err)
	}
	if err := info.SaveClusterCores(filepath.Join(dir, "cluster_core.csv")); err != nil {
		t.Fatal(err)
	}
	if err := info.SaveClusterASTs(filepath.Join(dir, "ast_cache")); err != nil {
		t.Fatal(err)
	}
	restored := NewClusterInfo()
	if err := restored.LoadFromCSV(filepath.Join(dir, "cluster_info.csv")); err != nil {
		t.Fatal(err)
	}
	if err := restored.LoadClusterCores(filepath.Join(dir, "cluster_core.csv")); err != nil {
		t.Fatal(err)
	}
	if err := restored.BindPrograms(nil); err != nil {
		t.Fatal(err)
	}
	if got := restored.ClusterCenters[id]; got.SeedHash != GetProgHash(p) || len(got.TreeNodes) == 0 {
		t.Fatal("centroid was not restored")
	}
}
