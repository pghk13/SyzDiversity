package corpus

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/syzkaller/prog"
)

type ClusterCenter struct {
	ClusterID int
	SeedHash  string
	Program   *prog.Prog
	TreeNodes []string
	TreeAdj   [][]int
}

type mutationStats struct {
	count   int
	rateSum float64
}

// ClusterInfo owns partition membership and scheduling statistics. All state
// changes, including selection counts, are serialized by mu. Reward histories
// retain sufficient statistics rather than one entry per execution.
type ClusterInfo struct {
	mu               sync.RWMutex
	ProgramHashes    map[string]int
	ClusterSizes     map[int]int
	ClusterCenters   map[int]*ClusterCenter
	AccessCount      map[int]int
	SeedAccessCount  map[string]int
	TotalAccess      int
	TotalClusterSize int
	MaxClusterID     int

	SeedCoverageSize    map[string]int
	SeedBugCount        map[string]int
	SeedExecutionTime   map[string]time.Duration
	ClusterSumRewards   map[int]float64
	SeedSumRewards      map[string]float64
	clusterCoverage     map[int]float64
	mutants             map[string]mutationStats
	coverage            map[uint64]struct{}
	started             bool
	similarityThreshold float64
	ExplorationRate     float64
	SyscallCost         int
}

func NewClusterInfo() *ClusterInfo {
	return &ClusterInfo{
		ProgramHashes: make(map[string]int), ClusterSizes: make(map[int]int),
		ClusterCenters: make(map[int]*ClusterCenter), AccessCount: make(map[int]int),
		SeedAccessCount: make(map[string]int), SeedCoverageSize: make(map[string]int),
		SeedBugCount: make(map[string]int), SeedExecutionTime: make(map[string]time.Duration),
		ClusterSumRewards: make(map[int]float64), SeedSumRewards: make(map[string]float64),
		clusterCoverage: make(map[int]float64), mutants: make(map[string]mutationStats),
		coverage: make(map[uint64]struct{}), MaxClusterID: -1,
		similarityThreshold: 0.4, ExplorationRate: 7, SyscallCost: DefaultSyscallCost,
	}
}

func (c *ClusterInfo) SetSimilarityThreshold(threshold float64) {
	if math.IsNaN(threshold) || threshold < 0 || threshold > 1 {
		panic("invalid community similarity threshold")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.similarityThreshold = threshold
}

func (c *ClusterInfo) GetSimilarityThreshold() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.similarityThreshold
}

func (c *ClusterInfo) SetExplorationRate(alpha float64) {
	if math.IsNaN(alpha) || math.IsInf(alpha, 0) || alpha < 1 {
		panic("CPR weight must be finite and at least one")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ExplorationRate = alpha
}

func readClusterCSV(path string, visit func([]string) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	r := csv.NewReader(file)
	r.FieldsPerRecord = -1
	if _, err := r.Read(); err != nil {
		return err
	}
	for line := 2; ; line++ {
		record, err := r.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(record) < 2 {
			return fmt.Errorf("%s:%d: expected two columns", path, line)
		}
		if err := visit(record); err != nil {
			return fmt.Errorf("%s:%d: %w", path, line, err)
		}
	}
}

func (c *ClusterInfo) LoadFromCSV(path string) error {
	labels := make(map[string]int)
	if err := readClusterCSV(path, func(row []string) error {
		id, err := strconv.Atoi(row[1])
		if err != nil {
			return err
		}
		if row[0] == "" || id < 0 {
			return fmt.Errorf("invalid seed or community ID")
		}
		if old, ok := labels[row[0]]; ok && old != id {
			return fmt.Errorf("conflicting community for %s", row[0])
		}
		labels[row[0]] = id
		return nil
	}); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for hash, id := range labels {
		if old, ok := c.ProgramHashes[hash]; ok && old != id {
			return fmt.Errorf("conflicting community for %s", hash)
		}
	}
	for hash, id := range labels {
		c.registerLocked(hash, id)
	}
	return nil
}

func (c *ClusterInfo) LoadClusterCores(path string) error {
	centers := make(map[int]*ClusterCenter)
	if err := readClusterCSV(path, func(row []string) error {
		id, err := strconv.Atoi(row[0])
		if err != nil {
			return err
		}
		if id < 0 || row[1] == "" {
			return fmt.Errorf("invalid community center")
		}
		if previous := centers[id]; previous != nil && previous.SeedHash != row[1] {
			return fmt.Errorf("conflicting centers for community %d", id)
		}
		center := &ClusterCenter{ClusterID: id, SeedHash: row[1]}
		// The centroid may no longer be a live corpus entry after minimization.
		// Preserve its fixed AST across restarts rather than choosing a new one.
		cache := filepath.Join(filepath.Dir(path), "ast_cache", row[1]+".json")
		if data, err := os.ReadFile(cache); err == nil {
			var ast ProgramAST
			if err := json.Unmarshal(data, &ast); err != nil {
				return err
			}
			if err := ast.Validate(); err != nil {
				return err
			}
			center.TreeNodes, center.TreeAdj = ast.Nodes, ast.Adj
		} else if !os.IsNotExist(err) {
			return err
		}
		centers[id] = center
		return nil
	}); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, center := range centers {
		if member, ok := c.ProgramHashes[center.SeedHash]; ok && member != id {
			return fmt.Errorf("center %s is not in community %d", center.SeedHash, id)
		}
	}
	for id, center := range centers {
		// Reloading the labels must not discard already attached programs/ASTs.
		if old := c.ClusterCenters[id]; old != nil && old.SeedHash == center.SeedHash {
			continue
		}
		c.ClusterCenters[id] = center
		c.MaxClusterID = max(c.MaxClusterID, id)
	}
	return nil
}

func (c *ClusterInfo) registerLocked(hash string, id int) {
	if _, exists := c.ProgramHashes[hash]; exists {
		return
	}
	c.ProgramHashes[hash] = id
	c.ClusterSizes[id]++
	c.TotalClusterSize++
	c.MaxClusterID = max(c.MaxClusterID, id)
	if c.AccessCount[id] == 0 {
		c.AccessCount[id] = 1
		if c.started {
			c.ClusterSumRewards[id] = c.clusterRewardLocked(id)
		}
	}
	c.SeedAccessCount[hash] = 1
}

func (c *ClusterInfo) GetClusterID(hash string) (int, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	id, exists := c.ProgramHashes[hash]
	return id, exists
}

func (c *ClusterInfo) GetClusterSize(id int) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ClusterSizes[id]
}

// BindPrograms attaches every available initial centroid before assigning any
// unlabelled seed. A missing centroid is reported rather than silently replaced.
func (c *ClusterInfo) BindPrograms(programs []*prog.Prog) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range programs {
		hash := GetProgHash(p)
		id, ok := c.ProgramHashes[hash]
		if !ok {
			continue
		}
		center := c.ClusterCenters[id]
		if center != nil && center.SeedHash == hash {
			ast, err := BuildProgramAST(p)
			if err != nil {
				return err
			}
			center.Program, center.TreeNodes, center.TreeAdj = p, ast.Nodes, ast.Adj
		}
	}
	for id := range c.ClusterSizes {
		center := c.ClusterCenters[id]
		if center == nil || len(center.TreeNodes) == 0 {
			return fmt.Errorf("community %d has no available centroid; regenerate cluster_core.csv for this corpus", id)
		}
	}
	return nil
}

func (c *ClusterInfo) AssignCluster(p *prog.Prog, hash string) (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id, exists := c.ProgramHashes[hash]; exists {
		return id, false
	}
	ast, err := BuildProgramAST(p)
	if err != nil {
		panic(err)
	}
	bestID, bestSimilarity := -1, math.Inf(-1)
	for id, center := range c.ClusterCenters {
		if len(center.TreeNodes) == 0 {
			continue
		}
		other := &ProgramAST{Nodes: center.TreeNodes, Adj: center.TreeAdj}
		similarity := ASTSimilarity(ast, other, c.SyscallCost)
		if similarity > bestSimilarity || similarity == bestSimilarity && id < bestID {
			bestID, bestSimilarity = id, similarity
		}
	}
	if bestID != -1 && bestSimilarity >= c.similarityThreshold {
		c.registerLocked(hash, bestID)
		return bestID, false
	}
	id := c.MaxClusterID + 1
	c.ClusterCenters[id] = &ClusterCenter{ClusterID: id, SeedHash: hash, Program: p, TreeNodes: ast.Nodes, TreeAdj: ast.Adj}
	c.registerLocked(hash, id)
	return id, true
}

func (c *ClusterInfo) StoreProgramInCluster(p *prog.Prog, hash string, id int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if center := c.ClusterCenters[id]; center != nil && center.SeedHash == hash && center.Program == nil {
		ast, err := BuildProgramAST(p)
		if err != nil {
			return
		}
		center.Program, center.TreeNodes, center.TreeAdj = p, ast.Nodes, ast.Adj
	}
}

func (c *ClusterInfo) cprLocked(id int) float64 {
	if c.ClusterSizes[id] == 0 {
		return 0
	}
	return float64(c.AccessCount[id]) * float64(c.TotalClusterSize) / float64(c.ClusterSizes[id])
}

func (c *ClusterInfo) CalculateCPR(id int) float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cprLocked(id)
}

func (c *ClusterInfo) clusterRewardLocked(id int) float64 {
	if c.ClusterSizes[id] == 0 {
		return 0
	}
	return c.clusterCoverage[id]/float64(c.ClusterSizes[id]) + c.ExplorationRate*c.cprLocked(id)
}

func (c *ClusterInfo) CalculateClusterInstantReward(id int) float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clusterRewardLocked(id)
}

func ucb(sum float64, visits, rounds int) float64 {
	return sum/float64(visits) + math.Sqrt(2*math.Log(float64(rounds))/float64(visits))
}

// ChooseProgram performs both argmax operations and accounts for exactly one
// scheduling round. Warm-up changes only the community objective to CPR.
func (c *ClusterInfo) ChooseProgram(rnd *rand.Rand, programs []*prog.Prog, warmup bool) *prog.Prog {
	items := make([]*Item, 0, len(programs))
	for _, p := range programs {
		items = append(items, &Item{Prog: p, Sig: GetProgHash(p)})
	}
	return c.chooseItems(rnd, items, warmup)
}

func (c *ClusterInfo) chooseItems(rnd *rand.Rand, items []*Item, warmup bool) *prog.Prog {
	if len(items) == 0 {
		return nil
	}
	var missing []*Item
	c.mu.RLock()
	for _, item := range items {
		if _, exists := c.ProgramHashes[item.Sig]; !exists {
			missing = append(missing, item)
		}
	}
	c.mu.RUnlock()
	for _, item := range missing {
		c.AssignCluster(item.Prog, item.Sig)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	groups := make(map[int][]*Item)
	for _, item := range items {
		id := c.ProgramHashes[item.Sig]
		groups[id] = append(groups[id], item)
	}
	if !c.started {
		for id := range c.ClusterSizes {
			c.ClusterSumRewards[id] = c.clusterRewardLocked(id)
		}
		c.started = true
	}
	ids := make([]int, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	bestID, bestScore, ties := -1, math.Inf(-1), 0
	for _, id := range ids {
		score := ucb(c.ClusterSumRewards[id], c.AccessCount[id], c.TotalAccess+1)
		if warmup {
			score = c.cprLocked(id)
		}
		if score > bestScore {
			bestID, bestScore, ties = id, score, 1
		} else if score == bestScore {
			ties++
			if rnd.Intn(ties) == 0 {
				bestID = id
			}
		}
	}
	var selected *Item
	bestScore, ties = math.Inf(-1), 0
	for _, item := range groups[bestID] {
		hash := item.Sig
		score := ucb(c.SeedSumRewards[hash], c.SeedAccessCount[hash], c.TotalAccess+1)
		if warmup {
			score = 0
		}
		if score > bestScore {
			selected, bestScore, ties = item, score, 1
		} else if score == bestScore {
			ties++
			if rnd.Intn(ties) == 0 {
				selected = item
			}
		}
	}
	c.AccessCount[bestID]++
	c.SeedAccessCount[selected.Sig]++
	c.TotalAccess++
	return selected.Prog
}

// UseSmash ranks nonempty communities by CPR, breaking ties by community ID.
func (c *ClusterInfo) UseSmash(hash string, top int) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	id, exists := c.ProgramHashes[hash]
	if !exists || top <= 0 {
		return false
	}
	value, rank := c.cprLocked(id), 1
	for other, size := range c.ClusterSizes {
		if size == 0 {
			continue
		}
		if score := c.cprLocked(other); score > value || score == value && other < id {
			rank++
		}
	}
	return rank <= top
}

// RecordExecution returns globally new coverage. Failed/zero-gain mutants still
// contribute a sample to Eq. 8, but only useful seeds enter the partition.
func (c *ClusterInfo) RecordExecution(p *prog.Prog, parent string, rawCover []uint64, elapsed time.Duration, crashed, initial bool) int {
	c.mu.Lock()
	gain := 0
	for _, pc := range rawCover {
		if _, ok := c.coverage[pc]; !ok {
			c.coverage[pc] = struct{}{}
			gain++
		}
	}
	c.mu.Unlock()
	hash := GetProgHash(p)
	if initial || gain > 0 || crashed {
		c.AssignCluster(p, hash)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if id, ok := c.ProgramHashes[hash]; ok {
		old := float64(c.SeedCoverageSize[hash] * (1 + c.SeedBugCount[hash]))
		c.SeedCoverageSize[hash] += gain
		if crashed {
			c.SeedBugCount[hash] = 1
		}
		c.SeedExecutionTime[hash] = elapsed
		c.clusterCoverage[id] += float64(c.SeedCoverageSize[hash]*(1+c.SeedBugCount[hash])) - old
		if c.started && c.AccessCount[id] == 1 {
			c.ClusterSumRewards[id] = c.clusterRewardLocked(id)
		}
	}
	if parent != "" {
		stats := c.mutants[parent]
		stats.count++
		if elapsed <= 0 {
			elapsed = time.Millisecond
		}
		multiplier := 1.0
		if crashed {
			multiplier = 2
		}
		stats.rateSum += float64(gain) / elapsed.Seconds() * multiplier
		c.mutants[parent] = stats
	}
	return gain
}

// FinishMutationRound takes one historical reward sample after the entire
// regular/smash batch, not once per child and not once per triage rerun.
func (c *ClusterInfo) FinishMutationRound(hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id, exists := c.ProgramHashes[hash]
	if !exists {
		return
	}
	stats := c.mutants[hash]
	if stats.count > 0 {
		c.SeedSumRewards[hash] += stats.rateSum / float64(stats.count)
	}
	c.ClusterSumRewards[id] += c.clusterRewardLocked(id)
}

func writeClusterCSV(path string, rows [][]string) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".cluster-*.csv")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	w := csv.NewWriter(file)
	err = w.WriteAll(rows)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(file.Name(), path)
}

func (c *ClusterInfo) SaveClusterLabel(path string) error {
	c.mu.RLock()
	rows := [][]string{{"ProgramHash", "ClusterID"}}
	hashes := make([]string, 0, len(c.ProgramHashes))
	for hash := range c.ProgramHashes {
		hashes = append(hashes, hash)
	}
	sort.Strings(hashes)
	for _, hash := range hashes {
		rows = append(rows, []string{hash, strconv.Itoa(c.ProgramHashes[hash])})
	}
	c.mu.RUnlock()
	return writeClusterCSV(path, rows)
}

func (c *ClusterInfo) SaveClusterCores(path string) error {
	c.mu.RLock()
	rows := [][]string{{"ClusterID", "SeedHash"}}
	ids := make([]int, 0, len(c.ClusterCenters))
	for id := range c.ClusterCenters {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		rows = append(rows, []string{strconv.Itoa(id), c.ClusterCenters[id].SeedHash})
	}
	c.mu.RUnlock()
	return writeClusterCSV(path, rows)
}

func (c *ClusterInfo) SaveClusterASTs(dir string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for _, center := range c.ClusterCenters {
		if len(center.TreeNodes) == 0 {
			continue
		}
		ast := &ProgramAST{Nodes: center.TreeNodes, Adj: center.TreeAdj}
		data, err := json.Marshal(ast)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, center.SeedHash+".json"), data, 0644); err != nil {
			return err
		}
	}
	return nil
}
