// Copyright 2025 SyzDiversity project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

type Fuzzer struct {
	Stats
	Config *Config
	Cover  *Cover

	ctx          context.Context
	mu           sync.Mutex
	rnd          *rand.Rand
	target       *prog.Target
	hintsLimiter prog.HintsLimiter
	runningJobs  map[jobIntrospector]struct{}

	ct           *prog.ChoiceTable
	ctProgs      int
	ctMu         sync.Mutex // TODO: use RWLock.
	ctRegenerate chan struct{}
	ClusterInfo  *corpus.ClusterInfo
	startTime    time.Time

	execQueues
}

func NewFuzzer(ctx context.Context, cfg *Config, rnd *rand.Rand,
	target *prog.Target) *Fuzzer {
	if cfg.NewInputFilter == nil {
		cfg.NewInputFilter = func(call string) bool {
			return true
		}
	}

	// Initialize diversity scheduling defaults.
	initializeDiversityConfig(cfg)
	f := &Fuzzer{
		Stats:       newStats(target),
		Config:      cfg,
		Cover:       newCover(),
		ClusterInfo: cfg.ClusterInfo,
		startTime:   time.Now(),

		ctx:         ctx,
		rnd:         rnd,
		target:      target,
		runningJobs: map[jobIntrospector]struct{}{},

		// We're okay to lose some of the messages -- if we are already
		// regenerating the table, we don't want to repeat it right away.
		ctRegenerate: make(chan struct{}),
	}
	f.execQueues = newExecQueues(f)
	// Initialize ClusterInfo
	f.initClusterInfo(cfg)

	f.updateChoiceTable(nil)
	go f.choiceTableUpdater()
	if cfg.Debug {
		go f.logCurrentStats()
	}

	// Start cluster info save thread
	if f.ClusterInfo != nil && cfg.Workdir != "" {
		go f.periodicSaveClusterInfo()
	}

	return f
}

type execQueues struct {
	triageCandidateQueue *queue.DynamicOrderer
	candidateQueue       *queue.PlainQueue
	triageQueue          *queue.DynamicOrderer
	smashQueue           *queue.PlainQueue
	source               queue.Source
}

func newExecQueues(fuzzer *Fuzzer) execQueues {
	ret := execQueues{
		triageCandidateQueue: queue.DynamicOrder(),
		candidateQueue:       queue.Plain(),
		triageQueue:          queue.DynamicOrder(),
		smashQueue:           queue.Plain(),
	}
	// Alternate smash jobs with exec/fuzz to spread attention to the wider area.
	skipQueue := 3
	if fuzzer.Config.PatchTest {
		// When we do patch fuzzing, we do not focus on finding and persisting
		// new coverage that much, so it's reasonable to spend more time just
		// mutating various corpus programs.
		skipQueue = 2
	}
	// Sources are listed in the order, in which they will be polled.
	ret.source = queue.Order(
		ret.triageCandidateQueue,
		ret.candidateQueue,
		ret.triageQueue,
		queue.Alternate(ret.smashQueue, skipQueue),
		queue.Callback(fuzzer.genFuzz),
	)
	return ret
}

func (fuzzer *Fuzzer) CandidateTriageFinished() bool {
	return fuzzer.statCandidates.Val()+fuzzer.statJobsTriageCandidate.Val() == 0
}

func (fuzzer *Fuzzer) execute(executor queue.Executor, req *queue.Request) *queue.Result {
	return fuzzer.executeWithFlags(executor, req, 0)
}

func (fuzzer *Fuzzer) executeWithFlags(executor queue.Executor, req *queue.Request, flags ProgFlags) *queue.Result {
	fuzzer.enqueue(executor, req, flags, 0)
	return req.Wait(fuzzer.ctx)
}

func (fuzzer *Fuzzer) prepare(req *queue.Request, flags ProgFlags, attempt int) {
	if fuzzer.ClusterInfo != nil && req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal != 0 {
		req.ExecOpts.ExecFlags |= flatrpc.ExecFlagCollectCover
	}
	req.OnDone(func(req *queue.Request, res *queue.Result) bool {
		return fuzzer.processResult(req, res, flags, attempt)
	})
}

func (fuzzer *Fuzzer) enqueue(executor queue.Executor, req *queue.Request, flags ProgFlags, attempt int) {
	fuzzer.prepare(req, flags, attempt)
	executor.Submit(req)
}

func (fuzzer *Fuzzer) processResult(req *queue.Request, res *queue.Result, flags ProgFlags, attempt int) bool {
	// Triage and minimization reruns must not earn mutation rewards or consume
	// coverage before the original execution has been accounted for.
	if fuzzer.ClusterInfo != nil && flags&progInTriage == 0 && req.Prog != nil {
		fuzzer.recordDiversityResult(req, res, flags)
	}

	dontTriage := flags&progInTriage > 0 || res.Status == queue.Hanged
	var triage map[int]*triageCall
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal > 0 && res.Info != nil && !dontTriage {
		for callIdx, info := range res.Info.Calls {
			fuzzer.triageProgCall(req.Prog, info, callIdx, &triage)
		}
		fuzzer.triageProgCall(req.Prog, res.Info.Extra, -1, &triage)

		if len(triage) != 0 {
			queueForJob, statForJob := fuzzer.triageQueue, fuzzer.statJobsTriage
			if flags&progCandidate > 0 {
				queueForJob, statForJob = fuzzer.triageCandidateQueue, fuzzer.statJobsTriageCandidate
			}
			job := &triageJob{
				p:        req.Prog.Clone(),
				executor: res.Executor,
				flags:    flags,
				queue:    queueForJob.Append(),
				calls:    triage,
				info: &JobInfo{
					Name: req.Prog.String(),
					Type: "triage",
				},
			}
			for id := range triage {
				job.info.Calls = append(job.info.Calls, job.p.CallName(id))
			}
			sort.Strings(job.info.Calls)
			fuzzer.startJob(statForJob, job)
		}
	}

	if res.Info != nil {
		fuzzer.statExecTime.Add(int(res.Info.Elapsed / 1e6))
		for call, info := range res.Info.Calls {
			fuzzer.handleCallInfo(req, info, call)
		}
		fuzzer.handleCallInfo(req, res.Info.Extra, -1)

	}

	maxCandidateAttempts := 3
	if req.Risky() {
		maxCandidateAttempts = 2
		if fuzzer.Config.Snapshot || res.Status == queue.Hanged {
			maxCandidateAttempts = 0
		}
	}
	if len(triage) == 0 && flags&ProgFromCorpus != 0 && attempt < maxCandidateAttempts {
		fuzzer.enqueue(fuzzer.candidateQueue, req, flags, attempt+1)
		return false
	}
	if flags&progCandidate != 0 {
		fuzzer.statCandidates.Add(-1)
	}
	return true
}

type Config struct {
	Debug                      bool
	Corpus                     *corpus.Corpus
	Logf                       func(level int, msg string, args ...interface{})
	Snapshot                   bool
	Coverage                   bool
	FaultInjection             bool
	Comparisons                bool
	Collide                    bool
	EnabledCalls               map[*prog.Syscall]bool
	NoMutateCalls              map[int]bool
	FetchRawCover              bool
	NewInputFilter             func(call string) bool
	PatchTest                  bool
	Workdir                    string              // Working directory
	ClusterInfo                *corpus.ClusterInfo // Cluster information
	ClusterSimilarityThreshold float64             // Cluster similarity threshold

	MutationTop       int
	WarmupDuration    time.Duration
	WarmupProbability float64
}

func (fuzzer *Fuzzer) triageProgCall(p *prog.Prog, info *flatrpc.CallInfo, call int, triage *map[int]*triageCall) {
	if info == nil {
		return
	}
	prio := signalPrio(p, info, call)
	newMaxSignal := fuzzer.Cover.addRawMaxSignal(info.Signal, prio)
	if newMaxSignal.Empty() {
		return
	}
	if !fuzzer.Config.NewInputFilter(p.CallName(call)) {
		return
	}
	fuzzer.Logf(2, "found new signal in call %d in %s", call, p)
	if *triage == nil {
		*triage = make(map[int]*triageCall)
	}
	(*triage)[call] = &triageCall{
		errno:     info.Error,
		newSignal: newMaxSignal,
		signals:   [deflakeNeedRuns]signal.Signal{signal.FromRaw(info.Signal, prio)},
	}
}

func (fuzzer *Fuzzer) handleCallInfo(req *queue.Request, info *flatrpc.CallInfo, call int) {
	if info == nil || info.Flags&flatrpc.CallFlagCoverageOverflow == 0 {
		return
	}
	syscallIdx := len(fuzzer.Syscalls) - 1
	if call != -1 {
		syscallIdx = req.Prog.Calls[call].Meta.ID
	}
	stat := &fuzzer.Syscalls[syscallIdx]
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectComps != 0 {
		stat.CompsOverflows.Add(1)
	} else {
		stat.CoverOverflows.Add(1)
	}
}

func signalPrio(p *prog.Prog, info *flatrpc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Error == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

const (
	TopCPRClusters  = 2
	smashIterations = 25
)

func initializeDiversityConfig(cfg *Config) {
	if cfg.MutationTop == 0 {
		cfg.MutationTop = TopCPRClusters
	}
	if cfg.WarmupDuration == 0 {
		cfg.WarmupDuration = 4 * time.Hour
	}
	if cfg.WarmupProbability == 0 {
		cfg.WarmupProbability = 0.25
	}
}

func (fuzzer *Fuzzer) genFuzz() *queue.Request {
	rnd := fuzzer.rand()
	var selected *prog.Prog
	if rnd.Float64() < 0.95 {
		if fuzzer.ClusterInfo == nil {
			selected = fuzzer.Config.Corpus.ChooseProgram(rnd)
		} else {
			warmup := time.Since(fuzzer.startTime) < fuzzer.Config.WarmupDuration &&
				rnd.Float64() < fuzzer.Config.WarmupProbability
			selected = fuzzer.Config.Corpus.ChooseProgramCommunity(rnd, fuzzer.ClusterInfo, warmup)
		}
	}
	if selected == nil {
		req := genProgRequest(fuzzer, rnd)
		fuzzer.prepare(req, 0, 0)
		return req
	}
	hash := GetProgHash(selected)
	count := 1
	if fuzzer.ClusterInfo != nil && fuzzer.ClusterInfo.UseSmash(hash, fuzzer.Config.MutationTop) {
		count = smashIterations
	}
	var remaining atomic.Int32
	remaining.Store(int32(count))
	var first *queue.Request
	for i := 0; i < count; i++ {
		p := selected.Clone()
		p.Mutate(rnd, prog.RecommendedCalls, fuzzer.ChoiceTable(),
			fuzzer.Config.NoMutateCalls, fuzzer.Config.Corpus.Programs())
		execStat := fuzzer.statExecFuzz
		if count > 1 {
			execStat = fuzzer.statExecSmash
		}
		if fuzzer.Config.Collide && rnd.Intn(3) == 0 {
			p = randomCollide(p, rnd)
			execStat = fuzzer.statExecCollide
		}
		req := &queue.Request{
			Prog: p, ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal), Stat: execStat,
			OriginSeedHash: hash, MutationDepth: 1,
		}
		req.OnDone(func(req *queue.Request, res *queue.Result) bool {
			if remaining.Add(-1) == 0 && fuzzer.ClusterInfo != nil {
				fuzzer.ClusterInfo.FinishMutationRound(hash)
			}
			return true
		})
		if i == 0 {
			first = req
			fuzzer.prepare(req, 0, 0)
		} else {
			fuzzer.enqueue(fuzzer.smashQueue, req, 0, 0)
		}
	}
	return first
}

func (fuzzer *Fuzzer) recordDiversityResult(req *queue.Request, res *queue.Result, flags ProgFlags) {
	if res.Status != queue.Success && res.Status != queue.Crashed {
		return
	}
	var coverage []uint64
	var elapsed time.Duration
	if res.Info != nil {
		elapsed = time.Duration(res.Info.Elapsed)
		for _, call := range res.Info.Calls {
			if call != nil {
				coverage = append(coverage, call.Cover...)
			}
		}
		if res.Info.Extra != nil {
			coverage = append(coverage, res.Info.Extra.Cover...)
		}
	}
	crashed := res.Status == queue.Crashed
	fuzzer.ClusterInfo.RecordExecution(req.Prog, req.OriginSeedHash, coverage, elapsed,
		crashed, flags&progCandidate != 0)
	// Ordinary syscall errno values are not kernel crashes. A real crash can
	// have no ProgInfo at all, and still qualifies for community admission.
	if crashed {
		fuzzer.Config.Corpus.Save(corpus.NewInput{Prog: req.Prog.Clone(), Call: -1, Cover: coverage})
	}
}

func (fuzzer *Fuzzer) startJob(stat *stat.Val, newJob job) {
	fuzzer.Logf(2, "started %T", newJob)
	go func() {
		stat.Add(1)
		defer stat.Add(-1)

		fuzzer.statJobs.Add(1)
		defer fuzzer.statJobs.Add(-1)

		if obj, ok := newJob.(jobIntrospector); ok {
			fuzzer.mu.Lock()
			fuzzer.runningJobs[obj] = struct{}{}
			fuzzer.mu.Unlock()

			defer func() {
				fuzzer.mu.Lock()
				delete(fuzzer.runningJobs, obj)
				fuzzer.mu.Unlock()
			}()
		}

		newJob.run(fuzzer)
	}()
}

func (fuzzer *Fuzzer) Next() *queue.Request {
	req := fuzzer.source.Next()
	if req == nil {
		// The fuzzer is not supposed to issue nil requests.
		panic("nil request from the fuzzer")
	}
	return req
}

func (fuzzer *Fuzzer) Logf(level int, msg string, args ...interface{}) {
	if fuzzer.Config.Logf == nil {
		return
	}
	fuzzer.Config.Logf(level, msg, args...)
}

type ProgFlags int

const (
	// The candidate was loaded from our local corpus rather than come from hub.
	ProgFromCorpus ProgFlags = 1 << iota
	ProgMinimized
	ProgSmashed

	progCandidate
	progInTriage
)

type Candidate struct {
	Prog  *prog.Prog
	Flags ProgFlags
}

// AddCandidates adds candidate seeds to queue using dynamic seed classification
func (fuzzer *Fuzzer) AddCandidates(candidates []Candidate) {
	fuzzer.statCandidates.Add(len(candidates))

	// If cluster info exists, handle seed classification
	hasClusterInfo := fuzzer.ClusterInfo != nil

	for _, candidate := range candidates {
		// Get program hash
		progHash := GetProgHash(candidate.Prog)

		// If cluster info is enabled, check existing cluster assignment or assign new cluster
		if hasClusterInfo {
			// First check if seed already has cluster assignment
			existingClusterID, exists := fuzzer.ClusterInfo.GetClusterID(progHash)

			if exists {
				// Seed already has cluster assignment, log and use existing assignment
				fuzzer.Logf(3, "Using existing cluster %d for seed %s", existingClusterID, progHash)

				// If seed is cluster center, store its program object
				fuzzer.ClusterInfo.StoreProgramInCluster(candidate.Prog, progHash, existingClusterID)
			} else {
				// Seed has no cluster assignment, perform dynamic classification
				clusterID, isNewCluster := fuzzer.ClusterInfo.AssignCluster(candidate.Prog, progHash)

				// If new cluster is created, log it
				if isNewCluster {
					fuzzer.Logf(0, "Created new cluster %d for seed %s", clusterID, progHash)
				} else {
					//fuzzer.Logf(2, "Assigned seed %s to cluster %d", progHash, clusterID)
				}

				// If seed is cluster center, store its program object
				fuzzer.ClusterInfo.StoreProgramInCluster(candidate.Prog, progHash, clusterID)
			}
		}

		req := &queue.Request{
			Prog:          candidate.Prog,
			ExecOpts:      setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:          fuzzer.statExecCandidate,
			Important:     true,
			IsGenerated:   false,
			MutationDepth: 0,
		}
		fuzzer.enqueue(fuzzer.candidateQueue, req, candidate.Flags|progCandidate, 0)
	}
}

func (fuzzer *Fuzzer) rand() *rand.Rand {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	return rand.New(rand.NewSource(fuzzer.rnd.Int63()))
}

func (fuzzer *Fuzzer) updateChoiceTable(programs []*prog.Prog) {
	newCt := fuzzer.target.BuildChoiceTable(programs, fuzzer.Config.EnabledCalls)

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()
	if len(programs) >= fuzzer.ctProgs {
		fuzzer.ctProgs = len(programs)
		fuzzer.ct = newCt
	}
}

func (fuzzer *Fuzzer) choiceTableUpdater() {
	for {
		select {
		case <-fuzzer.ctx.Done():
			return
		case <-fuzzer.ctRegenerate:
		}
		fuzzer.updateChoiceTable(fuzzer.Config.Corpus.Programs())
	}
}

func (fuzzer *Fuzzer) ChoiceTable() *prog.ChoiceTable {
	progs := fuzzer.Config.Corpus.Programs()

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()

	// There were no deep ideas nor any calculations behind these numbers.
	regenerateEveryProgs := 333
	if len(progs) < 100 {
		regenerateEveryProgs = 33
	}
	if fuzzer.ctProgs+regenerateEveryProgs < len(progs) {
		select {
		case fuzzer.ctRegenerate <- struct{}{}:
		default:
			// We're okay to lose the message.
			// It means that we're already regenerating the table.
		}
	}
	return fuzzer.ct
}

func (fuzzer *Fuzzer) RunningJobs() []*JobInfo {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()

	var ret []*JobInfo
	for item := range fuzzer.runningJobs {
		ret = append(ret, item.getInfo())
	}
	return ret
}

func (fuzzer *Fuzzer) logCurrentStats() {
	for {
		select {
		case <-time.After(time.Minute):
		case <-fuzzer.ctx.Done():
			return
		}

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		str := fmt.Sprintf("running jobs: %d, heap (MB): %d",
			fuzzer.statJobs.Val(), m.Alloc/1000/1000)
		fuzzer.Logf(0, "%s", str)
	}
}

func setFlags(execFlags flatrpc.ExecFlag) flatrpc.ExecOpts {
	return flatrpc.ExecOpts{
		ExecFlags: execFlags,
	}
}

// TODO: This method belongs better to pkg/flatrpc, but we currently end up
// having a cyclic dependency error.
func DefaultExecOpts(cfg *mgrconfig.Config, features flatrpc.Feature, debug bool) flatrpc.ExecOpts {
	env := csource.FeaturesToFlags(features, nil)
	if debug {
		env |= flatrpc.ExecEnvDebug
	}
	if cfg.Experimental.ResetAccState {
		env |= flatrpc.ExecEnvResetState
	}
	if cfg.Cover {
		env |= flatrpc.ExecEnvSignal
	}
	sandbox, err := flatrpc.SandboxToFlags(cfg.Sandbox)
	if err != nil {
		panic(fmt.Sprintf("failed to parse sandbox: %v", err))
	}
	env |= sandbox

	exec := flatrpc.ExecFlagThreaded
	if !cfg.RawCover {
		exec |= flatrpc.ExecFlagDedupCover
	}
	return flatrpc.ExecOpts{
		EnvFlags:   env,
		ExecFlags:  exec,
		SandboxArg: cfg.SandboxArg,
	}
}

func (fuzzer *Fuzzer) initClusterInfo(cfg *Config) {
	if cfg.ClusterInfo != nil && cfg.ClusterSimilarityThreshold > 0 {
		cfg.ClusterInfo.SetSimilarityThreshold(cfg.ClusterSimilarityThreshold)
	}
}

// Periodically save cluster center information
func (fuzzer *Fuzzer) periodicSaveClusterInfo() {
	if fuzzer.ClusterInfo == nil {
		return
	}

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		// Perform final save before exit
		case <-fuzzer.ctx.Done():
			// In actual applications, a more graceful shutdown and save mechanism might be needed
			fuzzer.Logf(0, "Context done, attempting final save of cluster info.")
			clusterPath := filepath.Join(fuzzer.Config.Workdir, "cluster_info_final.csv")
			if err := fuzzer.ClusterInfo.SaveClusterLabel(clusterPath); err != nil {
				fuzzer.Logf(0, "failed to save final cluster info: %v", err)
			} else {
				fuzzer.Logf(0, "saved final cluster information to %s", clusterPath)
			}

			clusterCorePath := filepath.Join(fuzzer.Config.Workdir, "cluster_core_final.csv")
			if err := fuzzer.ClusterInfo.SaveClusterCores(clusterCorePath); err != nil {
				fuzzer.Logf(0, "failed to save final cluster cores: %v", err)
			} else {
				fuzzer.Logf(0, "saved final cluster core information to %s", clusterCorePath)
			}

			astDir := filepath.Join(fuzzer.Config.Workdir, "ast_cache_final")
			if err := fuzzer.ClusterInfo.SaveClusterASTs(astDir); err != nil {
				fuzzer.Logf(0, "failed to save final cluster ASTs: %v", err)
			} else {
				fuzzer.Logf(0, "saved final cluster AST information to %s", astDir)
			}
			return // Exit goroutine
		case <-ticker.C:
			// Save updated clustering information
			clusterPath := filepath.Join(fuzzer.Config.Workdir, "cluster_info.csv")
			if err := fuzzer.ClusterInfo.SaveClusterLabel(clusterPath); err != nil {
				fuzzer.Logf(0, "failed to save cluster info: %v", err)
			} else {
				fuzzer.Logf(2, "saved updated cluster information")
			}

			// Save cluster center information
			clusterCorePath := filepath.Join(fuzzer.Config.Workdir, "cluster_core.csv")
			if err := fuzzer.ClusterInfo.SaveClusterCores(clusterCorePath); err != nil {
				fuzzer.Logf(0, "failed to save cluster cores: %v", err)
			} else {
				fuzzer.Logf(2, "saved updated cluster core information")
			}

			// Can save AST information
			astDir := filepath.Join(fuzzer.Config.Workdir, "ast_cache")
			if err := fuzzer.ClusterInfo.SaveClusterASTs(astDir); err != nil {
				fuzzer.Logf(0, "failed to save cluster ASTs: %v", err)
			} else {
				fuzzer.Logf(3, "saved updated cluster AST information")
			}
		}
	}
}
