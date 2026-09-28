// Copyright 2025 SyzDiversity project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"sync"

	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
)

// Cover keeps track of the signal known to the fuzzer.
type Cover struct {
	mu          sync.RWMutex
	maxSignal   signal.Signal            // max signal ever observed (including flakes)
	newSignal   signal.Signal            // newly identified max signal
	progSignals map[string]signal.Signal // Store mapping from program hash to signal
}


func newCover() *Cover {
	cover := new(Cover)
	cover.progSignals = make(map[string]signal.Signal)
	stat.New("max signal", "Maximum fuzzing signal (including flakes)",
		stat.Graph("signal"), stat.LenOf(&cover.maxSignal, &cover.mu))
	return cover
}

func (cover *Cover) AddProgSignal(hash string, sig signal.Signal) {
	cover.mu.Lock()
	defer cover.mu.Unlock()
	if existing, ok := cover.progSignals[hash]; ok {
		// If already exists, merge signals
		existing.Merge(sig)
		cover.progSignals[hash] = existing
	} else {
		// Otherwise, store new signal
		cover.progSignals[hash] = sig.Copy()
	}
}

func (cover *Cover) addRawMaxSignal(signal []uint64, prio uint8) signal.Signal {
	cover.mu.Lock()
	defer cover.mu.Unlock()
	diff := cover.maxSignal.DiffRaw(signal, prio)
	if diff.Empty() {
		return diff
	}
	cover.maxSignal.Merge(diff)
	cover.newSignal.Merge(diff)
	return diff
}

func (cover *Cover) CopyMaxSignal() signal.Signal {
	cover.mu.RLock()
	defer cover.mu.RUnlock()
	return cover.maxSignal.Copy()
}

func (cover *Cover) GrabSignalDelta() signal.Signal {
	cover.mu.Lock()
	defer cover.mu.Unlock()
	plus := cover.newSignal
	cover.newSignal = nil
	return plus
}

// Add method to get program signal
func (cover *Cover) GetSignal(hash string) signal.Signal {
	cover.mu.RLock()
	defer cover.mu.RUnlock()
	if sig, ok := cover.progSignals[hash]; ok {
		return sig.Copy()
	}
	return signal.Signal{} // Return empty signal
}

// Add helper method to get signal raw data
func (cover *Cover) GetSignalSize(hash string) int {
	sig := cover.GetSignal(hash)
	return sig.Len() // Signal has Len method
}
