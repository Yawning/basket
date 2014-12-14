// stats.go - CS-BuFLO rho-stats accumulator
// Copyright (C) 2014  Yawning Angel
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package basket

import (
	"sort"
	"sync"
	"time"
)

const (
	maxObservations = 1024 // Must be a power of 2.
)

type durationSlice []time.Duration

func (d durationSlice) Len() int {
	return len(d)
}

func (d durationSlice) Less(i, j int) bool {
	return d[i] < d[j]
}

func (d durationSlice) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

type statsAccumulator struct {
	sync.Mutex

	lastT       time.Time
	intervals   durationSlice
	intervalIdx int
}

func (a *statsAccumulator) reset() {
	a.Lock()
	defer a.Unlock()

	a.lastT = time.Time{}
	a.intervals = a.intervals[:0]
	a.intervalIdx = 0
}

func (a *statsAccumulator) add(t time.Time) {
	var zeroTime time.Time
	a.Lock()
	defer a.Unlock()

	if a.intervals == nil {
		a.intervals = make(durationSlice, 0, maxObservations)
	}

	// The CS-BuFLO rho-stats accumulator collects inter-packet intervals with
	// the goal of determining the median whenever an update to rho-star is
	// needed.  The intervals are punctuated by "false" inserted into the list
	// of interval observations.
	//
	// Since storing the actual times is not needed to calculate the list of
	// intervals, calculate the interval to be added as a sample each time a
	// non-false value is inserted.
	if t != zeroTime {
		// Ok, there was a previous timestamp recorded, and we have another
		// timestamp.  Derive the interval and factor it into the interval
		// calculations.  Since Go doesn't have a monotonic time source, check
		// for backward jumps in time here, and recover on the next sample.
		if a.lastT != zeroTime && t.After(a.lastT) {
			interval := t.Sub(a.lastT)
			if a.intervals.Len() < maxObservations {
				a.intervals = append(a.intervals, interval)
			} else {
				// Limit the list of intervals to something sane, and replace
				// the oldest observed value.  This only kicks in once the
				// backing store has been filled once, so the eldest at that
				// point is the 0th element.
				a.intervalIdx = (a.intervalIdx + 1) & (maxObservations - 1)
				a.intervals[a.intervalIdx] = interval
			}
		}
	}
	a.lastT = t
}

func (a *statsAccumulator) median() time.Duration {
	a.Lock()
	defer a.Unlock()

	// Return a 0 duration for the empty list case.
	if a.intervals.Len() == 0 {
		return time.Duration(0)
	}

	// Work on a copy of the interval list, so the aging works correctly.
	tmp := make(durationSlice, a.intervals.Len())
	copy(tmp, a.intervals)
	sort.Sort(tmp)
	return tmp[tmp.Len()/2]
}

var _ sort.Interface = (*durationSlice)(nil)
