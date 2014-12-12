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

	lastT     time.Time
	intervals durationSlice
}

func (a *statsAccumulator) reset() {
	a.Lock()
	defer a.Unlock()

	a.lastT = time.Time{}
	a.intervals = a.intervals[:0]
}

func (a *statsAccumulator) add(t time.Time) {
	var zeroTime time.Time
	a.Lock()
	defer a.Unlock()

	// The CS-BuFLO rho-stats accumulator collects inter-packet intervals with
	// the goal of determining the median whenever an update to rho-star is
	// needed.  The intervals are punctuated by "false" inserted into the list
	// of interval observations.
	//
	// Since storing the actual times is not needed to calculate the list of
	// intervals, calculate the interval to be added as a sample each time a
	// non-false value is inserted.
	//
	// Additionally since the list of intervals can grow to be rather large,
	// instead of calculating the true median (which requires storing every
	// single value), use an approximation.
	if t != zeroTime {
		// Ok, there was a previous timestamp recorded, and we have another
		// timestamp.  Derive the interval and factor it into the interval
		// calculations.  Since Go doesn't have a monotonic time source, check
		// for backward jumps in time here, and recover on the next sample.
		if a.lastT != zeroTime && t.After(a.lastT) {
			interval := t.Sub(a.lastT)

			// TODO: Use a huristic here instead of calculating the true median.
			a.intervals = append(a.intervals, interval)
		}
	}
	a.lastT = t
}

func (a *statsAccumulator) median() time.Duration {
	a.Lock()
	defer a.Unlock()

	// Return a 0 duration for the empty list case.
	if len(a.intervals) == 0 {
		return time.Duration(0)
	}

	// TODO: Use a huristic instead of calculating the true median.
	sort.Sort(a.intervals)
	return a.intervals[len(a.intervals)/2]
}

var _ sort.Interface = (*durationSlice)(nil)
