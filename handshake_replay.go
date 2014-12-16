// handshake_replay.go - basket handshake replay detection
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
	"github.com/dchest/blake256"
)

const replayMaxEntries = 200000

type replayMap struct {
	epochHour   uint32
	authDigests map[[blake256.Size]byte]bool
}

type handshakeReplay struct {
	maps []*replayMap
}

func (r *handshakeReplay) getMap(epochHour uint32) *replayMap {
	for _, m := range r.maps {
		if epochHour == m.epochHour {
			return m
		}
	}
	return nil
}

func (r *handshakeReplay) ageMaps() {
	// Age the old entries if neccecary.
	now := epochHour()
	newMaps := make([]*replayMap, 0, 3)
	for _, e := range []uint32{now - 1, now, now + 1} {
		if m := r.getMap(e); m != nil {
			newMaps = append(newMaps, m)
		}
	}
	r.maps = newMaps
}

func (r *handshakeReplay) testAndSet(authEpochHour uint32, authDigest []byte) bool {
	// Age out the old maps based on current time, as we return from this
	// routine.
	defer r.ageMaps()

	var dKey [blake256.Size]byte
	copy(dKey[:], authDigest)
	m := r.getMap(authEpochHour)
	if m != nil {
		// Hit.
		if present := m.authDigests[dKey]; present {
			return true
		}

		// Sanity check.  In theory this should never be triggered since
		// handshakes take a good amount of time, but be paranoid.
		if len(m.authDigests) > replayMaxEntries {
			// Ugh, the obfs4 version of this code maintains a LRU list just to
			// handle this condition, but that's kind of heavy for something
			// that should never happen.  If the replay filter ever happens to
			// fill up, just deny further authDigests for that epochHour.
			return true
		}
	} else {
		// First time this epochHour has been seen.  Create the backing entry.
		// It is possible due to the hour changing right as this routine is
		// entered that an extra backing map gets added, only to immediately be
		// cleaned up by the defered ageMaps() call, but that's totally
		// harmless.
		m = &replayMap{epochHour: authEpochHour}
		m.authDigests = make(map[[blake256.Size]byte]bool)
		r.maps = append(r.maps, m)
	}

	// Add the authDigest to the map and return.
	m.authDigests[dKey] = true
	return false
}
