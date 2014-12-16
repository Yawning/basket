// handshake_replay_test.go - basket handshake replay detection tests
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
	"testing"

	"github.com/dchest/blake256"
)

func TestHandshakeReplay(t *testing.T) {
	authDigest := make([]byte, blake256.Size)
	for i := range authDigest {
		authDigest[i] = byte(i)
	}

	replayFilter := &handshakeReplay{}
	now := epochHour()

	// Initial test and set, should be false.
	if replayFilter.testAndSet(now, authDigest) {
		t.Fatal("replayFilter.testAndSet() initial was true")
	}

	// 2nd test and set (replayed), should be true.
	if !replayFilter.testAndSet(now, authDigest) {
		t.Fatal("replayFilter.testAndSet() 2nd was false")
	}
}
