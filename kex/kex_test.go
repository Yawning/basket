// kex.go - basket handshake keyexchange tests
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

package kex

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestKex(t *testing.T) {
	var zeroes [32]byte

	// Generate 2 keypairs.
	x, X, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	y, Y, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Do both sides of the exchange.
	xY := x.KeyExchange(Y)
	yX := y.KeyExchange(X)
	if bytes.Compare(xY[:], yX[:]) != 0 {
		t.Fatal("xY != yX")
	}

	// Test scrubbing the output and private keys.
	xY.Obliterate()
	if bytes.Compare(xY[:], zeroes[:]) != 0 {
		t.Fatal("xy != zeroes, post Obliterate()")
	}
	x.Obliterate()
	if bytes.Compare(x[:], zeroes[:]) != 0 {
		t.Fatal("x != zeroes, post Obliterate()")
	}

	// Test public key ctor.
	YY, err := NewPublicKey(Y.Bytes())
	if err != nil {
		t.Fatalf("NewPublicKey(Y.Bytes()): %v", err)
	}
	if bytes.Compare(Y.Bytes(), YY.Bytes()) != 0 {
		t.Fatal("Y.Bytes() != YY.Bytes()")
	}
}
