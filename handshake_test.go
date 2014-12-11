// handshake_test.go - basket handshake tests
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
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/yawning/basket/cert"
)

func TestHandshake(t *testing.T) {
	// Ed25519/Curve25519
	c, err := cert.New(cert.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := newClientHandshake(rand.Reader, HandshakeCurve25519, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, err := handshakeRequestFromBytes(ch.reqBlob, nil)
	if err != nil {
		t.Fatal(err)
	}

	sh, err := newServerHandshake(rand.Reader, c, req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := handshakeResponseFromBytes(sh.respBlob)
	if err != nil {
		t.Fatal(err)
	}

	if err := ch.onHandshakeResponse(resp); err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(ch.sekrit.Bytes(), sh.sekrit.Bytes()) != 0 {
		t.Error("shared secret mismatch")
	}

	// SPHINCS256/NTRU (Test shared secret auth here as well).
	authKey := []byte("alea iacta est")
	c, err = cert.New(cert.AlgSphincs256)
	if err != nil {
		t.Fatal(err)
	}
	ch, err = newClientHandshake(rand.Reader, HandshakeNTRU, authKey)
	if err != nil {
		t.Fatal(err)
	}
	req, err = handshakeRequestFromBytes(ch.reqBlob, authKey)
	if err != nil {
		t.Fatal(err)
	}

	sh, err = newServerHandshake(rand.Reader, c, req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = handshakeResponseFromBytes(sh.respBlob)
	if err != nil {
		t.Fatal(err)
	}

	if err := ch.onHandshakeResponse(resp); err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(ch.sekrit.Bytes(), sh.sekrit.Bytes()) != 0 {
		t.Error("shared secret mismatch")
	}
}
