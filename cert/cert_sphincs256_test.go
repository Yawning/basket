// cert_sphincs256_test.go - basket sphincs256 certificate tests
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

package cert

import (
	"bytes"
	"testing"
)

func TestSphincs256(t *testing.T) {
	cert, err := New(AlgSphincs256)
	if err != nil {
		t.Fatal(err)
	}

	// Test the basic accessors.
	if cert.Algorithm() != AlgSphincs256 {
		t.Fatalf("unexpected cert algorithm: %x", cert.Algorithm())
	}

	sCert := (cert).(*certSphincs256)
	pub := cert.PublicKey()
	if bytes.Compare(pub, sCert.publicKey[:]) != 0 {
		t.Errorf("cert.publicKey != cert.PublicKey()")
	}

	priv, err := cert.PrivateKey()
	if err != nil {
		t.Errorf("cert.PrivateKey() returned error: %v", err)
	}
	if bytes.Compare(priv, sCert.privateKey[:]) != 0 {
		t.Errorf("cert.privateKey != cert.PrivateKey()")
	}

	// Test signing and verification.
	testMsg := []byte("I am writing this under an appreciable mental strain, " +
		"since by tonight I shall be no more. Penniless, and at the end of " +
		"my supply of the drug which alone makes life endurable, I can bear " +
		"the torture no longer; and shall cast myself from this garret " +
		"window into the squalid street below.")
	sig, err := cert.Sign(testMsg)
	if err != nil {
		t.Fatalf("cert.Sign returned error: %v", err)
	}
	if !cert.Verify(testMsg, sig) {
		t.Fatalf("cert.Verify returned false")
	}

	// Test serialization.
	pubBlob, err := cert.Serialize(false)
	if err != nil {
		t.Fatalf("cert.Serialize(false) returned error: %v", err)
	}
	pubCert, err := Load(pubBlob)
	if err != nil {
		t.Fatalf("failed to Load(pubBlob): %v", err)
	}
	pub = pubCert.PublicKey()
	if bytes.Compare(pub, sCert.publicKey[:]) != 0 {
		t.Errorf("cert.publicKey != pubCert.PublicKey()")
	}
	priv, err = pubCert.PrivateKey()
	if err == nil || priv != nil {
		t.Errorf("pubCert.PrivateKey() succeded for a public key only cert")
	}

	privBlob, err := cert.Serialize(true)
	if err != nil {
		t.Fatalf("cert.Serialize(true) returned error: %v", err)
	}
	privCert, err := Load(privBlob)
	if err != nil {
		t.Fatalf("failed to Load(privBlob): %v", err)
	}
	pub = privCert.PublicKey()
	if bytes.Compare(pub, sCert.publicKey[:]) != 0 {
		t.Errorf("cert.publicKey != privCert.PublicKey()")
	}
	priv, err = privCert.PrivateKey()
	if err != nil {
		t.Errorf("privCert.PrivateKey() returned error: %v", err)
	}
	if bytes.Compare(priv, sCert.privateKey[:]) != 0 {
		t.Errorf("cert.privateKey != privCert.PrivateKey()")
	}
}
