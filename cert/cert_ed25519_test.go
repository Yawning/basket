// cert_ed25519_test.go - basket Ed25519 certificate tests
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

func TestEd25519(t *testing.T) {
	cert, err := New(AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}

	// Test the basic accessors.
	if cert.Algorithm() != AlgEd25519 {
		t.Fatalf("unexpected cert algorithm: %x", cert.Algorithm())
	}

	edCert := (cert).(*certEd25519)
	pub := cert.PublicKey()
	if bytes.Compare(pub, edCert.publicKey[:]) != 0 {
		t.Errorf("cert.publicKey != cert.PublicKey()")
	}

	priv, err := cert.PrivateKey()
	if err != nil {
		t.Errorf("cert.PrivateKey() returned error: %v", err)
	}
	if bytes.Compare(priv, edCert.privateKey[:]) != 0 {
		t.Errorf("cert.privateKey != cert.PrivateKey()")
	}

	// Test signing and verification.
	testMsg := []byte("The most merciful thing in the world, I think, is " +
		"the inability of the human mind to correlate all its contents. We " +
		"live on a placid island of ignorance in the midst of black seas of " +
		"infinity, and it was not meant that we should voyage far.")
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
	if bytes.Compare(pub, edCert.publicKey[:]) != 0 {
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
	if bytes.Compare(pub, edCert.publicKey[:]) != 0 {
		t.Errorf("cert.publicKey != privCert.PublicKey()")
	}
	priv, err = privCert.PrivateKey()
	if err != nil {
		t.Errorf("privCert.PrivateKey() returned error: %v", err)
	}
	if bytes.Compare(priv, edCert.privateKey[:]) != 0 {
		t.Errorf("cert.privateKey != privCert.PrivateKey()")
	}
}
