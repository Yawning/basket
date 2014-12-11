// cert_ed25519.go - basket Ed25519 certificates
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
	"crypto/rand"
	"fmt"

	"github.com/agl/ed25519"
)

type certEd25519 struct {
	publicKey  *[ed25519.PublicKeySize]byte
	privateKey *[ed25519.PrivateKeySize]byte
}

func (c *certEd25519) Algorithm() CertificateAlgorithm {
	return AlgEd25519
}

func (c *certEd25519) SignatureSize() int {
	return ed25519.SignatureSize
}

func (c *certEd25519) PublicKey() []byte {
	ret := make([]byte, ed25519.PublicKeySize)
	copy(ret, c.publicKey[:])
	return ret
}

func (c *certEd25519) HasPrivateKey() bool {
	return c.privateKey != nil
}

func (c *certEd25519) PrivateKey() ([]byte, error) {
	if !c.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}
	ret := make([]byte, ed25519.PrivateKeySize)
	copy(ret, c.privateKey[:])
	return ret, nil
}

func (c *certEd25519) Sign(message []byte) ([]byte, error) {
	if !c.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}
	sig := ed25519.Sign(c.privateKey, message)
	return sig[:], nil
}

func (c *certEd25519) Verify(message []byte, signature []byte) bool {
	// Reject pathologically malformed signatures off the bat.
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	var sig [ed25519.SignatureSize]byte
	copy(sig[:], signature)
	return ed25519.Verify(c.publicKey, message, &sig)
}

func (c *certEd25519) Serialize(includePrivate bool) ([]byte, error) {
	return serialize(c, includePrivate)
}

func (c *certEd25519) String() string {
	return toString(c)
}

func newCertEd25519() (*certEd25519, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &certEd25519{publicKey: pub, privateKey: priv}, nil
}

func loadCertEd25519(flags byte, blob []byte) (*certEd25519, error) {
	var pub [ed25519.PublicKeySize]byte
	var priv [ed25519.PrivateKeySize]byte
	switch len(blob) {
	case ed25519.PublicKeySize:
		copy(pub[:], blob[:ed25519.PublicKeySize])
		return &certEd25519{publicKey: &pub}, nil
	case ed25519.PublicKeySize + ed25519.PrivateKeySize:
		copy(pub[:], blob[:ed25519.PublicKeySize])
		copy(priv[:], blob[ed25519.PublicKeySize:])
		return &certEd25519{publicKey: &pub, privateKey: &priv}, nil
	}
	return nil, fmt.Errorf("cert/ed25519: malformed key(s)")
}

var _ Certificate = (*certEd25519)(nil)
