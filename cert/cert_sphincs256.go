// cert_sphincs256.go - basket sphincs256 certificates
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

	"github.com/yawning/sphincs256"
)

type certSphincs256 struct {
	publicKey  *[sphincs256.PublicKeySize]byte
	privateKey *[sphincs256.PrivateKeySize]byte
}

func (c *certSphincs256) Algorithm() CertificateAlgorithm {
	return AlgSphincs256
}

func (c *certSphincs256) SignatureSize() int {
	return sphincs256.SignatureSize
}

func (c *certSphincs256) PublicKey() []byte {
	ret := make([]byte, sphincs256.PublicKeySize)
	copy(ret, c.publicKey[:])
	return ret
}

func (c *certSphincs256) HasPrivateKey() bool {
	return c.privateKey != nil
}

func (c *certSphincs256) PrivateKey() ([]byte, error) {
	if !c.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}
	ret := make([]byte, sphincs256.PrivateKeySize)
	copy(ret, c.privateKey[:])
	return ret, nil
}

func (c *certSphincs256) Sign(message []byte) ([]byte, error) {
	if !c.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}
	sig := sphincs256.Sign(c.privateKey, message)
	return sig[:], nil
}

func (c *certSphincs256) Verify(message []byte, signature []byte) bool {
	// Reject pathologically malformed signatures off the bat.
	if len(signature) != sphincs256.SignatureSize {
		return false
	}
	var sig [sphincs256.SignatureSize]byte
	copy(sig[:], signature)
	return sphincs256.Verify(c.publicKey, message, &sig)
}

func (c *certSphincs256) Serialize(includePrivate bool) ([]byte, error) {
	return serialize(c, includePrivate)
}

func (c *certSphincs256) String() string {
	return toString(c)
}

func newCertSphincs256() (*certSphincs256, error) {
	pub, priv, err := sphincs256.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &certSphincs256{publicKey: pub, privateKey: priv}, nil
}

func loadCertSphincs256(flags byte, blob []byte) (*certSphincs256, error) {
	var pub [sphincs256.PublicKeySize]byte
	var priv [sphincs256.PrivateKeySize]byte
	switch len(blob) {
	case sphincs256.PublicKeySize:
		copy(pub[:], blob[:sphincs256.PublicKeySize])
		return &certSphincs256{publicKey: &pub}, nil
	case sphincs256.PublicKeySize + sphincs256.PrivateKeySize:
		copy(pub[:], blob[:sphincs256.PublicKeySize])
		copy(priv[:], blob[sphincs256.PublicKeySize:])
		return &certSphincs256{publicKey: &pub, privateKey: &priv}, nil
	}
	return nil, fmt.Errorf("cert/sphincs256: malformed key(s)")
}

var _ Certificate = (*certSphincs256)(nil)
