// kex.go - basket handshake keyexchange
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

// Package kex wraps the go.crypto Curve25519 primitive for ease of use.
package kex

import (
	"errors"
	"io"

	"code.google.com/p/go.crypto/curve25519"
	"github.com/dchest/blake512"
)

const (
	// PublicKeySize is the size of a Curve25519 public key in bytes.
	PublicKeySize    = 32

	// PrivateKeySize is the size of a Curve25519 private key in bytes.
	PrivateKeySize   = 32

	// SharedSecretSize is the size of a Curve25519 shared secret in bytes.
	SharedSecretSize = 32
)

// ErrInvalidPublicKey is the error returned when a public key is invalid.
var ErrInvalidPublicKey = errors.New("kex: invalid raw public key")

// SharedSecret is a wrapper type around a shared secret.
type SharedSecret [SharedSecretSize]byte

// Bytes returns the raw shared secret as a byte slice.
func (s *SharedSecret) Bytes() []byte {
	return s[:]
}

// Obliterate clears the shared secret.
func (s *SharedSecret) Obliterate() {
	wipe(s[:])
}

// PrivateKey is a wrapper type around a private key.
type PrivateKey [PrivateKeySize]byte

// KeyExchange calculates the shared secret based on a private key and separate
// public key.
func (p *PrivateKey) KeyExchange(pub *PublicKey) *SharedSecret {
	s := new(SharedSecret)
	curve25519.ScalarMult((*[32]byte)(s), (*[32]byte)(p), (*[32]byte)(pub))
	return s
}

// Obliterate clears the private key.
func (p *PrivateKey) Obliterate() {
	wipe(p[:])
}

// PublicKey is a wrapper type around a public key.
type PublicKey [PublicKeySize]byte

// Bytes returns the raw public key as a byte slice.
func (p *PublicKey) Bytes() []byte {
	return p[:]
}

// GenerateKey creates a new public/private key pair using a given source of
// entropy.
func GenerateKey(random io.Reader) (priv *PrivateKey, pub *PublicKey, err error) {
	priv = new(PrivateKey)
	if _, err = random.Read(priv[:]); err != nil {
		return nil, nil, err
	}
	h := blake512.New()
	h.Write(priv[:])
	digest := h.Sum(nil)
	defer wipe(digest)
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64
	copy(priv[:], digest[:PrivateKeySize])
	pub = new(PublicKey)
	curve25519.ScalarBaseMult((*[32]byte)(pub), (*[32]byte)(priv))
	return
}


// NewPublicKey creates a PublicKey from the raw key material.
func NewPublicKey(raw []byte) (pub *PublicKey, err error) {
	if len(raw) != PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	pub = new(PublicKey)
	copy(pub[:], raw)
	return
}

func wipe(s []byte) {
	for i := range s {
		s[i] = 0
	}
}
