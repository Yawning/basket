// cert.go - basket certificates
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

// Package cert implements supports for basket "certificates" used to verify
// endpoint identity during the cryptographic handshake.  Despite the naming
// "certs" are merely a common serialization format for keys belonging to a
// given signature algorithm (Think SSH host keys/SSH user ID keys).
package cert

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/dchest/blake256"
)

const (
	blobHdrSize = blake256.Size + 1 + 1
)

// UnsupportedAlgorithmError is the error returned when an invalid algorithm is
// specified.
type UnsupportedAlgorithmError CertificateAlgorithm

func (a UnsupportedAlgorithmError) Error() string {
	id := uint64(a)
	return "cert: unsupported algorithm: " + strconv.FormatUint(id, 10)
}

// ErrNoPrivateKey is the error returned when a operation that requires a
// private key is attempted using a cert that only contains a public key.
var ErrNoPrivateKey = errors.New("cert: no private key")

// CertificateAlgorithm specifies the signature algorithm used by the
// certificate.
type CertificateAlgorithm byte

const (
	// AlgEd25519 is Ed25519/SHA-512.
	AlgEd25519 CertificateAlgorithm = iota

	// AlgSphincs256 is SPHINCS256/BLAKE-512.
	AlgSphincs256
)

// CertificateAlgorithmFromString returns a CertificateAlgorithm given a string
// representation of the byte value of the algorithm.
func CertificateAlgorithmFromString(algStr string) (CertificateAlgorithm, error) {
	algInt, err := strconv.ParseUint(algStr, 10, 8)
	if err != nil {
		return 0, err
	}

	alg := CertificateAlgorithm(algInt)
	switch alg {
	case AlgEd25519:
	case AlgSphincs256:
	default:
		return 0, UnsupportedAlgorithmError(alg)
	}
	return alg, nil
}

// Certificate is the common interface supported by all certificate types.
type Certificate interface {
	// Algorithm returns the algorithm supported by this certificate.
	Algorithm() CertificateAlgorithm

	// SignatureSize returns the size of signatures produced by the given
	// algorithm in bytes.
	SignatureSize() int

	// PublicKey returns the binary representation of the public key.
	PublicKey() []byte

	// HasPrivateKey returns if a private key is present.
	HasPrivateKey() bool

	// PrivateKey returns the binary representation of the private key.
	PrivateKey() ([]byte, error)

	// Sign signs a given message with the private key and returns the
	// signature.
	Sign(message []byte) ([]byte, error)

	// Verify validates a given message + signature combination against the
	// public key.
	Verify(message []byte, signature []byte) bool

	// Serialize returns a binary representation of the certificate suitable
	// for network transmission or loading.
	Serialize(includePrivate bool) ([]byte, error)

	// String returns a string representation of the certificate's public
	// information.
	String() string
}

// New generates a new Certificate with a fresh keypair.
func New(algorithm CertificateAlgorithm) (Certificate, error) {
	switch algorithm {
	case AlgEd25519:
		return newCertEd25519()
	case AlgSphincs256:
		return newCertSphincs256()
	}
	return nil, UnsupportedAlgorithmError(algorithm)
}

// Load decodes a binary representation of a certificate produced by Serialize.
func Load(blob []byte) (Certificate, error) {
	// The binary serialization format consists of:
	//  uint8_t digest[32]  - blake256 digest of:
	//   uint8_t alg_id     - the CertificateAlgorithm
	//   uint8_t flags      - reserved for future expansion
	//   uint8_t pub_key[]  - public key
	//   uint8_t priv_key[] - private key (optional)
	//
	// Note: The inclusion of a digest is to guard against things like on-disk
	// corruption and is not intended to provide any sort of security.

	if len(blob) < blobHdrSize {
		return nil, fmt.Errorf("cert: truncated certificate")
	}

	h := blake256.New()
	h.Write(blob[blake256.Size:])
	d := h.Sum(nil)
	if subtle.ConstantTimeCompare(d, blob[:blake256.Size]) != 1 {
		return nil, fmt.Errorf("cert: corrupted certificate")
	}

	algID := CertificateAlgorithm(blob[blobHdrSize-2])
	flags := blob[blobHdrSize-1]
	blob = blob[blobHdrSize:]
	switch algID {
	case AlgEd25519:
		return loadCertEd25519(flags, blob)
	case AlgSphincs256:
		return loadCertSphincs256(flags, blob)
	}
	return nil, UnsupportedAlgorithmError(algID)
}

func serialize(cert Certificate, includePrivate bool) ([]byte, error) {
	var err error
	var priv []byte
	pub := cert.PublicKey()
	keyLen := len(pub)
	if includePrivate {
		if priv, err = cert.PrivateKey(); err != nil {
			return nil, err
		}
		keyLen += len(priv)
	}

	blob := make([]byte, 0, blobHdrSize+keyLen)
	var algIDFlags [2]byte
	algIDFlags[0] = byte(cert.Algorithm())
	algIDFlags[1] = 0
	h := blake256.New()
	h.Write(algIDFlags[:])
	h.Write(pub)
	if priv != nil {
		h.Write(priv)
	}
	blob = h.Sum(blob)
	blob = append(blob, algIDFlags[:]...)
	blob = append(blob, pub...)
	if priv != nil {
		blob = append(blob, priv...)
		for i := range priv {
			priv[i] = 0 // Paranoia paranoia everybody's coming to get me.
		}
	}
	return blob, nil
}

func toString(c Certificate) string {
	ret := ""
	switch c.Algorithm() {
	case AlgEd25519:
		ret += "Ed25519:"
	case AlgSphincs256:
		ret += "SPHINCS256:"
	default:
		ret += "<Unknown Algorithm>:"
	}
	h := blake256.New()
	h.Write(c.PublicKey())
	digest := h.Sum(nil)
	ret += hex.EncodeToString(digest)
	return ret
}
