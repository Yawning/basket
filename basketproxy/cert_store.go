// cert_store.go - basket application certificate store code
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

package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/dchest/blake256"

	"github.com/yawning/basket/cert"
)

func logCertDigest(cert cert.Certificate) {
	h := blake256.New()
	h.Write(cert.PublicKey())
	dig := h.Sum(nil)
	digStr := hex.EncodeToString(dig[:16])
	infof("Server Cert Digest: digest=%d:%s", int(cert.Algorithm()), digStr)
}

// loadOrGenerateCert loads (or generates and saves) a server certificate from
// on disk storage.  Certificates are stored as a trivial base64 encoding of
// the byte serialized format.
func loadOrGenerateCert(certFile string, alg cert.CertificateAlgorithm) (cert.Certificate, error) {
	blobB64, err := ioutil.ReadFile(certFile)
	if err == nil {
		blob, err := base64.StdEncoding.DecodeString(string(blobB64))
		if err != nil {
			return nil, err
		}
		cert, err := cert.Load(blob)
		if err != nil {
			return nil, err
		}
		if !cert.HasPrivateKey() {
			return nil, errors.New("basketproxy: stored cert missing private key")
		}
		logCertDigest(cert)
		return cert, nil
	}

	// If the error was a load related failure that doesn't indicate that a
	// cert file does not exist, bail out.
	if !os.IsNotExist(err) {
		return nil, err
	}
	cert, err := cert.New(alg)
	if err != nil {
		return nil, err
	}
	blob, err := cert.Serialize(true)
	if err != nil {
		return nil, err
	}
	blobB64 = []byte(base64.StdEncoding.EncodeToString(blob))
	if err = ioutil.WriteFile(certFile, blobB64, 0600); err != nil {
		return nil, err
	}
	logCertDigest(cert)
	return cert, nil
}

type knownHostsDigest struct {
	algorithm cert.CertificateAlgorithm
	digest    []byte
}

type knownHostsStore struct {
	sync.Mutex
	file string

	hostMap   map[string]cert.Certificate
	digestMap map[string]*knownHostsDigest
}

func (k *knownHostsStore) save() error {
	const preamble = "# basket_known_hosts: basket host/certificate store\n" +
		"#  Contains a list of ip:port and server certificate pairs for all\n" +
		"#  hosts that the client has connected to.\n\n"
	newContents := []byte(preamble)
	for addrStr, cert := range k.hostMap {
		certBlob, err := cert.Serialize(false)
		if err != nil {
			return err
		}
		line := addrStr + " " + base64.StdEncoding.EncodeToString(certBlob) + "\n"
		newContents = append(newContents, []byte(line)...)
	}
	return ioutil.WriteFile(k.file, newContents, 0600)
}

func (k *knownHostsStore) registerDigest(addr *net.TCPAddr, d string) error {
	// The digest format is "<algorithm ID>:hex(BLAKE256-128(publicKey))".
	splitD := strings.Split(d, ":")
	if len(splitD) != 2 {
		return errors.New("digest is malformed")
	}

	algID, err := strconv.ParseUint(splitD[0], 10, 8)
	if err != nil {
		return err
	}
	dig, err := hex.DecodeString(splitD[1])
	if err != nil {
		return err
	}
	if len(dig) != 16 {
		return errors.New("digest length is not 16 bytes")
	}

	k.Lock()
	defer k.Unlock()
	k.digestMap[addr.String()] = &knownHostsDigest{algorithm: cert.CertificateAlgorithm(algID), digest: dig}
	return nil
}

func (k *knownHostsStore) checkCert(addr *net.TCPAddr, serverCert cert.Certificate, tofu bool) error {
	k.Lock()
	defer k.Unlock()

	// First check to see if we have a known "good" certificate for this
	// address.
	addrStr := addr.String()
	if knownCert := k.hostMap[addrStr]; knownCert != nil {
		// It appears that a copy of the certificate exists in the store, so
		// compare it and reject if there is a mismatch.
		if serverCert.Algorithm() != knownCert.Algorithm() {
			return errors.New("certificate algorithm mismatch")
		}
		if subtle.ConstantTimeCompare(serverCert.PublicKey(), knownCert.PublicKey()) != 1 {
			return errors.New("certificate mismatch, did the server cert change?")
		}
		return nil
	}

	// Second check to see if we have a known "good" digest of what we think
	// the address's public key should be.
	if knownDigest := k.digestMap[addrStr]; knownDigest != nil {
		if serverCert.Algorithm() != knownDigest.algorithm {
			return errors.New("certificate algorithm/digest algorithm mismatch")
		}

		h := blake256.New()
		h.Write(serverCert.PublicKey())
		d := h.Sum(nil)
		if subtle.ConstantTimeCompare(knownDigest.digest, d[:16]) != 1 {
			return errors.New("certificate/digest mismatch, did the server cert change?")
		}

		// Ok, treat this as a forced TOFU case since the digests match.
		infof("Server Cert: %s: Trusting-On-First-Digest", addr)
		k.hostMap[addrStr] = serverCert
		return k.save()
	}

	if tofu {
		// Trust On First Use.
		infof("Server Cert: %s: Trusting-On-First-Use", addr)
		k.hostMap[addrStr] = serverCert
		return k.save()
	}

	// Unknown cert, no known digest, and TOFU is disabled.
	return errors.New("unknown certificate, TOFU is disabled")
}

func newKnownHosts(file string) (*knownHostsStore, error) {
	k := &knownHostsStore{file: file}
	k.hostMap = make(map[string]cert.Certificate)
	k.digestMap = make(map[string]*knownHostsDigest)

	// Load the known hosts file if one exists already.
	fBlob, err := ioutil.ReadFile(file)
	if err != nil {
		// Lacking an existing file is a non-fatal error.
		if os.IsNotExist(err) {
			return k, nil
		}
		return nil, err
	}

	lines := strings.Split(string(fBlob), "\n")
	for i, line := range lines {
		// Trim leading/trailing whitespace.
		line = strings.TrimSpace(line)

		// Skip 0 length lines, and lines that begin with '#'.
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		lineSplit := strings.Split(line, " ")
		if len(lineSplit) != 2 {
			return nil, fmt.Errorf("known_hosts line %d: line malformed", i+1)
		}
		addrStr := lineSplit[0]
		if _, err = parseAddrPortStr(addrStr); err != nil {
			return nil, fmt.Errorf("known_hosts line %d malformed address: %s", i+1, err)
		}
		certStr := lineSplit[1]
		certBlob, err := base64.StdEncoding.DecodeString(certStr)
		if err != nil {
			return nil, fmt.Errorf("known_hosts line %d: cert base64 decode failed: %s", i+1, err)
		}
		cert, err := cert.Load(certBlob)
		if err != nil {
			return nil, fmt.Errorf("known_hosts line %d: cert load failed: %s", i+1, err)
		}
		k.hostMap[addrStr] = cert
	}
	return k, nil
}
