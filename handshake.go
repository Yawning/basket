// handshake.go - basket handshake
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
	"crypto/hmac"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/dchest/blake256"

	"github.com/yawning/basket/cert"
	"github.com/yawning/basket/kex"
	"github.com/yawning/ntru"
	"github.com/yawning/ntru/params"
)

const (
	// EES1171EP1 + SPHINCS256 is the worst case.
	maxHandshakeRequestSize  = 1682
	maxHandshakeResponseSize = 43740

	ntruPublicKeySize  = 1615 // EES1171EP1
	ntruCiphertextSize = 1611
)

var ErrInvalidHandshakeRequest = errors.New("invalid handshakeRequest")
var ErrInvalidHandshakeResponse = errors.New("invalid handshakeResponse")
var ErrInvalidSignature = errors.New("invalid signature")

// HandshakeMethod specifies the key exchange algorithm to use.
type HandshakeMethod byte

const (
	// HandshakeCurve25519 is a classical Curve25519 key exchange.
	HandshakeCurve25519 HandshakeMethod = iota

	// HandshakeNTRU is Curve25519 with the server's public key transmitted on
	// the wire as a NTRUEncrypt ciphertext.
	HandshakeNTRU
)

// HandshakeMethodFromString returns a HandshakeMethod given a string
// representation of the byte value of the method.
func HandshakeMethodFromString(methodStr string) (HandshakeMethod, error) {
	methodInt, err := strconv.ParseUint(methodStr, 10, 8)
	if err != nil {
		return 0, err
	}

	method := HandshakeMethod(methodInt)
	switch method {
	case HandshakeCurve25519:
	case HandshakeNTRU:
	default:
		return 0, InvalidHandshakeMethodError(method)
	}
	return method, nil
}

// InvalidHandshakeMethodError is the error returned when the handshake method
// is invalid.
type InvalidHandshakeMethodError HandshakeMethod

func (m InvalidHandshakeMethodError) Error() string {
	me := uint64(m)
	return "unsupported handshake method: " + strconv.FormatUint(me, 10)
}

func epochHour() uint32 {
	return uint32(time.Now().Unix() / (60 * 60))
}

func tweakAuthKey(authKey []byte, epochHour uint32) []byte {
	tweaked := make([]byte, len(authKey)+4)
	copy(tweaked, authKey)
	binary.BigEndian.PutUint32(tweaked[len(authKey):], epochHour)
	return tweaked
}

type handshakeRequest struct {
	method     HandshakeMethod
	kexPublic  *kex.PublicKey
	ntruPublic *ntru.PublicKey
	authDigest []byte

	digest []byte
}

func handshakeRequestFromBytes(raw []byte, replayFilter *handshakeReplay, authKey []byte) (*handshakeRequest, error) {
	if len(raw) < 1+kex.PublicKeySize+blake256.Size || len(raw) > maxHandshakeRequestSize {
		return nil, ErrInvalidHandshakeRequest
	}
	// uint16_t length
	rLen := binary.BigEndian.Uint16(raw[0:2])
	if len(raw)-2 != int(rLen) {
		return nil, ErrInvalidHandshakeRequest
	}

	req := &handshakeRequest{}

	// uint8_t  method
	p := raw[2:]
	req.method = HandshakeMethod(p[0])

	// uint8_t  curve25519_public_key[32]
	p = p[1:]
	req.kexPublic, _ = kex.NewPublicKey(p[:kex.PublicKeySize])

	// uint8_t  ntru_public_key[1615] (Optional, method = 1 only)
	p = p[kex.PublicKeySize:]
	if req.method == HandshakeNTRU {
		var err error
		if len(p) != ntruPublicKeySize+blake256.Size {
			return nil, ErrInvalidHandshakeRequest
		}
		req.ntruPublic, err = ntru.NewPublicKey(p[0:ntruPublicKeySize])
		if err != nil || req.ntruPublic.Params.OID != params.EES1171EP1 {
			return nil, ErrInvalidHandshakeRequest
		}
		p = p[ntruPublicKeySize:]
	} else {
		if len(p) != blake256.Size {
			return nil, ErrInvalidHandshakeRequest
		}
	}

	// uint8_t  auth_digest[32] (shared secret)
	req.authDigest = p
	if authKey != nil {
		// If there is an authKey set, actually validate the auth_digest value.
		authOk := false
		epochHour := epochHour()
		epochHours := []uint32{epochHour, epochHour - 1, epochHour + 1}
		for _, e := range epochHours {
			tweakedKey := tweakAuthKey(authKey, e)
			m := hmac.New(blake256.New, tweakedKey)
			m.Write(raw[0 : len(raw)-len(p)])
			calcAuth := m.Sum(nil)
			if hmac.Equal(calcAuth, req.authDigest) {
				if replayFilter != nil {
					authOk = !replayFilter.testAndSet(e, req.authDigest)
				} else {
					authOk = true
				}
			}
		}
		if !authOk {
			return nil, ErrInvalidHandshakeRequest
		}
	} else {
		// Ensure that the client isn't trying to authenticate when there is no
		// authKey set.  Technically speaking there isn't any reason why this
		// couldn't be allowed, but I don't feel great about signing random
		// garbage that the client sent, even if it is after being digested.
		var tmp byte
		for _, x := range req.authDigest[:blake256.Size] {
			tmp |= x
		}
		if tmp != 0 {
			return nil, ErrInvalidHandshakeRequest
		}
	}

	h := blake256.New()
	h.Write(raw)
	req.digest = h.Sum(nil)

	return req, nil
}

type clientHandshake struct {
	kexPrivate  *kex.PrivateKey
	ntruPrivate *ntru.PrivateKey

	req     *handshakeRequest
	reqBlob []byte

	sekrit *kex.SharedSecret
}

func (ch *clientHandshake) onHandshakeResponse(resp *handshakeResponse) (err error) {
	// It is assumed that the caller has checked that resp.cert is something it
	// trusts at this point, otherwise anyone can mount an active MITM.  The
	// signature is validated during resp creation, so as long as the cert is
	// validated before this, the rest is handled here.

	if ch.req.method != resp.method {
		return errors.New("response method != request method")
	}
	if subtle.ConstantTimeCompare(ch.req.digest, resp.reqDigest) != 1 {
		return errors.New("response request digest != request digest")
	}
	if ch.req.method == HandshakeNTRU {
		// All the attacks that can happen vs the RSA based TLS key exchange
		// mechanisms may be applicable here, except:
		//
		//  a) The NTRU key is ephemeral.
		//  b) Callers presumably drop the connection on a failure here.
		//
		// So this is fine.
		pt, err := ntru.Decrypt(ch.ntruPrivate, resp.ntruKexPublic)
		if err != nil {
			return err
		}
		if len(pt) != kex.PublicKeySize {
			return errors.New("response NTRU plaintext not a Curve25519 key")
		}
		resp.kexPublic, _ = kex.NewPublicKey(pt)
		ch.ntruPrivate.F.Obliterate()
	}
	ch.sekrit = ch.kexPrivate.KeyExchange(resp.kexPublic)
	ch.kexPrivate.Obliterate()
	return nil
}

func newClientHandshake(random io.Reader, method HandshakeMethod, authKey []byte) (*clientHandshake, error) {
	var err error
	if method != HandshakeNTRU && method != HandshakeCurve25519 {
		return nil, InvalidHandshakeMethodError(method)
	}

	ch := &clientHandshake{}
	req := &handshakeRequest{}
	ch.kexPrivate, req.kexPublic, err = kex.GenerateKey(random)
	if err != nil {
		return nil, err
	}
	req.method = method
	if method == HandshakeNTRU {
		ch.ntruPrivate, err = ntru.GenerateKey(random, params.EES1171EP1)
		if err != nil {
			return nil, err
		}
		req.ntruPublic = &ch.ntruPrivate.PublicKey
	}

	// Construct the raw wire payload.
	//
	// uint16_t length
	// uint8_t  method
	// uint8_t  curve25519_public_key[32]
	// uint8_t  ntru_public_key[1615] (Optional, method = 1 only)
	// uint8_t  auth_digest[32] (shared secret)

	n := 1 + kex.PublicKeySize + blake256.Size
	switch req.method {
	case HandshakeCurve25519:
	case HandshakeNTRU:
		n += req.ntruPublic.Size()
	default:
		panic("invalid handshake method in request serialization")
	}
	rawReq := make([]byte, 2, n)
	binary.BigEndian.PutUint16(rawReq[0:2], uint16(n))
	rawReq = append(rawReq, byte(req.method))
	rawReq = append(rawReq, req.kexPublic.Bytes()...)
	if req.method == HandshakeNTRU {
		rawReq = append(rawReq, req.ntruPublic.Bytes()...)
	}
	if authKey != nil {
		m := hmac.New(blake256.New, tweakAuthKey(authKey, epochHour()))
		m.Write(rawReq)
		req.authDigest = m.Sum(nil)
	} else {
		req.authDigest = make([]byte, blake256.Size)
	}
	rawReq = append(rawReq, req.authDigest...)
	ch.reqBlob = rawReq

	// The handshakeResponse includes a digest of the handshakeRequest,
	// calculate and store so it can be compared later.
	h := blake256.New()
	h.Write(rawReq)
	req.digest = h.Sum(nil)
	ch.req = req

	return ch, nil
}

type handshakeResponse struct {
	method    HandshakeMethod
	reqDigest []byte

	kexPublic     *kex.PublicKey
	ntruKexPublic []byte

	cert cert.Certificate
}

func handshakeResponseFromBytes(raw []byte) (*handshakeResponse, error) {
	var err error
	if len(raw) < 3 || len(raw) > maxHandshakeResponseSize {
		return nil, ErrInvalidHandshakeResponse
	}
	// uint16_t length
	rLen := binary.BigEndian.Uint16(raw[0:2])
	if len(raw)-2 != int(rLen) {
		return nil, ErrInvalidHandshakeResponse
	}

	resp := &handshakeResponse{}

	// uint8_t  method
	p := raw[2:]
	resp.method = HandshakeMethod(p[0])

	// uint8_t  request_digest[32]
	p = p[1:]
	if len(p) < blake256.Size {
		return nil, ErrInvalidHandshakeResponse
	}
	resp.reqDigest = p[0:blake256.Size]

	p = p[blake256.Size:]
	switch resp.method {
	case HandshakeCurve25519:
		// uint8_t  curve25519_public_key[32] (method = 0)
		if len(p) < kex.PublicKeySize {
			return nil, ErrInvalidHandshakeResponse
		}
		resp.kexPublic, _ = kex.NewPublicKey(p[:kex.PublicKeySize])
		p = p[kex.PublicKeySize:]
	case HandshakeNTRU:
		// uint8_t  ntru_encrypted_public_key[1611] (method = 1)
		if len(p) < ntruCiphertextSize {
			return nil, ErrInvalidHandshakeResponse
		}
		resp.ntruKexPublic = p[:ntruCiphertextSize]
		p = p[ntruCiphertextSize:]
	default:
		return nil, InvalidHandshakeMethodError(resp.method)
	}

	// uint16_t cert_length
	// uint8_t  cert[cert_length]
	if len(p) < 2 {
		return nil, ErrInvalidHandshakeResponse
	}
	certLen := binary.BigEndian.Uint16(p[0:2])
	if len(p) < int(certLen)+2 {
		return nil, ErrInvalidHandshakeResponse
	}
	resp.cert, err = cert.Load(p[2 : 2+certLen])
	if err != nil {
		return nil, err
	}

	// uint16_t signature_length
	// uint16_t signature[signature_length] (Everything up to the sig)
	p = p[2+certLen:]
	if len(p) < 2 {
		return nil, ErrInvalidHandshakeResponse
	}
	sigLen := binary.BigEndian.Uint16(p[0:2])
	p = p[2:]
	if len(p) != int(sigLen) || int(sigLen) != resp.cert.SignatureSize() {
		return nil, ErrInvalidHandshakeResponse
	}

	// Verify the signature.  Caller MUST check resp.cert to see if it was what
	// it thinks the server should be signing with.
	if !resp.cert.Verify(raw[0:len(raw)-len(p)], p) {
		return nil, ErrInvalidSignature
	}
	return resp, nil
}

type serverHandshake struct {
	req *handshakeRequest

	respBlob []byte

	sekrit *kex.SharedSecret
}

func newServerHandshake(random io.Reader, certPrivate cert.Certificate, req *handshakeRequest) (*serverHandshake, error) {
	// At this point req is assumed to be valid (since the deserialization code
	// checks everything to ensure that it is sane).

	sh := &serverHandshake{req: req}
	kexPriv, kexPub, err := kex.GenerateKey(random)
	if err != nil {
		return nil, err
	}

	// Construct the raw wire payload.
	//
	// uint16_t length
	// uint8_t  method
	// uint8_t  request_digest[32]
	// uint8_t  curve25519_public_key[32] (method = 0)
	// uint8_t  ntru_encrypted_public_key[1611] (method = 1)
	// uint16_t cert_length
	// uint8_t  cert[cert_length]
	// uint16_t signature_length
	// uint16_t signature[signature_length] (Everything up to the sig)

	certBlob, err := certPrivate.Serialize(false)
	if err != nil {
		panic("failed to serialize cert: " + err.Error())
	}

	n := 1 + blake256.Size + 2 + len(certBlob) + 2 + certPrivate.SignatureSize()
	var publicKey []byte
	switch req.method {
	case HandshakeCurve25519:
		n += kex.PublicKeySize
		publicKey = kexPub.Bytes()
	case HandshakeNTRU:
		ntruKexPublic, err := ntru.Encrypt(random, req.ntruPublic, kexPub.Bytes())
		if err != nil {
			return nil, err
		}
		n += len(ntruKexPublic)
		publicKey = ntruKexPublic
	default:
		panic("invalid handshake method in response serialization")
	}

	rawResp := make([]byte, 2, 2+n)
	binary.BigEndian.PutUint16(rawResp[0:2], uint16(n))
	rawResp = append(rawResp, (byte)(req.method))
	rawResp = append(rawResp, req.digest...)
	rawResp = append(rawResp, publicKey...)

	var certLen [2]byte
	binary.BigEndian.PutUint16(certLen[0:2], uint16(len(certBlob)))
	rawResp = append(rawResp, certLen[:]...)
	rawResp = append(rawResp, certBlob...)

	var sigLen [2]byte
	binary.BigEndian.PutUint16(sigLen[0:2], uint16(certPrivate.SignatureSize()))
	rawResp = append(rawResp, sigLen[:]...)

	// Sign everything up to this point.
	sig, err := certPrivate.Sign(rawResp)
	if err != nil {
		panic("signing failed: " + err.Error())
	}
	rawResp = append(rawResp, sig...)
	sh.respBlob = rawResp

	// Do the key exchange, this side is complete, all that remains is to send
	// respBlob.
	sh.sekrit = kexPriv.KeyExchange(req.kexPublic)
	kexPriv.Obliterate()

	return sh, nil
}
