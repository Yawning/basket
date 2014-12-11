// basket.go - basket net.Conn interface
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

// Package basket implements the basket pluggable transport protocol, aimed at
// providing post-quantum link cryptography and traffic correlation defenses to
// the Tor wire protocol.
package basket

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"code.google.com/p/go.crypto/hkdf"
	"code.google.com/p/go.crypto/nacl/secretbox"

	"github.com/dchest/blake256"

	"github.com/yawning/basket/cert"
)

const (
	frameSize      = 1500 - (14 + 20 + 32) // XXX: 1498 instead of 1500?
	maxPayloadSize = frameSize - (boxOverhead + 2)

	boxKeySize         = 32
	boxNonceSize       = 24
	boxNoncePrefixSize = boxNonceSize - 8
	boxOverhead        = secretbox.Overhead

	connectTimeout = 30 * time.Second
	initialRho     = 1 * time.Millisecond
	quietTime      = 2 * time.Second
)

var ErrCounterWrapped = errors.New("nonce counter wrapped")
var ErrDecryptFailed = errors.New("decrypt failed")
var ErrMalformedFrame = errors.New("malformed frame")

// AcceptError is the error returned from Accept that wraps the underlying
// failure reasons with a net.Error interface that is always Temporary().
type AcceptError struct {
	Err error
}

func (e *AcceptError) Error() string {
	return "accept failed: " + e.Err.Error()
}

func (e *AcceptError) Timeout() bool {
	if ee, ok := e.Err.(net.Error); ok {
		return ee.Timeout()
	}
	return false
}

func (e *AcceptError) Temporary() bool {
	return true
}

// ServerConfig specifies the server connection configuration parameters.
type ServerConfig struct {
	// ServerCert is the server's certificate that is used to sign responses.
	ServerCert cert.Certificate

	// AuthKey is the optional handshake authorization shared-secret.
	AuthKey    []byte
}

type basketListener struct {
	ln *net.TCPListener

	serverCert cert.Certificate
	authKey    []byte
}

func (l *basketListener) Accept() (c net.Conn, err error) {
	if c, err = l.ln.Accept(); err != nil {
		return nil, err
	}

	// Ok, so in theory the server side handshake *SHOULD* be done in a
	// separate go routine since this serializes all incoming connection
	// attempts.  But, doing it this way makes it dead easy to ensure that
	// incomming connections don't impact existing onces (by chewing up all of
	// the CPU), since I can run the Accept() loop in a go routine that's
	// pinned to an OS thread.  Yay for the "wrong" approach being easy and
	// getting mostly acceptable behavior.

	c.SetDeadline(time.Now().Add(connectTimeout))

	// Read the request.
	rawReq, err := readLenPrefixedData(c)
	if err != nil {
		c.Close()
		return nil, &AcceptError{err}
	}
	req, err := handshakeRequestFromBytes(rawReq, l.authKey)
	if err != nil {
		c.Close()
		return nil, &AcceptError{err}
	}

	// Do the server side of the handshake.
	sh, err := newServerHandshake(rand.Reader, l.serverCert, req)
	if err != nil {
		c.Close()
		return nil, &AcceptError{err}
	}

	// Write the response.
	if n, err := c.Write(sh.respBlob); err != nil || n != len(sh.respBlob) {
		c.Close()
		return nil, &AcceptError{err}
	}

	// Initialize the actual connection.
	c.SetDeadline(time.Time{})
	defer sh.sekrit.Obliterate()
	c, err = newBasketConn(c, sh.sekrit.Bytes(), false)
	if err != nil {
		c.Close()
		return nil, &AcceptError{err}
	}
	return
}

func (l *basketListener) Close() error {
	return l.ln.Close()
}

func (l *basketListener) Addr() net.Addr {
	return l.ln.Addr()
}

func Listen(network string, laddr *net.TCPAddr, config *ServerConfig) (*basketListener, error) {
	// XXX: Should I validate the cert here or just assume the caller isn't stupid?

	l, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}
	return &basketListener{ln: l, serverCert: config.ServerCert, authKey: config.AuthKey}, nil
}

type basketConn struct {
	sync.WaitGroup
	conn net.Conn

	txBoxKey         [boxKeySize]byte
	txBoxNoncePrefix [boxNoncePrefixSize]byte
	txBoxNonceCtr    uint64

	rxBoxKey         [boxKeySize]byte
	rxBoxNoncePrefix [boxNoncePrefixSize]byte
	rxBoxNonceCtr    uint64

	recvBuf bytes.Buffer

	isClient bool
}

func (c *basketConn) Read(b []byte) (n int, err error) {
	// Read off the network.  Note that this reads at least one single frame.
	for c.recvBuf.Len() == 0 {
		// Frame size is constant and hardcoded, so "packets" are just NaCl
		// secretboxes.
		var box [frameSize]byte
		if _, err := io.ReadFull(c.conn, box[:]); err != nil {
			return 0, err
		}

		// Decrypt the secretbox.
		if c.rxBoxNonceCtr == 0 {
			// Ensuring that the counter does not wrap is the user's problem,
			// though that is entirely unrealistic at any presently obtainable
			// data rate.
			return 0, ErrCounterWrapped
		}
		var nonce [boxNonceSize]byte
		copy(nonce[:boxNoncePrefixSize], c.rxBoxNoncePrefix[:])
		binary.BigEndian.PutUint64(nonce[boxNoncePrefixSize:], c.rxBoxNonceCtr)
		c.rxBoxNonceCtr++
		frame := make([]byte, 0, frameSize-boxOverhead)
		frame, ok := secretbox.Open(frame, box[:], &nonce, &c.rxBoxKey)
		if !ok {
			// Decrypting failed.
			return 0, ErrDecryptFailed
		}
		if len(frame) != frameSize-boxOverhead {
			// This should *never* happen.
			panic("len(frame) != frameSize-boxOverhead")
		}

		// Decode the framing.  Frames are dead simple and are merely:
		//  uint16_t payload_len
		//  uint8_t payload[payload_len]
		//  uint8_t padding[frameSize-(boxOverhead+2+payload_len)]
		payloadLen := binary.BigEndian.Uint16(frame[0:2])
		if payloadLen > 0 { // If frame contains payload:
			if payloadLen > maxPayloadSize {
				// The peer is sending malformed secretbox payloads, or I
				// managed to fuck up something exceedingly trivial.
				return 0, ErrMalformedFrame
			}

			// Stash the payload in the receive buffer.
			c.recvBuf.Write(frame[2 : 2+payloadLen])

			// rho-stats = rho-stats || false
			// (onLoadEvent <- 0, padding-done <- 0) - Skipped.
		}
	}
	return c.recvBuf.Read(b)
}

func (c *basketConn) Write(b []byte) (n int, err error) {
	// HACKHACKHACK: For now just write onto the network instead of doing the
	// CS-BuFLO things.
	for toSend := len(b); toSend > 0; {
		payloadLen := toSend
		if payloadLen > maxPayloadSize {
			payloadLen = maxPayloadSize
		}

		if c.txBoxNonceCtr == 0 {
			// Ensuring that the counter does not wrap is the user's problem,
			// though that is entirely unrealistic at any presently obtainable
			// data rate.
			return n, ErrCounterWrapped
		}
		var nonce [boxNonceSize]byte
		copy(nonce[:boxNoncePrefixSize], c.txBoxNoncePrefix[:])
		binary.BigEndian.PutUint64(nonce[boxNoncePrefixSize:], c.txBoxNonceCtr)
		c.txBoxNonceCtr++

		var frame [frameSize - boxOverhead]byte
		binary.BigEndian.PutUint16(frame[0:2], uint16(payloadLen))
		copy(frame[2:], b[:payloadLen])

		box := make([]byte, 0, frameSize)
		box = secretbox.Seal(box, frame[:], &nonce, &c.txBoxKey)

		if _, err = c.conn.Write(box[:]); err != nil {
			// The return value for n here will be inaccurate but failures at
			// this point are fatal to the calling code so it doesn't matter.
			return
		}

		toSend -= payloadLen
		n += payloadLen
		b = b[payloadLen:]
	}

	// XXX: Check to see if the connection is still open.

	// output-buff <- output-buff || data
	// real-bytes <- real-bytes + length(m)
	// last-site-response-time <- CURRENT-TIME
	return
}

func (c *basketConn) Close() error {
	// XXX: Tear down the CS-BuFLO related things.
	c.Wait()

	// Clear out the keys.
	for i := range c.txBoxKey {
		c.txBoxKey[i] = 0
	}
	for i := range c.rxBoxKey {
		c.rxBoxKey[i] = 0
	}

	return c.conn.Close()
}

func (c *basketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *basketConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *basketConn) SetDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (c *basketConn) SetReadDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (c *basketConn) SetWriteDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (c *basketConn) doWrite(b []byte) (n, j int, err error) {
	return
}

func (c *basketConn) writeWorker() {
	// This is where the magic happens.
	for {
		// HACKHACKHACK: One day this will handle all the writes.
		break

		// if output-buff is not empty
		//  rho-stats <- rho-stats || CURRENT-TIME

		// (output-buf, j) <- CS-SEND(s, output-buff)
		// junk-bytes <- junk-bytes + j

		// if DONE-XMITTING then
		//  reset all variables
		// else
		//  if rho-star = NaN then
		//   rho-star <- INITIAL-RHO
		//  else if CROSSED-THRESHOLD(real-bytes, junk-bytes) then
		//   rho-star <- RHO-ESTIMATOR(rho-stats, rho-star)
		//   rho-stats = 0
		// if m is a time-out (always true in this implementation) then
		//   rho <- random number in [0, 2 * rho-star]
		// SLEEP(rho)
	}
	c.Done()
}

func newBasketConn(c net.Conn, sekrit []byte, isClient bool) (*basketConn, error) {
	bConn := &basketConn{conn: c, isClient: isClient}

	// Derive the session keys.
	h := hkdf.New(blake256.New, sekrit, nil, nil)
	if isClient {
		if _, err := io.ReadFull(h, bConn.txBoxKey[:]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(h, bConn.txBoxNoncePrefix[:]); err != nil {
			return nil, err
		}
		bConn.txBoxNonceCtr = 1
		if _, err := io.ReadFull(h, bConn.rxBoxKey[:]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(h, bConn.rxBoxNoncePrefix[:]); err != nil {
			return nil, err
		}
		bConn.rxBoxNonceCtr = 1
	} else {
		if _, err := io.ReadFull(h, bConn.rxBoxKey[:]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(h, bConn.rxBoxNoncePrefix[:]); err != nil {
			return nil, err
		}
		bConn.rxBoxNonceCtr = 1
		if _, err := io.ReadFull(h, bConn.txBoxKey[:]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(h, bConn.txBoxNoncePrefix[:]); err != nil {
			return nil, err
		}
		bConn.txBoxNonceCtr = 1
	}

	// Initialize the CS-BuFLO parameters.

	// Start up the CS-BuFLO write worker.
	bConn.Add(1)
	go bConn.writeWorker()

	return bConn, nil
}

// ClientConfig specifies the client connection configuration parameters.
type ClientConfig struct {
	// Method specifies which key exchange method to use.
	Method HandshakeMethod

	// AuthKey is the optional handshake authorization shared-secret.
	AuthKey []byte

	// CertCheckFn is the routine used to validate the server's certificate.
	CertCheckFn func(*net.TCPAddr, cert.Certificate) error
}

func Dial(network string, addr *net.TCPAddr, config *ClientConfig) (*basketConn, error) {
	// Generate the handshake request before the connection is opened.
	ch, err := newClientHandshake(rand.Reader, config.Method, config.AuthKey)
	if err != nil {
		return nil, err
	}

	// Establish the underlying TCP connection.
	c, err := net.DialTCP(network, nil, addr)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(connectTimeout))

	// Send the request.
	if n, err := c.Write(ch.reqBlob); err != nil || n != len(ch.reqBlob) {
		c.Close()
		return nil, err
	}

	// Read and process the response.
	rawResp, err := readLenPrefixedData(c)
	if err != nil {
		c.Close()
		return nil, err
	}
	resp, err := handshakeResponseFromBytes(rawResp)
	if err != nil {
		c.Close()
		return nil, err
	}
	if config.CertCheckFn != nil {
		// If this is not set, the user opted to live dangerously, and not
		// authenticate the peer.  This sort of stupidity should probably be
		// disallowed to be honest.
		if err = config.CertCheckFn(addr, resp.cert); err != nil {
			c.Close()
			return nil, err
		}
	}
	if err := ch.onHandshakeResponse(resp); err != nil {
		c.Close()
		return nil, err
	}

	// Initialize the actual connection.
	c.SetDeadline(time.Time{})
	defer ch.sekrit.Obliterate()
	return newBasketConn(c, ch.sekrit.Bytes(), true)
}

func readLenPrefixedData(c net.Conn) ([]byte, error) {
	var buf [2 + 65535]byte
	if _, err := io.ReadFull(c, buf[0:2]); err != nil {
		return nil, err
	}
	expLen := binary.BigEndian.Uint16(buf[0:2])
	if _, err := io.ReadFull(c, buf[2:2+int(expLen)]); err != nil {
		return nil, err
	}
	return buf[0 : 2+expLen], nil
}

var _ net.Error = (*AcceptError)(nil)
var _ net.Conn = (*basketConn)(nil)
var _ net.Listener = (*basketListener)(nil)
