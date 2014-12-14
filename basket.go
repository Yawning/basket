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
	"math"
	mathRand "math/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"code.google.com/p/go.crypto/hkdf"
	"code.google.com/p/go.crypto/nacl/secretbox"

	"github.com/dchest/blake256"

	"github.com/yawning/basket/cert"
	"github.com/yawning/basket/kist"
)

const (
	frameSize      = 1500 - (14 + 20 + 32) // XXX: 1498 instead of 1500?
	maxPayloadSize = frameSize - (boxOverhead + 2)

	maxPendingFrames = 64

	boxKeySize         = 32
	boxNonceSize       = 24
	boxNoncePrefixSize = boxNonceSize - 8
	boxOverhead        = secretbox.Overhead

	connectTimeout = 30 * time.Second
	initialRho     = 1 * time.Millisecond // XXX: Lengthen this?
	upperRho       = 4 * time.Millisecond
	quietTime      = 2 * time.Second // XXX: Shorten this?
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

type csRandSource struct{}

func (r *csRandSource) Int63() int64 {
	var src [8]byte
	if _, err := io.ReadFull(rand.Reader, src[:]); err != nil {
		panic(err)
	}
	v := binary.BigEndian.Uint64(src[:])
	v &= (1<<63 - 1)
	return int64(v)
}

func (r *csRandSource) Seed(int64) {}

var csRand = mathRand.New(&csRandSource{})

// ServerConfig specifies the server connection configuration parameters.
type ServerConfig struct {
	// ServerCert is the server's certificate that is used to sign responses.
	ServerCert cert.Certificate

	// AuthKey is the optional handshake authorization shared-secret.
	AuthKey []byte
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
	sync.Mutex
	sync.WaitGroup

	fileConn   *os.File
	localAddr  net.Addr
	remoteAddr net.Addr

	txBoxKey         [boxKeySize]byte
	txBoxNoncePrefix [boxNoncePrefixSize]byte
	txBoxNonceCtr    uint64

	rxBoxKey         [boxKeySize]byte
	rxBoxNoncePrefix [boxNoncePrefixSize]byte
	rxBoxNonceCtr    uint64

	writeChan chan []byte
	recvBuf   bytes.Buffer

	isClient bool
	isClosed bool

	lastSiteResponseTime time.Time
	realBytes            uint64
	junkBytes            uint64
	rhoStar              time.Duration
	rhoStats             statsAccumulator
}

func (c *basketConn) Read(b []byte) (n int, err error) {
	// Read off the network.  Note that this reads at least one single frame.
	for c.recvBuf.Len() == 0 {
		// Frame size is constant and hardcoded, so "packets" are just NaCl
		// secretboxes.
		var box [frameSize]byte
		if _, err := io.ReadFull(c.fileConn, box[:]); err != nil {
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
			// Decrypting failed.  Possible if Close() happens while a Read
			// call is in progress since the keys get obliterated, which is
			// harmless if somewhat annoying.  Throwing a lock around the
			// decrypt would solve that but that's kind of terrible from a
			// performance standpoint.
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
			c.rhoStats.add(time.Time{})
			// (onLoadEvent <- 0, padding-done <- 0) - Skipped.
		}
	}
	return c.recvBuf.Read(b)
}

func (c *basketConn) Write(b []byte) (n int, err error) {
	defer func() {
		// If this gets triggered, it because we tried to write to the closed
		// writeChan.
		if r := recover(); r != nil {
			err = syscall.EBADF
		}
	}()

	for toSend := len(b); toSend > 0; {
		// Cut up the write buffer into slices that are at most maxPayloadSize
		// bytes long, and dump them into the outgoing write buffer so that the
		// worker can do the write.
		payloadLen := toSend
		if payloadLen > maxPayloadSize {
			payloadLen = maxPayloadSize
		}

		// output-buff <- output-buff || data
		// NB: managing real-bytes is done from the worker
		frame := make([]byte, payloadLen)
		copy(frame, b[:payloadLen])
		c.writeChan <- frame
		toSend -= payloadLen
		n += payloadLen
		b = b[payloadLen:]

		// last-site-response-time <- CURRENT-TIME
		c.Lock()
		c.lastSiteResponseTime = time.Now()
		c.Unlock()
	}
	return
}

func (c *basketConn) Close() error {
	c.Lock()
	defer c.Unlock()

	if c.isClosed {
		return syscall.EBADF
	}
	c.isClosed = true

	// Tear down the CS-BuFLO related things.
	close(c.writeChan)
	c.Wait()

	// Clear out the keys.
	for i := range c.txBoxKey {
		c.txBoxKey[i] = 0
	}
	for i := range c.rxBoxKey {
		c.rxBoxKey[i] = 0
	}

	return c.fileConn.Close()
}

func (c *basketConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *basketConn) RemoteAddr() net.Addr {
	return c.remoteAddr
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
	if b != nil && len(b) > maxPayloadSize {
		panic("doWrite(): len(b) > maxPayloadSize")
	}

	if c.txBoxNonceCtr == 0 {
		// Ensuring that the counter does not wrap is the user's problem,
		// though that is entirely unrealistic at any presently obtainable
		// data rate.
		return 0, 0, ErrCounterWrapped
	}
	var nonce [boxNonceSize]byte
	copy(nonce[:boxNoncePrefixSize], c.txBoxNoncePrefix[:])
	binary.BigEndian.PutUint64(nonce[boxNoncePrefixSize:], c.txBoxNonceCtr)
	c.txBoxNonceCtr++

	var frame [frameSize - boxOverhead]byte
	bLen := 0
	if b != nil {
		bLen = len(b)
		copy(frame[2:], b)
	}
	binary.BigEndian.PutUint16(frame[0:2], uint16(bLen))

	box := make([]byte, 0, frameSize)
	box = secretbox.Seal(box, frame[:], &nonce, &c.txBoxKey)

	if _, err = c.fileConn.Write(box[:]); err != nil {
		// The return value for n here will be inaccurate but failures at
		// this point are fatal to the calling code so it doesn't matter.
		return
	}
	return bLen, maxPayloadSize - bLen, nil
}

func (c *basketConn) writeWorker() {
	doSleep := func() {
		// rho <- random number in [0, 2 * rho-star]
		rho := initialRho // Sigh, make sure that rho is always somewhat sane.
		if c.rhoStar != 0 {
			rho = time.Duration(csRand.Int63n(2 * int64(c.rhoStar)))
		}
		// SLEEP(rho)
		time.Sleep(rho)
	}

	// This is where the magic happens.
writeLoop:
	for {
		var err error
		j := 0
		isDone := false

		// Check if network conditions would allow for a frame to be
		// written.  The CS-BuFLO paper does this the absolute garbage way by
		// setting the socket to non-blocking mode and doing a YOLO write.
		// Basket does the smart thing and queries the socket information to
		// see if a Write of the target size will go through without blocking.
		if cap, err := kist.EstimateWriteCapacity(c.fileConn); err == nil {
			// Failures are probably catastrophic, but since they are unlikely,
			// just assume that the link has capacity if we fail to get an
			// estimate.
			if cap < frameSize {
				// Ok, the link is congested either due to insufficient send
				// socket buffer space (unlikely), or the congestion window
				// being full (likely).  In either case, sleep for the random
				// interval and try again.
				doSleep()
				continue
			}
		}

		select {
		case frame, ok := <-c.writeChan:
			if !ok {
				// The writeChan is closed.
				break writeLoop
			}
			c.realBytes += uint64(len(frame))

			// if output-buff is not empty
			//  rho-stats <- rho-stats || CURRENT-TIME
			c.rhoStats.add(time.Now())

			// (output-buf, j) <- CS-SEND(s, output-buff)
			_, j, err = c.doWrite(frame)
			if err != nil {
				c.Done()
				c.Close()
				return
			}
		case <-time.After(0):
			// Meh, the write buffer is empty, check if we should be idle, and
			// if not inject some padding.
			if isDone = c.doneXmitting(); !isDone {
				_, j, err = c.doWrite(nil)
				if err != nil {
					c.Done()
					c.Close()
					return
				}
			}
		}

		// junk-bytes <- junk-bytes + j
		c.junkBytes += uint64(j)

		// if DONE-XMITTING then
		if isDone {
			// reset all variables
			c.realBytes = 0
			c.junkBytes = 0
			c.rhoStar = initialRho // Paper says 0, but want a sane value.
			c.rhoStats.reset()
		} else {
			if c.rhoStar == 0 {
				// if rho-star = NaN then
				//  rho-star <- INITIAL-RHO
				c.rhoStar = initialRho
			} else if crossedThreshold(float64(c.realBytes + c.junkBytes)) {
				// if CROSSED-THRESHOLD(real-bytes, junk-bytes) then
				//  rho-star <- RHO-ESTIMATOR(rho-stats, rho-star)
				//   I <- [rho-stats i+1 - rho-stats i | rho-stats i+1 != false
				//        && rho-stats i != false]
				//   if I = empty list then
				//     return rho-star
				//   return 2^(floor(log2(median(I))))
				//  rho-stats = 0
				median := c.rhoStats.median()
				if median == 0 {
					c.rhoStar = upperRho
				} else {
					shift := uint(math.Floor(math.Log2(float64(median))))
					c.rhoStar = 1 << shift

					// XXX: The implementation by the authors caps "tau"
					// (called rho in the paper) to upperRho.  I think this
					// wastes bandwidth, but allowing rho to grow too large
					// adds a lot of latency.
					if c.rhoStar > upperRho {
						c.rhoStar = upperRho
					}
				}
				c.rhoStats.reset()
			}
		}
		doSleep()
	}
	c.Done()
}

func (c *basketConn) doneXmitting() bool {
	// The paper specifies this as:
	//   LENGTH(output-buff) <- 0 &&
	//   CHANNEL-IDLE(onLoadEvent, last-site-response-time) &&
	//   (padding-done || CROSSED-THRESHOLD(real-bytes + junk-bytes))
	//
	// This is only called if the output-buffer is empty, onLoadEvent and
	// padding-done are not used in this version of the code, so things are
	// simplified somewhat (yay).
	//
	// crossedThreshold can be called with just c.realBytes for "payload"
	// padding, but "total" padding appears to be a better (if more expensive)
	// defense.  Consider CTSP to cut down on bandwidth consumption.

	c.Lock()
	defer c.Unlock()

	// CHANNEL-IDLE(onLoadEvent, last-site-response-time)
	isIdle := time.Now().Sub(c.lastSiteResponseTime) > quietTime

	// CROSSED-THRESHOLD(x)
	//  return floor(log2(x - PACKET-SIZE)) < floor(log2(x))
	crossedThresh := crossedThreshold(float64(c.realBytes + c.junkBytes))

	return isIdle && crossedThresh
}

func crossedThreshold(x float64) bool {
	// CROSSED-THRESHOLD(x)
	//  return floor(log2(x - PACKET-SIZE)) < floor(log2(x))
	if x <= maxPayloadSize {
		// Should never happen for the "total padding" mode.
		return false
	}
	return math.Floor(math.Log2(x-maxPayloadSize)) < math.Floor(math.Log2(x))
}

func newBasketConn(c net.Conn, sekrit []byte, isClient bool) (*basketConn, error) {
	// We need to get at the raw file descriptor.  The Go runtime's idea of a
	// reasonable way to do this is to use File() which duplicates the
	// underlying fd, and then call file.Fd().  Naturally the original
	// net.TCPConn needs to be cleaned up separately.
	fConn, err := c.(*net.TCPConn).File()
	if err != nil {
		c.Close()
		return nil, err
	}

	bConn := &basketConn{fileConn: fConn, isClient: isClient}
	bConn.writeChan = make(chan []byte, maxPendingFrames)
	bConn.localAddr = c.LocalAddr()
	bConn.remoteAddr = c.RemoteAddr()
	c.Close() // Everything else can be done via bConn.fileConn.

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
