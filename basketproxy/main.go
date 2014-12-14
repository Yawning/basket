// main.go - basket application code
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
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strconv"
	"sync"
	"syscall"

	"git.torproject.org/pluggable-transports/goptlib.git"

	"github.com/yawning/basket"
	"github.com/yawning/basket/cert"
)

var enableTofu bool
var enableLogging bool
var stateDir string
var handlerChan chan int
var knownHosts *knownHostsStore

const (
	ptMethodName = "basket"
	ptLogFile    = "basket.log"
	ptServerCert = "basket_server.b64"
	ptKnownHosts = "basket_known_hosts"

	digestArg  = "digest"
	authKeyArg = "authKey"
)

func infof(format string, a ...interface{}) {
	if enableLogging {
		msg := fmt.Sprintf(format, a...)
		log.Print("[INFO]: " + msg)
	}
}

func errorf(format string, a ...interface{}) {
	if enableLogging {
		msg := fmt.Sprintf(format, a...)
		log.Print("[ERROR]: " + msg)
	}
}

func warnf(format string, a ...interface{}) {
	if enableLogging {
		msg := fmt.Sprintf(format, a...)
		log.Print("[WARN]: " + msg)
	}
}

func envError(msg string) error {
	pt.Stdout.Write([]byte("ENV-ERROR " + msg + "\n"))
	return errors.New("basket: " + msg)
}

func ptIsClient() (bool, error) {
	clientEnv := os.Getenv("TOR_PT_CLIENT_TRANSPORTS")
	serverEnv := os.Getenv("TOR_PT_SERVER_TRANSPORTS")
	if clientEnv != "" && serverEnv != "" {
		return false, envError("TOR_PT_CLIENT_TRANSPORTS and TOR_PT_SERVER_TRANSPORTS are set")
	} else if clientEnv == "" && serverEnv == "" {
		return false, envError("not launched as a managed transport")
	}
	return clientEnv != "", nil
}

func clientAcceptLoop(socksListener *pt.SocksListener) error {
	defer socksListener.Close()
	for {
		conn, err := socksListener.AcceptSocks()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go clientHandler(conn)
	}
}

func clientHandler(socksConn *pt.SocksConn) {
	defer socksConn.Close()
	handlerChan <- 1
	defer func() {
		handlerChan <- -1
		if r := recover(); r != nil {
			warnf("clientHandler() recovered: %s", r)
		}
	}()

	// Convert the target to a TCPAddr.  This *could* just use
	// net.ResolveTCPAddr(), but that can potentially hit up DNS, while this
	// does not.
	tAddr, err := parseAddrPortStr(socksConn.Req.Target)
	if err != nil {
		warnf("parseAddrPortStr() failed: %s", err)
		socksConn.Reject()
		return
	}

	// Optionally use a short digest identifier instead of TOFU.
	if digestStr, ok := socksConn.Req.Args.Get(digestArg); ok {
		if err := knownHosts.registerDigest(tAddr, digestStr); err != nil {
			warnf("knownHosts.registerDigest() failed: %s", err)
			socksConn.Reject()
			return
		}
	}

	// Optionally authenticate with the server.
	var authKey []byte
	if authKeyStr, ok := socksConn.Req.Args.Get(authKeyArg); ok {
		if authKey, err = hex.DecodeString(authKeyStr); err != nil {
			warnf("invalid authKey: %s", err)
			socksConn.Reject()
			return
		}
	}

	// TODO: Pull out the handshake method from the args.
	cfg := &basket.ClientConfig{Method: basket.HandshakeNTRU, CertCheckFn: checkServerCert, AuthKey: authKey}
	basketConn, err := basket.Dial("tcp", tAddr, cfg)
	if err != nil {
		warnf("basket.Dial() failed: %s", err)
		socksConn.Reject()
		return
	}
	defer basketConn.Close()
	if err = socksConn.Grant(basketConn.RemoteAddr().(*net.TCPAddr)); err != nil {
		warnf("socksConn.Grant() failed: %s", err)
		return
	}

	if err = copyLoop(socksConn, basketConn); err != nil {
		// XXX: Log.
	} else {
		// XXX: Clean connection termination.
	}
}

func serverAcceptLoop(ln net.Listener, info *pt.ServerInfo) error {
	runtime.LockOSThread()
	defer func() {
		if r := recover(); r != nil {
			warnf("serverAcceptLoop() recovered: %s", r)
		}
	}()
	for {
		basketConn, err := ln.Accept()
		if err != nil {
			warnf("ln.Accept() failed: %s\n", err)
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				return err
			}
			continue
		}
		go serverHandler(basketConn, info)
	}
}

func serverHandler(basketConn net.Conn, info *pt.ServerInfo) {
	defer basketConn.Close()
	handlerChan <- 1
	defer func() {
		handlerChan <- 1
		if r := recover(); r != nil {
			warnf("serverHandler(): recovered: %s", r)
		}
	}()

	orConn, err := pt.DialOr(info, basketConn.RemoteAddr().String(), ptMethodName)
	if err != nil {
		warnf("pt.DialOr() failed: %s", err)
		return
	}
	defer orConn.Close()
	if err = copyLoop(orConn, basketConn); err != nil {
		// XXX: Log.
	} else {
		// XXX: Clean connection termination.
	}
}

func copyLoop(a, b net.Conn) error {
	errChan := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				warnf("copyLoop(b, a): recovered: %s", r)
			}
		}()

		defer wg.Done()
		defer b.Close()
		defer a.Close()
		_, err := io.Copy(b, a)
		errChan <- err
	}()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				warnf("copyLoop(a, b): recovered: %s", r)
			}
		}()

		defer wg.Done()
		defer a.Close()
		defer b.Close()
		_, err := io.Copy(a, b)
		errChan <- err
	}()

	wg.Wait()
	if len(errChan) > 0 {
		return <-errChan
	}
	return nil
}

func checkServerCert(addr *net.TCPAddr, serverCert cert.Certificate) error {
	err := knownHosts.checkCert(addr, serverCert, enableTofu)
	if err == nil {
		infof("Server Cert: %s: %s", addr, serverCert.String())
	} else {
		errorf("Server Cert: %s: VERIFICATION FAILED: %s", addr, err)
	}
	return err
}

func parseAddrPortStr(s string) (*net.TCPAddr, error) {
	hostStr, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(hostStr)
	if ip == nil {
		return nil, errors.New("parseAddrPortStr: invalid IP address")
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{IP: ip, Port: int(port)}, nil
}

func main() {
	flag.BoolVar(&enableLogging, "enableLogging", false, "Log to TOR_PT_STATE_LOCATION/"+ptLogFile)
	flag.BoolVar(&enableTofu, "enableTofu", true, "Trust-On-First-Use for server identity certs")
	flag.Parse()

	isClient, err := ptIsClient()
	if err != nil {
		os.Exit(-1)
	}

	if stateDir, err = pt.MakeStateDir(); err != nil {
		log.Fatalf("[ERROR]: No state directory: %s", err)
	}
	if enableLogging {
		f, err := os.OpenFile(path.Join(stateDir, ptLogFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			envError(fmt.Sprintf("failed to open log file: %s", err))
			os.Exit(-1)
		}
		log.SetOutput(f)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	handlerChan = make(chan int)
	var listeners []net.Listener
	if isClient {
		ptInfo, err := pt.ClientSetup([]string{ptMethodName})
		if err != nil {
			errorf("pt.ClientSetup() failed: %s", err)
		}

		for _, methodName := range ptInfo.MethodNames {
			switch methodName {
			case ptMethodName:
				// Load the known hosts store.
				knownHosts, err = newKnownHosts(path.Join(stateDir, ptKnownHosts))
				if err != nil {
					// XXX: Log
					pt.CmethodError(methodName, err.Error())
					continue
				}

				ln, err := pt.ListenSocks("tcp4", "127.0.0.1:0")
				if err != nil {
					// XXX: Log
					pt.CmethodError(methodName, err.Error())
					continue
				}
				go clientAcceptLoop(ln)
				pt.Cmethod(methodName, ln.Version(), ln.Addr())
				listeners = append(listeners, ln)
			default:
				pt.CmethodError(methodName, "no such method")
			}
		}
		pt.CmethodsDone()
	} else {
		ptInfo, err := pt.ServerSetup([]string{ptMethodName})
		if err != nil {
			errorf("pt.ServerSetup() failed: %s", err)
		}

		for _, bindaddr := range ptInfo.Bindaddrs {
			methodName := bindaddr.MethodName
			switch methodName {
			case ptMethodName:
				// TODO: Allow the user to specify the algorithm.
				serverCert, err := loadOrGenerateCert(path.Join(stateDir, ptServerCert), cert.AlgSphincs256)
				if err != nil {
					errorf("loadOrGenerateCert() failed: %s", err)
					pt.SmethodError(methodName, err.Error())
					continue
				}
				infof("Server Cert: %s", serverCert.String())

				var authKey []byte
				if authKeyStr, ok := bindaddr.Options.Get(authKeyArg); ok {
					if authKey, err = hex.DecodeString(authKeyStr); err != nil {
						errorf("invalid authKey: %s", err)
						pt.SmethodError(methodName, err.Error())
						continue
					}
				}

				cfg := &basket.ServerConfig{ServerCert: serverCert, AuthKey: authKey}
				ln, err := basket.Listen("tcp", bindaddr.Addr, cfg)
				if err != nil {
					// XXX: Log
					pt.SmethodError(methodName, err.Error())
					continue
				}

				// Force at least 2 OS threads so that it's possible to pin the
				// serverAcceptLoop.
				if runtime.GOMAXPROCS(0) < 2 {
					runtime.GOMAXPROCS(2)
				}

				go serverAcceptLoop(ln, &ptInfo)
				// TODO: Publish the authKey and digest to BridgeDB.
				pt.SmethodArgs(methodName, ln.Addr(), nil)
				listeners = append(listeners, ln)
			default:
				pt.SmethodError(methodName, "no such method")
			}
		}
		pt.SmethodsDone()
	}
	if len(listeners) == 0 {
		os.Exit(-1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	var sig os.Signal
	numHandlers := 0
	for sig == nil {
		select {
		case n := <-handlerChan:
			numHandlers += n
		case sig = <-sigChan:
			if sig == syscall.SIGTERM {
				return
			}
		}
	}
	sig = nil
	for sig == nil && numHandlers != 0 {
		select {
		case n := <-handlerChan:
			numHandlers += n
		case sig = <-sigChan:
		}
	}
}
