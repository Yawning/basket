// kist_linux.go - Linux Kernel-Informed Socket-Transport
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

// Package kist implements the link capacity estimation algorithm from
// "Never Been KIST: Tor’s Congestion Management Blossoms with Kernel-Informed
// Socket Transport".
package kist

import (
	"os"
	"syscall"
	"unsafe"
)

// EstimateWriteCapacity attempts to figure out how much can be written to a
// given os.File without blocking.  It is assumed that the os.File is actually
// a TCP socket (since the algorithm queries TCP_INFO), but since the Go
// runtime doesn't deem users worthy to get at the raw file descriptor, an
// os.File is used instead.
func EstimateWriteCapacity(f *os.File) (int, error) {
	// Estimate the amount of write capacity available on a given connection by
	// using the algorithm specified in "Never Been KIST: Tor’s Congestion
	// Management Blossoms with Kernel-Informed Socket Transport".
	//
	// The amount that can be sent any time can be estimated as:
	//  socket_space = sndbufcap - sndbuflen
	//  tcp_space = (cwnd - unacked) * mss
	//  limit = min(socket_space, tcp_space)

	fd := f.Fd()

	// Detemine the total capacity of the send socket buffer "sndbufcap", with
	// a SO_SNDBUF getsockopt() call, and the current amount of data in the
	// send socket buffer "sndbuflen" with a TIOCOUTQ ioctl.
	//
	// NB: SIOCOUTQ is the Linux-ism that is more accurately named, but they
	// are functionally equivalent.
	var value int
	valueLen := uint32(unsafe.Sizeof(value))
	if _, _, e1 := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, uintptr(unsafe.Pointer(&value)), uintptr(unsafe.Pointer(&valueLen)), 0); e1 != 0 {
		return 0, e1
	}
	sndbufcap := value
	if _, _, e1 := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCOUTQ, uintptr(unsafe.Pointer(&value))); e1 != 0 {
		return 0, e1
	}
	sndbuflen := value
	socketSpace := sndbufcap - sndbuflen

	// Determine the tcp_space via a TCP_INFO getsockopt() call.
	var info syscall.TCPInfo
	infoLen := uint32(syscall.SizeofTCPInfo)
	if _, _, e1 := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_TCP, syscall.TCP_INFO, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&infoLen)), 0); e1 != 0 {
		return 0, e1
	}
	tcpSpace := (info.Snd_cwnd - info.Unacked) * info.Snd_mss

	// Return the minimum of the two capacities.
	if int(tcpSpace) > socketSpace {
		return socketSpace, nil
	}
	return int(tcpSpace), nil
}
