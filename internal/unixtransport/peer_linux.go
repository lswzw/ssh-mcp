//go:build linux

package unixtransport

import (
	"fmt"
	"net"
	"syscall"
)

func peerCredentials(connection net.Conn) (Peer, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return Peer{}, fmt.Errorf("local transport is not a Unix connection")
	}
	rawConnection, err := unixConnection.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var credential *syscall.Ucred
	var controlErr error
	err = rawConnection.Control(func(fd uintptr) {
		credential, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return Peer{}, err
	}
	if controlErr != nil {
		return Peer{}, controlErr
	}
	return Peer{UID: int(credential.Uid), PID: int(credential.Pid)}, nil
}
