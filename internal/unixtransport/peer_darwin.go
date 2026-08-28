//go:build darwin

package unixtransport

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
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
	var uid int
	var pid int
	var controlErr error
	err = rawConnection.Control(func(fd uintptr) {
		credential, credentialErr := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credentialErr != nil {
			controlErr = credentialErr
			return
		}
		uid = int(credential.Uid)
		pid, controlErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if err != nil {
		return Peer{}, err
	}
	if controlErr != nil {
		return Peer{}, controlErr
	}
	return Peer{UID: uid, PID: pid}, nil
}
