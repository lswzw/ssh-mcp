//go:build !linux && !darwin && !windows

package unixtransport

import (
	"errors"
	"net"
)

func peerCredentials(net.Conn) (Peer, error) {
	return Peer{}, errors.New("peer credentials are not implemented on this platform")
}
