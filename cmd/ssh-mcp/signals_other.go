//go:build !darwin && !linux && !windows

package main

import "context"

func daemonSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}
