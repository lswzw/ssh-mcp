//go:build darwin || linux

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func daemonSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}
