//go:build windows

package main

import (
	"context"
	"os"
	"os/signal"
)

func daemonSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt)
}
