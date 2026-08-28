package dbtransport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPostgresTLSRefusalFailsClosed(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct{}, 1)
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		accepted <- struct{}{}

		var request [8]byte
		if _, err := io.ReadFull(connection, request[:]); err != nil {
			serverDone <- err
			return
		}
		if got, want := binary.BigEndian.Uint32(request[:4]), uint32(8); got != want {
			serverDone <- &unexpectedValue{got: got, want: want}
			return
		}
		if got, want := binary.BigEndian.Uint32(request[4:]), uint32(postgresSSLRequestCode); got != want {
			serverDone <- &unexpectedValue{got: got, want: want}
			return
		}
		if _, err := connection.Write([]byte{'N'}); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	connection, err := negotiatePostgresTLS(context.Background(), listener.Addr().String(), &tls.Config{ServerName: "127.0.0.1"})
	if connection != nil {
		_ = connection.Close()
		t.Fatal("negotiatePostgresTLS() returned a connection after TLS refusal")
	}
	if err == nil || !strings.Contains(err.Error(), "refused required TLS") {
		t.Fatalf("negotiatePostgresTLS() error = %v, want TLS refusal", err)
	}

	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("server did not observe the connection")
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server protocol error = %v", err)
	}
}

func TestResultCollectorEnforcesRowAndByteLimits(t *testing.T) {
	t.Parallel()

	collector, err := newResultCollector(Limits{MaxRows: 1, MaxBytes: 8})
	if err != nil {
		t.Fatalf("newResultCollector() error = %v", err)
	}
	if collector.addRow([]string{"abcd"}) {
		t.Fatal("first row unexpectedly exceeded the limit")
	}
	if !collector.addRow([]string{"efgh"}) {
		t.Fatal("second row did not exceed the row limit")
	}
	result := collector.result([]string{"value"})
	if len(result.Rows) != 1 || !result.RowsTruncated || result.BytesTruncated {
		t.Fatalf("row-limited result = %#v", result)
	}

	collector, err = newResultCollector(Limits{MaxRows: 2, MaxBytes: 3})
	if err != nil {
		t.Fatalf("newResultCollector() error = %v", err)
	}
	if !collector.addRow([]string{"four"}) {
		t.Fatal("oversized row did not exceed the byte limit")
	}
	result = collector.result([]string{"value"})
	if len(result.Rows) != 0 || result.RowsTruncated || !result.BytesTruncated {
		t.Fatalf("byte-limited result = %#v", result)
	}
}

func TestResultCollectorAcceptsExplicitFiniteOutputLimitAboveDefault(t *testing.T) {
	t.Parallel()

	collector, err := newResultCollector(Limits{MaxRows: 1, MaxBytes: 128 << 10})
	if err != nil {
		t.Fatalf("newResultCollector() error = %v", err)
	}
	if collector.limits.MaxBytes != 128<<10 {
		t.Fatalf("MaxBytes = %d, want %d", collector.limits.MaxBytes, 128<<10)
	}
}

type unexpectedValue struct {
	got  uint32
	want uint32
}

func (e *unexpectedValue) Error() string {
	return "unexpected PostgreSQL TLS request value"
}
