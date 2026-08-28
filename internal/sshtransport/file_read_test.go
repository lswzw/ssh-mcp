package sshtransport

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReadFileRejectsInvalidRequestBeforeDispatch(t *testing.T) {
	t.Parallel()

	var factoryCalls int
	client := &Client{fileFactory: func() (readOnlySFTP, error) {
		factoryCalls++
		return nil, errors.New("factory must not be called")
	}}
	for _, tc := range []struct {
		name   string
		path   string
		offset int64
		limit  int
	}{
		{name: "relative", path: "etc/config", limit: 10},
		{name: "dot component", path: "/etc/./config", limit: 10},
		{name: "parent component", path: "/etc/../config", limit: 10},
		{name: "duplicate separator", path: "/etc//config", limit: 10},
		{name: "nul", path: "/etc/config\x00secret", limit: 10},
		{name: "negative offset", path: "/etc/config", offset: -1, limit: 10},
		{name: "zero limit", path: "/etc/config", limit: 0},
		{name: "over hard limit", path: "/etc/config", limit: MaxFileReadBytes + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.ReadFile(context.Background(), tc.path, tc.offset, tc.limit)
			if !errors.Is(err, ErrInvalidFileRead) {
				t.Fatalf("ReadFile() error = %v, want ErrInvalidFileRead", err)
			}
		})
	}
	if factoryCalls != 0 {
		t.Fatalf("file factory calls = %d, want 0", factoryCalls)
	}
}

func TestReadFileRejectsSymlinkAndNonRegularBeforeOpen(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		mode os.FileMode
		want error
	}{
		{name: "symlink", mode: os.ModeSymlink | 0o777, want: ErrFileSymlink},
		{name: "directory", mode: os.ModeDir | 0o755, want: ErrFileNotRegular},
		{name: "device", mode: os.ModeDevice | 0o600, want: ErrFileNotRegular},
		{name: "fifo", mode: os.ModeNamedPipe | 0o600, want: ErrFileNotRegular},
		{name: "socket", mode: os.ModeSocket | 0o600, want: ErrFileNotRegular},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := &fakeReadOnlySFTP{lstatInfo: fakeFileInfo{mode: tc.mode}}
			client := &Client{fileFactory: func() (readOnlySFTP, error) { return fs, nil }}
			_, err := client.ReadFile(context.Background(), "/etc/config", 0, 10)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ReadFile() error = %v, want %v", err, tc.want)
			}
			if fs.openCalls != 0 {
				t.Fatalf("Open calls = %d, want 0", fs.openCalls)
			}
		})
	}
}

func TestReadFileReturnsUTF8WithinOffsetAndLimit(t *testing.T) {
	t.Parallel()

	fs := &fakeReadOnlySFTP{
		lstatInfo: fakeFileInfo{mode: 0o600, size: int64(len("hello 世界"))},
		file:      &fakeReadOnlyFile{data: []byte("hello 世界")},
	}
	client := &Client{fileFactory: func() (readOnlySFTP, error) { return fs, nil }}

	result, err := client.ReadFile(context.Background(), "/etc/config", int64(len("hello ")), 6)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if result.Content != "世界" || result.Encoding != FileEncodingUTF8 || result.BytesRead != len("世界") || result.FileSize != int64(len("hello 世界")) || !result.EOF {
		t.Fatalf("ReadFile() result = %#v", result)
	}
	if fs.file.readOffset != int64(len("hello ")) || fs.file.readLength != 6 {
		t.Fatalf("ReadAt(offset,length) = (%d,%d), want (%d,6)", fs.file.readOffset, fs.file.readLength, len("hello "))
	}
}

func TestReadFileEncodesInvalidUTF8AsBase64(t *testing.T) {
	t.Parallel()

	payload := []byte{0x00, 0xff, 0x01, 0xfe}
	fs := &fakeReadOnlySFTP{
		lstatInfo: fakeFileInfo{mode: 0o600, size: int64(len(payload))},
		file:      &fakeReadOnlyFile{data: payload},
	}
	client := &Client{fileFactory: func() (readOnlySFTP, error) { return fs, nil }}
	result, err := client.ReadFile(context.Background(), "/var/data", 0, len(payload))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if result.Encoding != FileEncodingBase64 || result.Content != base64.StdEncoding.EncodeToString(payload) {
		t.Fatalf("base64 result = %#v", result)
	}
}

func TestReadFileRejectsOffsetPastEnd(t *testing.T) {
	t.Parallel()

	fs := &fakeReadOnlySFTP{lstatInfo: fakeFileInfo{mode: 0o600, size: 4}}
	client := &Client{fileFactory: func() (readOnlySFTP, error) { return fs, nil }}
	_, err := client.ReadFile(context.Background(), "/var/data", 5, 1)
	if !errors.Is(err, ErrFileOffsetOutOfRange) {
		t.Fatalf("ReadFile() error = %v, want ErrFileOffsetOutOfRange", err)
	}
	if fs.openCalls != 0 {
		t.Fatalf("Open calls = %d, want 0", fs.openCalls)
	}
}

func TestReadFileRejectsTypeChangedAfterOpen(t *testing.T) {
	t.Parallel()

	fs := &fakeReadOnlySFTP{
		lstatInfo: fakeFileInfo{mode: 0o600, size: 4},
		file:      &fakeReadOnlyFile{statInfo: fakeFileInfo{mode: os.ModeDir | 0o755, size: 4}},
	}
	client := &Client{fileFactory: func() (readOnlySFTP, error) { return fs, nil }}
	_, err := client.ReadFile(context.Background(), "/var/data", 0, 1)
	if !errors.Is(err, ErrFileNotRegular) {
		t.Fatalf("ReadFile() error = %v, want ErrFileNotRegular", err)
	}
	if fs.file.readCalls != 0 {
		t.Fatalf("ReadAt calls = %d, want 0", fs.file.readCalls)
	}
}

func TestReadFileCancellationBeforeDispatchIsNotDispatched(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	client := &Client{fileFactory: func() (readOnlySFTP, error) {
		called = true
		return nil, nil
	}}
	_, err := client.ReadFile(ctx, "/etc/config", 0, 1)
	if !errors.Is(err, ErrNotDispatched) {
		t.Fatalf("ReadFile() error = %v, want ErrNotDispatched", err)
	}
	if errors.Is(err, ErrFileReadOutcomeUnknown) || called {
		t.Fatalf("canceled request was dispatched: called=%t error=%v", called, err)
	}
}

func TestReadFileCancellationAfterDispatchIsOutcomeUnknown(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	closed := make(chan struct{})
	fs := &fakeReadOnlySFTP{
		lstatStarted: started,
		lstatRelease: closed,
	}
	client := &Client{fileFactory: func() (readOnlySFTP, error) { return fs, nil }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan error, 1)
	go func() {
		_, err := client.ReadFile(ctx, "/etc/config", 0, 1)
		resultCh <- err
	}()
	<-started
	cancel()
	err := <-resultCh
	if !errors.Is(err, ErrFileReadOutcomeUnknown) || errors.Is(err, ErrNotDispatched) {
		t.Fatalf("ReadFile() error = %v, want outcome unknown only", err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("SFTP channel was not closed after cancellation")
	}
}

func TestReadFileDoesNotExposeRemoteErrorText(t *testing.T) {
	t.Parallel()

	const secret = "remote-secret-content"
	fs := &fakeReadOnlySFTP{
		lstatInfo: fakeFileInfo{mode: 0o600, size: 4},
		file:      &fakeReadOnlyFile{statInfo: fakeFileInfo{mode: 0o600, size: 4}, readErr: errors.New(secret)},
	}
	client := &Client{fileFactory: func() (readOnlySFTP, error) { return fs, nil }}
	_, err := client.ReadFile(context.Background(), "/var/data", 0, 4)
	if !errors.Is(err, ErrFileReadFailed) || strings.Contains(err.Error(), secret) {
		t.Fatalf("ReadFile() error = %v, want sanitized ErrFileReadFailed", err)
	}
}

type fakeReadOnlySFTP struct {
	mu           sync.Mutex
	lstatInfo    os.FileInfo
	lstatErr     error
	openErr      error
	file         *fakeReadOnlyFile
	openCalls    int
	lstatStarted chan struct{}
	lstatRelease chan struct{}
	closeOnce    sync.Once
}

func (f *fakeReadOnlySFTP) Lstat(string) (os.FileInfo, error) {
	if f.lstatStarted != nil {
		close(f.lstatStarted)
	}
	if f.lstatRelease != nil {
		<-f.lstatRelease
	}
	if f.lstatErr != nil {
		return nil, f.lstatErr
	}
	return f.lstatInfo, nil
}

func (f *fakeReadOnlySFTP) Open(string) (readOnlySFTPFile, error) {
	f.mu.Lock()
	f.openCalls++
	f.mu.Unlock()
	if f.openErr != nil {
		return nil, f.openErr
	}
	return f.file, nil
}

func (f *fakeReadOnlySFTP) Close() error {
	f.closeOnce.Do(func() {
		if f.lstatRelease != nil {
			close(f.lstatRelease)
		}
	})
	return nil
}

type fakeReadOnlyFile struct {
	mu         sync.Mutex
	data       []byte
	statInfo   os.FileInfo
	statErr    error
	readErr    error
	readCalls  int
	readOffset int64
	readLength int
}

func (f *fakeReadOnlyFile) ReadAt(dst []byte, offset int64) (int, error) {
	f.mu.Lock()
	f.readCalls++
	f.readOffset = offset
	f.readLength = len(dst)
	f.mu.Unlock()
	if f.readErr != nil {
		return 0, f.readErr
	}
	if offset >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(dst, f.data[offset:])
	if n < len(dst) {
		return n, io.EOF
	}
	return n, nil
}

func (f *fakeReadOnlyFile) Stat() (os.FileInfo, error) {
	if f.statErr != nil {
		return nil, f.statErr
	}
	if f.statInfo != nil {
		return f.statInfo, nil
	}
	return fakeFileInfo{mode: 0o600, size: int64(len(f.data))}, nil
}

func (*fakeReadOnlyFile) Close() error { return nil }

type fakeFileInfo struct {
	mode os.FileMode
	size int64
}

func (f fakeFileInfo) Name() string       { return "remote" }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }
