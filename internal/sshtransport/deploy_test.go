// These tests are the transport-level contract for the controlled binary
// deployment API. The production API exposes one high-level DeployBinary
// operation and a test seam for a protocol adapter with only the operations
// used below.
package sshtransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDeployBinaryBacksUpBeforeServerSideActivation(t *testing.T) {
	t.Parallel()

	const target = "/srv/app/bin/service.jar"
	payload := []byte("jar bytes are not an audit record")
	oldPayload := []byte("previous jar bytes stay in the backup")
	fs := newDeployContractFS(target, oldPayload)
	client := newDeployContractClient(t, fs)

	result, err := client.DeployBinary(context.Background(), bytes.NewReader(payload), BinaryDeploymentRequest{
		RemotePath:     target,
		ExpectedSize:   int64(len(payload)),
		ExpectedSHA256: deploySHA256(payload),
		MaxBytes:       int64(len(payload)),
	})
	if err != nil {
		t.Fatalf("DeployBinary() error = %v", err)
	}
	if result.RemotePath != target || result.BytesUploaded != int64(len(payload)) ||
		result.SHA256 != deploySHA256(payload) || result.BackupPath == "" || !result.Activated {
		t.Fatalf("DeployBinary() result = %#v", result)
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.openedTarget {
		t.Fatal("deployment opened the live target for writing")
	}
	if fs.usedTruncate {
		t.Fatal("deployment used O_TRUNC instead of an exclusive temporary file")
	}
	backupIndex, activationIndex := fs.indexOfRename(target, result.BackupPath), fs.indexOfRename(fs.tempPath, target)
	if backupIndex < 0 || activationIndex < 0 || backupIndex >= activationIndex {
		t.Fatalf("rename order = %#v, want target->backup before temp->target", fs.renames)
	}
	if fs.files[result.BackupPath] == nil || !bytes.Equal(fs.files[result.BackupPath], oldPayload) {
		t.Fatalf("backup content was not preserved: %#v", fs.files)
	}
	if !bytes.Equal(fs.files[target], payload) {
		t.Fatalf("activated target content = %q, want payload", fs.files[target])
	}
	if path.Dir(result.BackupPath) != path.Dir(target) || path.Base(result.BackupPath) == path.Base(target) {
		t.Fatalf("backup path = %q, want a distinct sibling of %q", result.BackupPath, target)
	}
}

func TestDeployBinaryAcceptsAnEmptyRegularFile(t *testing.T) {
	t.Parallel()

	const target = "/srv/app/releases/marker"
	oldPayload := []byte("previous release marker")
	fs := newDeployContractFS(target, oldPayload)
	client := newDeployContractClient(t, fs)

	result, err := client.DeployBinary(context.Background(), bytes.NewReader(nil), BinaryDeploymentRequest{
		RemotePath: target, ExpectedSize: 0, ExpectedSHA256: deploySHA256(nil), MaxBytes: 1,
	})
	if err != nil {
		t.Fatalf("DeployBinary() error = %v", err)
	}
	if !result.Activated || result.BytesUploaded != 0 || result.SHA256 != deploySHA256(nil) {
		t.Fatalf("DeployBinary() result = %#v", result)
	}

	fs.mu.Lock()
	deployed, deployedOK := fs.files[target]
	backup := fs.files[result.BackupPath]
	fs.mu.Unlock()
	if !deployedOK || len(deployed) != 0 {
		t.Fatalf("activated empty source = %q, exists = %v", deployed, deployedOK)
	}
	if !bytes.Equal(backup, oldPayload) {
		t.Fatalf("backup content = %q, want %q", backup, oldPayload)
	}
}

func TestDeployBinaryWritesExclusiveTemporaryFileWithoutPermissionChanges(t *testing.T) {
	t.Parallel()

	const target = "/srv/app/bin/service"
	fs := newDeployContractFS(target, []byte("old"))
	client := newDeployContractClient(t, fs)
	payload := []byte("new")
	if _, err := client.DeployBinary(context.Background(), bytes.NewReader(payload), BinaryDeploymentRequest{
		RemotePath: target, ExpectedSize: int64(len(payload)), ExpectedSHA256: deploySHA256(payload), MaxBytes: 3,
	}); err != nil {
		t.Fatalf("DeployBinary() error = %v", err)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.writeCount == 0 {
		t.Fatal("temporary source was not written")
	}
}

func TestDeployBinaryRefusesToCreateUnbackedTarget(t *testing.T) {
	t.Parallel()

	const target = "/srv/app/bin/missing"
	fs := newDeployContractFS(target, []byte("old"))
	fs.targetMissing = true
	client := newDeployContractClient(t, fs)

	_, err := client.DeployBinary(context.Background(), bytes.NewReader([]byte("new")), BinaryDeploymentRequest{
		RemotePath: target, ExpectedSize: 3, ExpectedSHA256: deploySHA256([]byte("new")), MaxBytes: 3,
	})
	if err == nil {
		t.Fatal("DeployBinary() unexpectedly created a target without a backup")
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.renames) != 0 || fs.writeCount != 0 {
		t.Fatalf("unbacked deployment changed remote state: writes=%d renames=%#v", fs.writeCount, fs.renames)
	}
}

func TestDeployBinaryRejectsSymlinkAndNonRegularTargetBeforeUpload(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		mode os.FileMode
	}{
		{name: "symlink", mode: os.ModeSymlink | 0o777},
		{name: "directory", mode: os.ModeDir | 0o755},
		{name: "device", mode: os.ModeDevice | 0o600},
		{name: "fifo", mode: os.ModeNamedPipe | 0o600},
		{name: "socket", mode: os.ModeSocket | 0o600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newDeployContractFS("/srv/app/bin/service", []byte("old"))
			fs.targetInfo = deployContractInfo{mode: tc.mode, size: 3}
			client := newDeployContractClient(t, fs)
			_, err := client.DeployBinary(context.Background(), bytes.NewReader([]byte("new")), BinaryDeploymentRequest{
				RemotePath: "/srv/app/bin/service", ExpectedSize: 3,
				ExpectedSHA256: deploySHA256([]byte("new")), MaxBytes: 3,
			})
			if err == nil {
				t.Fatal("DeployBinary() accepted a non-regular target")
			}
			fs.mu.Lock()
			defer fs.mu.Unlock()
			if fs.writeCount != 0 || len(fs.renames) != 0 {
				t.Fatalf("non-regular target was modified: writes=%d renames=%#v", fs.writeCount, fs.renames)
			}
		})
	}
}

func TestDeployBinaryRejectsUncanonicalRemotePathsBeforeProtocolDispatch(t *testing.T) {
	t.Parallel()

	var factoryCalls int
	client := &Client{deploymentFactory: func() (deploymentProtocol, error) {
		factoryCalls++
		return nil, errors.New("deployment protocol must not start")
	}}
	for _, remotePath := range []string{
		"relative/app", "/srv/app/./service", "/srv/app/../service", "/srv/app//service",
		"/srv/app/service/", "/srv/app/service\x00secret",
	} {
		_, err := client.DeployBinary(context.Background(), bytes.NewReader([]byte("new")), BinaryDeploymentRequest{
			RemotePath: remotePath, ExpectedSize: 3, ExpectedSHA256: deploySHA256([]byte("new")), MaxBytes: 3,
		})
		if err == nil {
			t.Fatalf("DeployBinary(%q) unexpectedly accepted a non-canonical path", remotePath)
		}
	}
	if factoryCalls != 0 {
		t.Fatalf("deployment protocol calls = %d, want 0", factoryCalls)
	}
}

func TestDeployBinaryVerifiesDigestAndSizeBeforeBackup(t *testing.T) {
	t.Parallel()

	const target = "/srv/app/bin/service"
	payload := []byte("new source")
	fs := newDeployContractFS(target, []byte("old source"))
	client := newDeployContractClient(t, fs)

	_, err := client.DeployBinary(context.Background(), bytes.NewReader(payload), BinaryDeploymentRequest{
		RemotePath: target, ExpectedSize: int64(len(payload) + 1), ExpectedSHA256: deploySHA256(payload), MaxBytes: 1 << 20,
	})
	if err == nil {
		t.Fatal("DeployBinary() accepted an incorrect expected size")
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.indexOfRename(target, "") >= 0 {
		t.Fatalf("target was backed up despite an integrity failure: %#v", fs.renames)
	}
	if !bytes.Equal(fs.files[target], []byte("old source")) {
		t.Fatal("integrity failure changed the live target")
	}
}

func TestDeployBinaryVerifiesRemoteTemporaryDigestBeforeBackup(t *testing.T) {
	t.Parallel()

	const target = "/srv/app/bin/service"
	payload := []byte("new source")
	fs := newDeployContractFS(target, []byte("old source"))
	fs.tamperTemporaryRead = true
	client := newDeployContractClient(t, fs)

	_, err := client.DeployBinary(context.Background(), bytes.NewReader(payload), BinaryDeploymentRequest{
		RemotePath: target, ExpectedSize: int64(len(payload)), ExpectedSHA256: deploySHA256(payload), MaxBytes: 1 << 20,
	})
	if err == nil {
		t.Fatal("DeployBinary() accepted a tampered temporary source")
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.indexOfRename(target, "") >= 0 {
		t.Fatalf("target was backed up before remote digest verification: %#v", fs.renames)
	}
	if !bytes.Equal(fs.files[target], []byte("old source")) {
		t.Fatal("remote digest failure changed the live target")
	}
	if fs.tempPath != "" && fs.files[fs.tempPath] != nil {
		t.Fatalf("temporary source was not cleaned: %q", fs.tempPath)
	}
}

func TestDeployBinaryNeverOverwritesAnExistingBackup(t *testing.T) {
	t.Parallel()

	const target = "/srv/app/bin/service"
	fs := newDeployContractFS(target, []byte("old"))
	fs.backupNameExists = true
	client := newDeployContractClient(t, fs)

	_, err := client.DeployBinary(context.Background(), bytes.NewReader([]byte("new")), BinaryDeploymentRequest{
		RemotePath: target, ExpectedSize: 3, ExpectedSHA256: deploySHA256([]byte("new")), MaxBytes: 3,
	})
	if err == nil {
		t.Fatal("DeployBinary() overwrote an existing backup")
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.indexOfRename(target, "") >= 0 {
		t.Fatalf("live target moved despite backup collision: %#v", fs.renames)
	}
	if !bytes.Equal(fs.files[target], []byte("old")) {
		t.Fatal("backup collision changed live target")
	}
}

func TestDeployBinaryCleansTemporaryAfterKnownBackupRenameCollision(t *testing.T) {
	t.Parallel()

	const target = "/srv/app/bin/service"
	fs := newDeployContractFS(target, []byte("old"))
	// The preflight Lstat reports no backup, but the server reports a known
	// destination collision when the mandatory backup rename is dispatched.
	fs.backupRenameErr = os.ErrExist
	client := newDeployContractClient(t, fs)

	_, err := client.DeployBinary(context.Background(), bytes.NewReader([]byte("new")), BinaryDeploymentRequest{
		RemotePath: target, ExpectedSize: 3, ExpectedSHA256: deploySHA256([]byte("new")), MaxBytes: 3,
	})
	if !errors.Is(err, ErrDeploymentBackupExists) {
		t.Fatalf("DeployBinary() error = %v, want backup collision", err)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if !bytes.Equal(fs.files[target], []byte("old")) {
		t.Fatalf("known backup collision changed live target: %q", fs.files[target])
	}
	if fs.removedPath != fs.tempPath || fs.tempPath == "" {
		t.Fatalf("temporary source was not cleaned after known collision: removed=%q temp=%q", fs.removedPath, fs.tempPath)
	}
}

func TestDeployBinaryFailsClosedWhenBackupOrMissingTargetCannotBeVerified(t *testing.T) {
	t.Parallel()

	t.Run("backup lstat returned nil info", func(t *testing.T) {
		fs := newDeployContractFS("/srv/app/bin/service", []byte("old"))
		fs.nilBackupLstat = true
		client := newDeployContractClient(t, fs)
		_, err := client.DeployBinary(context.Background(), bytes.NewReader([]byte("new")), BinaryDeploymentRequest{
			RemotePath: "/srv/app/bin/service", ExpectedSize: 3, ExpectedSHA256: deploySHA256([]byte("new")), MaxBytes: 3,
		})
		if err == nil {
			t.Fatal("DeployBinary() accepted a malformed backup Lstat response")
		}
		fs.mu.Lock()
		defer fs.mu.Unlock()
		if fs.indexOfRename(fs.targetPath, "") >= 0 {
			t.Fatalf("target moved despite unverified backup path: %#v", fs.renames)
		}
	})

	t.Run("target lstat returned nil info after backup", func(t *testing.T) {
		fs := newDeployContractFS("/srv/app/bin/service", []byte("old"))
		fs.nilMissingTargetLstat = true
		client := newDeployContractClient(t, fs)
		_, err := client.DeployBinary(context.Background(), bytes.NewReader([]byte("new")), BinaryDeploymentRequest{
			RemotePath: "/srv/app/bin/service", ExpectedSize: 3, ExpectedSHA256: deploySHA256([]byte("new")), MaxBytes: 3,
		})
		if !errors.Is(err, ErrDeploymentOutcomeUnknown) {
			t.Fatalf("DeployBinary() error = %v, want outcome unknown", err)
		}
		fs.mu.Lock()
		defer fs.mu.Unlock()
		if fs.activationCalls != 0 {
			t.Fatalf("activation calls = %d, want 0 after malformed Lstat", fs.activationCalls)
		}
	})
}

func TestDeployBinaryClosesTemporaryWriterBeforeCleanup(t *testing.T) {
	t.Parallel()

	fs := newDeployContractFS("/srv/app/bin/service", []byte("old"))
	fs.writeErr = errors.New("write failed")
	client := newDeployContractClient(t, fs)
	_, err := client.DeployBinary(context.Background(), bytes.NewReader([]byte("new")), BinaryDeploymentRequest{
		RemotePath: "/srv/app/bin/service", ExpectedSize: 3, ExpectedSHA256: deploySHA256([]byte("new")), MaxBytes: 3,
	})
	if err == nil {
		t.Fatal("DeployBinary() unexpectedly succeeded")
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.writerCloseCalls != 1 || fs.removeBeforeWriterClose {
		t.Fatalf("temporary cleanup did not close its writer first: closes=%d early_remove=%t", fs.writerCloseCalls, fs.removeBeforeWriterClose)
	}
}

func TestDeployBinaryRollsBackAfterActivationFailureWithoutOverwriting(t *testing.T) {
	t.Parallel()

	const target = "/srv/app/bin/service"
	oldPayload, newPayload := []byte("old"), []byte("new")
	fs := newDeployContractFS(target, oldPayload)
	fs.failActivation = errors.New("activation failed: do not expose this detail")
	client := newDeployContractClient(t, fs)

	result, err := client.DeployBinary(context.Background(), bytes.NewReader(newPayload), BinaryDeploymentRequest{
		RemotePath: target, ExpectedSize: int64(len(newPayload)), ExpectedSHA256: deploySHA256(newPayload), MaxBytes: 3,
	})
	if err == nil {
		t.Fatal("DeployBinary() hid an activation failure")
	}
	if result.BackupPath == "" {
		t.Fatalf("activation failure result lost backup path: %#v", result)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	backupIndex := fs.indexOfRename(target, "")
	rollbackIndex := fs.indexOfRenamePrefix(".ssh-mcp-backup-", target)
	if backupIndex < 0 || rollbackIndex < 0 || backupIndex >= rollbackIndex {
		t.Fatalf("rollback order = %#v, want backup then one rollback", fs.renames)
	}
	if !bytes.Equal(fs.files[target], oldPayload) {
		t.Fatalf("rollback target = %q, want old payload", fs.files[target])
	}
	if fs.openedTarget || fs.usedTruncate {
		t.Fatal("rollback used a direct target write")
	}
}

func TestDeployBinaryCancellationBeforeDispatchIsNotDispatched(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var factoryCalls int
	client := &Client{deploymentFactory: func() (deploymentProtocol, error) {
		factoryCalls++
		return nil, errors.New("must not dial")
	}}
	_, err := client.DeployBinary(ctx, bytes.NewReader([]byte("new")), BinaryDeploymentRequest{
		RemotePath: "/srv/app/bin/service", ExpectedSize: 3, ExpectedSHA256: deploySHA256([]byte("new")), MaxBytes: 3,
	})
	if !errors.Is(err, ErrNotDispatched) || errors.Is(err, ErrDeploymentOutcomeUnknown) {
		t.Fatalf("canceled pre-dispatch error = %v, want ErrNotDispatched only", err)
	}
	if factoryCalls != 0 {
		t.Fatalf("deployment protocol calls = %d, want 0", factoryCalls)
	}
}

func TestDeployBinaryCancellationAfterActivationStartedIsOutcomeUnknown(t *testing.T) {
	t.Parallel()

	const target = "/srv/app/bin/service"
	fs := newDeployContractFS(target, []byte("old"))
	fs.blockActivation = true
	client := newDeployContractClient(t, fs)
	ctx, cancel := context.WithCancel(context.Background())
	deployed := make(chan error, 1)
	go func() {
		_, err := client.DeployBinary(ctx, bytes.NewReader([]byte("new")), BinaryDeploymentRequest{
			RemotePath: target, ExpectedSize: 3, ExpectedSHA256: deploySHA256([]byte("new")), MaxBytes: 3,
		})
		deployed <- err
	}()
	select {
	case <-fs.activationStarted:
	case <-time.After(time.Second):
		t.Fatal("activation did not start")
	}
	cancel()
	close(fs.activationRelease)
	err := <-deployed
	if !errors.Is(err, ErrDeploymentOutcomeUnknown) || errors.Is(err, ErrNotDispatched) {
		t.Fatalf("post-dispatch cancellation error = %v, want outcome unknown", err)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.activationCalls != 1 {
		t.Fatalf("activation calls = %d, want no automatic retry", fs.activationCalls)
	}
	if fs.tempPath == "" {
		t.Fatal("deployment did not create a temporary path")
	}
	if fs.removedPath == fs.tempPath {
		t.Fatalf("unknown activation state removed temporary path %q", fs.tempPath)
	}
}

func TestDeployBinaryCancellationDuringUploadIsOutcomeUnknown(t *testing.T) {
	t.Parallel()

	const target = "/srv/app/bin/service"
	fs := newDeployContractFS(target, []byte("old"))
	client := newDeployContractClient(t, fs)
	ctx, cancel := context.WithCancel(context.Background())
	source := newBlockingDeploymentReader()
	deployed := make(chan error, 1)
	go func() {
		_, err := client.DeployBinary(ctx, source, BinaryDeploymentRequest{
			RemotePath: target, ExpectedSize: 3, ExpectedSHA256: deploySHA256([]byte("new")), MaxBytes: 3,
		})
		deployed <- err
	}()
	select {
	case <-source.started:
	case <-time.After(time.Second):
		t.Fatal("upload reader did not start")
	}
	cancel()
	err := <-deployed
	close(source.release)
	if !errors.Is(err, ErrDeploymentOutcomeUnknown) || errors.Is(err, ErrDeploymentFailed) {
		t.Fatalf("upload cancellation error = %v, want outcome unknown", err)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.indexOfRename(target, "") >= 0 {
		t.Fatalf("upload cancellation changed live target: %#v", fs.renames)
	}
	if fs.removedPath != fs.tempPath {
		t.Fatalf("upload cancellation did not clean pre-mutation temporary file: removed=%q temp=%q", fs.removedPath, fs.tempPath)
	}
}

func TestDeployBinaryRejectsSameSizeTargetReplacementBeforeBackup(t *testing.T) {
	t.Parallel()

	const target = "/srv/app/bin/service"
	fs := newDeployContractFS(target, []byte("old"))
	fs.targetInfo = deployContractInfo{mode: 0o755, size: 3, modTime: time.Unix(10, 0)}
	fs.currentTargetInfo = deployContractInfo{mode: 0o755, size: 3, modTime: time.Unix(20, 0)}
	client := newDeployContractClient(t, fs)
	payload := []byte("new")
	_, err := client.DeployBinary(context.Background(), bytes.NewReader(payload), BinaryDeploymentRequest{
		RemotePath: target, ExpectedSize: int64(len(payload)), ExpectedSHA256: deploySHA256(payload), MaxBytes: 3,
	})
	if !errors.Is(err, ErrDeploymentTargetChanged) {
		t.Fatalf("DeployBinary() error = %v, want target changed", err)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.indexOfRename(target, "") >= 0 {
		t.Fatalf("same-size target replacement was backed up: %#v", fs.renames)
	}
}

func TestDeployBinaryRejectsMalformedSourceReader(t *testing.T) {
	t.Parallel()

	const target = "/srv/app/bin/service"
	fs := newDeployContractFS(target, []byte("old"))
	client := newDeployContractClient(t, fs)
	_, err := client.DeployBinary(context.Background(), malformedDeploymentReader{}, BinaryDeploymentRequest{
		RemotePath: target, ExpectedSize: 1, ExpectedSHA256: deploySHA256([]byte("x")), MaxBytes: 3,
	})
	if err == nil {
		t.Fatal("DeployBinary() accepted a source reader that returned an invalid byte count")
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.indexOfRename(target, "") >= 0 {
		t.Fatalf("malformed source changed live target: %#v", fs.renames)
	}
}

func TestDeployBinarySanitizesRemoteErrorsAndNeverReturnsSourceBytes(t *testing.T) {
	t.Parallel()

	const target = "/srv/app/bin/service"
	secret := []byte("private-build-signature-should-not-leak")
	fs := newDeployContractFS(target, []byte("old"))
	fs.writeErr = fmt.Errorf("remote protocol rejected bytes: %s", secret)
	client := newDeployContractClient(t, fs)

	_, err := client.DeployBinary(context.Background(), bytes.NewReader(secret), BinaryDeploymentRequest{
		RemotePath: target, ExpectedSize: int64(len(secret)), ExpectedSHA256: deploySHA256(secret), MaxBytes: 1 << 20,
	})
	if err == nil || strings.Contains(err.Error(), string(secret)) || strings.Contains(err.Error(), "remote protocol rejected") {
		t.Fatalf("DeployBinary() exposed remote/source detail: %v", err)
	}
}

func TestDeployBinaryEnforcesAnIndependentHardSizeLimit(t *testing.T) {
	t.Parallel()

	var factoryCalls int
	client := &Client{deploymentFactory: func() (deploymentProtocol, error) {
		factoryCalls++
		return nil, errors.New("must not start for an over-limit source")
	}}
	_, err := client.DeployBinary(context.Background(), bytes.NewReader([]byte("x")), BinaryDeploymentRequest{
		RemotePath: "/srv/app/bin/service", ExpectedSize: MaxBinaryDeploymentBytes + 1, ExpectedSHA256: deploySHA256([]byte("x")),
		MaxBytes: MaxBinaryDeploymentBytes + 1,
	})
	if err == nil {
		t.Fatal("DeployBinary() accepted a source over its hard limit")
	}
	if factoryCalls != 0 {
		t.Fatalf("deployment protocol calls = %d, want 0", factoryCalls)
	}
}

func deploySHA256(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func newDeployContractClient(t *testing.T, fs *deployContractFS) *Client {
	t.Helper()
	return &Client{deploymentFactory: func() (deploymentProtocol, error) { return fs, nil }}
}

type deployContractFS struct {
	mu                      sync.Mutex
	targetPath              string
	tempPath                string
	targetInfo              os.FileInfo
	targetMissing           bool
	files                   map[string][]byte
	openedTarget            bool
	usedTruncate            bool
	writeCount              int
	openWrites              []string
	renames                 [][2]string
	backupNameExists        bool
	backupRenameErr         error
	nilBackupLstat          bool
	nilMissingTargetLstat   bool
	tamperTemporaryRead     bool
	failActivation          error
	writeErr                error
	blockActivation         bool
	activationStarted       chan struct{}
	activationRelease       chan struct{}
	activationCalls         int
	currentTargetInfo       os.FileInfo
	targetLstatCalls        int
	closeCalls              int
	removedPath             string
	writerCloseCalls        int
	removeBeforeWriterClose bool
}

func newDeployContractFS(target string, oldPayload []byte) *deployContractFS {
	return &deployContractFS{
		targetPath:        target,
		targetInfo:        deployContractInfo{mode: 0o755, size: int64(len(oldPayload))},
		files:             map[string][]byte{target: append([]byte(nil), oldPayload...)},
		activationStarted: make(chan struct{}),
		activationRelease: make(chan struct{}),
	}
}

func (f *deployContractFS) Lstat(remotePath string) (os.FileInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if remotePath == f.targetPath {
		if f.targetMissing {
			return nil, os.ErrNotExist
		}
		if _, exists := f.files[remotePath]; !exists {
			if f.nilMissingTargetLstat {
				return nil, nil
			}
			return nil, os.ErrNotExist
		}
		f.targetLstatCalls++
		if f.currentTargetInfo != nil && f.targetLstatCalls > 1 {
			return f.currentTargetInfo, nil
		}
		return f.targetInfo, nil
	}
	if strings.HasPrefix(path.Base(remotePath), ".ssh-mcp-backup-") && f.nilBackupLstat {
		return nil, nil
	}
	if strings.HasPrefix(path.Base(remotePath), ".ssh-mcp-backup-") && f.backupNameExists {
		return deployContractInfo{mode: 0o600, size: 1}, nil
	}
	if data, ok := f.files[remotePath]; ok {
		return deployContractInfo{mode: 0o600, size: int64(len(data))}, nil
	}
	return nil, os.ErrNotExist
}

func (f *deployContractFS) OpenFile(remotePath string, flags int, _ os.FileMode) (io.WriteCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.openWrites = append(f.openWrites, remotePath)
	if remotePath == f.targetPath {
		f.openedTarget = true
	}
	if flags&os.O_TRUNC != 0 {
		f.usedTruncate = true
	}
	if remotePath == f.targetPath || flags&os.O_EXCL == 0 || flags&os.O_CREATE == 0 || flags&os.O_TRUNC != 0 {
		return nil, errors.New("deployment must exclusively create a temporary file")
	}
	f.tempPath = remotePath
	return &deployContractWriter{owner: f, path: remotePath}, nil
}

func (f *deployContractFS) Open(remotePath string) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.files[remotePath]
	if !ok {
		return nil, os.ErrNotExist
	}
	if f.tamperTemporaryRead && remotePath == f.tempPath {
		data = append([]byte(nil), data...)
		if len(data) == 0 {
			data = []byte("tampered")
		} else {
			data[0] ^= 0xff
		}
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), data...))), nil
}

func (f *deployContractFS) Rename(oldPath, newPath string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renames = append(f.renames, [2]string{oldPath, newPath})
	if oldPath == f.tempPath && newPath == f.targetPath {
		f.activationCalls++
		if f.blockActivation {
			select {
			case <-f.activationStarted:
			default:
				close(f.activationStarted)
			}
			release := f.activationRelease
			f.mu.Unlock()
			<-release
			f.mu.Lock()
		}
		if f.failActivation != nil {
			return f.failActivation
		}
	}
	if strings.Contains(path.Base(newPath), ".ssh-mcp-backup-") && f.backupNameExists {
		return os.ErrExist
	}
	if strings.Contains(path.Base(newPath), ".ssh-mcp-backup-") && f.backupRenameErr != nil {
		return f.backupRenameErr
	}
	if _, exists := f.files[newPath]; exists {
		return os.ErrExist
	}
	data, exists := f.files[oldPath]
	if !exists {
		return os.ErrNotExist
	}
	delete(f.files, oldPath)
	f.files[newPath] = append([]byte(nil), data...)
	return nil
}

func (f *deployContractFS) Remove(remotePath string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removedPath = remotePath
	if f.tempPath == remotePath && f.writerCloseCalls == 0 {
		f.removeBeforeWriterClose = true
	}
	delete(f.files, remotePath)
	return nil
}

func (f *deployContractFS) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCalls++
	return nil
}

func (f *deployContractFS) indexOfRename(oldPath, newPath string) int {
	for index, rename := range f.renames {
		if rename[0] == oldPath && (newPath == "" || rename[1] == newPath) {
			return index
		}
	}
	return -1
}

func (f *deployContractFS) indexOfRenamePrefix(prefix, newPath string) int {
	for index, rename := range f.renames {
		if strings.HasPrefix(path.Base(rename[0]), prefix) && rename[1] == newPath {
			return index
		}
	}
	return -1
}

type deployContractWriter struct {
	owner *deployContractFS
	path  string
	data  bytes.Buffer
}

func (w *deployContractWriter) Write(payload []byte) (int, error) {
	w.owner.mu.Lock()
	w.owner.writeCount++
	err := w.owner.writeErr
	w.owner.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return w.data.Write(payload)
}

func (w *deployContractWriter) Close() error {
	w.owner.mu.Lock()
	defer w.owner.mu.Unlock()
	w.owner.writerCloseCalls++
	w.owner.files[w.path] = append([]byte(nil), w.data.Bytes()...)
	return nil
}

type deployContractInfo struct {
	mode    os.FileMode
	size    int64
	modTime time.Time
}

func (i deployContractInfo) Name() string       { return "deploy-source" }
func (i deployContractInfo) Size() int64        { return i.size }
func (i deployContractInfo) Mode() os.FileMode  { return i.mode }
func (i deployContractInfo) ModTime() time.Time { return i.modTime }
func (i deployContractInfo) IsDir() bool        { return i.mode.IsDir() }
func (i deployContractInfo) Sys() interface{}   { return nil }

type malformedDeploymentReader struct{}

func (malformedDeploymentReader) Read([]byte) (int, error) { return deploymentChunkBytes + 1, nil }

type blockingDeploymentReader struct {
	started chan struct{}
	release chan struct{}
}

func newBlockingDeploymentReader() *blockingDeploymentReader {
	return &blockingDeploymentReader{started: make(chan struct{}), release: make(chan struct{})}
}

func (r *blockingDeploymentReader) Read([]byte) (int, error) {
	select {
	case <-r.started:
	default:
		close(r.started)
	}
	<-r.release
	return 0, io.EOF
}
