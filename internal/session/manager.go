package session

import (
	"context"
	"errors"
	"sync"
	"time"

	"ssh-mcp/internal/store"
)

const (
	initialUnlockBackoff = time.Second
	maxUnlockBackoff     = 30 * time.Second
)

var ErrUnlockRateLimited = errors.New("unlock is temporarily rate limited")

type Options struct {
	Now func() time.Time
}

// Manager owns the only decrypted data key for the current daemon process.
// Runtime owns daemon lifetime, so the vault remains unlocked until explicit
// lock or daemon shutdown rather than maintaining a second idle timer.
type Manager struct {
	store *store.Store

	mu       sync.Mutex
	vault    *store.Vault
	now      func() time.Time
	failures int
	retryAt  time.Time
}

func NewManager(credentialStore *store.Store) *Manager {
	return NewManagerWithOptions(credentialStore, Options{})
}

func NewManagerWithOptions(credentialStore *store.Store, options Options) *Manager {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Manager{store: credentialStore, now: now}
}

// Unlock unlocks an existing credential store, or initializes it on the
// first successful use. The created result is true only for initialization.
func (m *Manager) Unlock(ctx context.Context, masterPassword []byte) (created bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.now().Before(m.retryAt) {
		return false, ErrUnlockRateLimited
	}
	previous := m.vault
	m.vault = nil
	if previous != nil {
		previous.Lock()
	}

	vault, err := m.store.Unlock(ctx, masterPassword)
	if errors.Is(err, store.ErrUninitialized) {
		vault, err = m.store.Initialize(ctx, masterPassword)
		created = err == nil
	}
	if err != nil {
		m.recordFailureLocked(err)
		return false, err
	}
	if err := vault.MigrateTargetCredentialOwners(ctx); err != nil {
		vault.Lock()
		return false, err
	}

	m.vault = vault
	m.failures = 0
	m.retryAt = time.Time{}
	return created, nil
}

func (m *Manager) recordFailureLocked(err error) {
	if !errors.Is(err, store.ErrUnlockFailed) {
		return
	}
	m.failures++
	delay := initialUnlockBackoff
	for count := 1; count < m.failures && delay < maxUnlockBackoff; count++ {
		delay *= 2
	}
	if delay > maxUnlockBackoff {
		delay = maxUnlockBackoff
	}
	m.retryAt = m.now().Add(delay)
}

func (m *Manager) IsUnlocked() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.vault != nil
}

func (m *Manager) Vault() (*store.Vault, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.vault == nil {
		return nil, store.ErrLocked
	}
	return m.vault, nil
}

// TouchRemoteActivity remains for the runner interface. Runtime owns the
// daemon-level activity clock, and the default manager has no idle guard.
func (m *Manager) TouchRemoteActivity() {
}

// Lock clears the in-memory DEK. It is safe to call during process shutdown.
func (m *Manager) Lock() {
	m.mu.Lock()
	vault := m.vault
	m.vault = nil
	m.mu.Unlock()

	if vault != nil {
		vault.Lock()
	}
}

func (m *Manager) Close() {
	m.Lock()
}
