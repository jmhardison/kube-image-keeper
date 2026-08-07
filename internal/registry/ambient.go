package registry

import (
	"fmt"
	"slices"
	"sync"

	"github.com/enix/kube-image-keeper/internal/config"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/google"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var ambientLog = logf.Log.WithName("ambient-auth")

var (
	// ambientMu guards ambientReady and ambientKeychains. SetupAmbientAuth
	// holds a write lock once at startup; all subsequent reads use a read lock
	// so concurrent registry operations never block each other.
	ambientMu        sync.RWMutex
	ambientReady     bool
	ambientKeychains []authn.Keychain
)

// SetupAmbientAuth builds the ambient keychain chain from cfg. It is
// idempotent: subsequent calls after the first successful setup are no-ops.
// An unknown or misconfigured provider returns an error, which callers should
// treat as fatal (the operator should not start with broken ambient auth).
//
// Note: each keychain object manages its own short-lived token refresh
// internally via its Resolve method. This function only creates the keychain
// objects once; it does not cache tokens.
func SetupAmbientAuth(cfg config.AmbientAuth) error {
	ambientMu.Lock()
	defer ambientMu.Unlock()

	if ambientReady {
		return nil
	}

	if len(cfg.Providers) > 0 {
		ambientLog.Info("enabling ambient auth", "providerCount", len(cfg.Providers))
	}

	keychains := make([]authn.Keychain, 0, len(cfg.Providers))
	for _, p := range cfg.Providers {
		kc, err := buildProvider(p)
		if err != nil {
			return err
		}
		keychains = append(keychains, kc)
		if len(p.Registries) > 0 {
			ambientLog.Info("registered ambient auth provider", "type", p.Type, "registries", p.Registries)
		} else {
			ambientLog.Info("registered ambient auth provider", "type", p.Type)
		}
	}

	ambientKeychains = keychains
	ambientReady = true
	return nil
}

// ResetAmbientAuth clears the ambient keychain state. Only for use in tests.
func ResetAmbientAuth() {
	ambientMu.Lock()
	defer ambientMu.Unlock()
	ambientReady = false
	ambientKeychains = nil
}

// scopedKeychain wraps an inner keychain and gates resolution to a configured
// set of registry hostnames. When the registries list is empty the inner
// keychain is called unconditionally (it handles its own scoping).
type scopedKeychain struct {
	registries []string
	inner      authn.Keychain
}

func (s *scopedKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	if !slices.Contains(s.registries, target.RegistryStr()) {
		return authn.Anonymous, nil
	}
	return s.inner.Resolve(target)
}

// loggingKeychain wraps an inner keychain and emits a V(1) log entry each time
// Resolve is called. It sits inside any scopedKeychain gate so it only fires
// when the registry has already been confirmed as in-scope.
type loggingKeychain struct {
	providerType string
	inner        authn.Keychain
}

func (l *loggingKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	ambientLog.V(1).Info("attempting credential exchange", "provider", l.providerType, "registry", target.RegistryStr())
	return l.inner.Resolve(target)
}

func buildProvider(p config.AmbientProvider) (authn.Keychain, error) {
	var base authn.Keychain
	switch p.Type {
	case "gcp":
		// google.Keychain gates itself via isGoogle() so an explicit registries
		// list is optional; specifying one is still honoured by scopedKeychain.
		base = google.Keychain
	default:
		return nil, fmt.Errorf("unknown ambient auth provider type %q", p.Type)
	}

	// loggingKeychain sits between any scope gate and the real keychain so
	// the log fires only after the registry has been confirmed as in-scope.
	logged := &loggingKeychain{providerType: p.Type, inner: base}

	if len(p.Registries) == 0 {
		return logged, nil
	}
	return &scopedKeychain{registries: p.Registries, inner: logged}, nil
}

// getAmbientKeychains returns the ambient keychain slice for use in
// GetKeychains. The slice is written once at startup and is safe to read
// without copying; callers must not modify it.
func getAmbientKeychains() []authn.Keychain {
	ambientMu.RLock()
	defer ambientMu.RUnlock()
	return ambientKeychains
}
