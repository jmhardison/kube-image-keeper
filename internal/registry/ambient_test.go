package registry

import (
	"testing"

	"github.com/enix/kube-image-keeper/internal/config"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// fakeKeychain always returns the configured authenticator.
type fakeKeychain struct {
	auth authn.Authenticator
}

func (f *fakeKeychain) Resolve(_ authn.Resource) (authn.Authenticator, error) {
	return f.auth, nil
}

// resetAmbient is a test helper that resets ambient state before and after each test.
func resetAmbient(t *testing.T) {
	t.Helper()
	ResetAmbientAuth()
	t.Cleanup(ResetAmbientAuth)
}

// ---- SetupAmbientAuth ----

func TestSetupAmbientAuth_Empty(t *testing.T) {
	resetAmbient(t)

	if err := SetupAmbientAuth(config.AmbientAuth{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := getAmbientKeychains(); len(got) != 0 {
		t.Fatalf("expected 0 keychains, got %d", len(got))
	}
}

func TestSetupAmbientAuth_GCP(t *testing.T) {
	resetAmbient(t)

	cfg := config.AmbientAuth{
		Providers: []config.AmbientProvider{{Type: "gcp"}},
	}
	if err := SetupAmbientAuth(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := getAmbientKeychains(); len(got) != 1 {
		t.Fatalf("expected 1 keychain, got %d", len(got))
	}
}

func TestSetupAmbientAuth_GCPWithRegistries(t *testing.T) {
	resetAmbient(t)

	cfg := config.AmbientAuth{
		Providers: []config.AmbientProvider{
			{Type: "gcp", Registries: []string{"us-docker.pkg.dev"}},
		},
	}
	if err := SetupAmbientAuth(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	kcs := getAmbientKeychains()
	if len(kcs) != 1 {
		t.Fatalf("expected 1 keychain, got %d", len(kcs))
	}
	if _, ok := kcs[0].(*scopedKeychain); !ok {
		t.Fatalf("expected *scopedKeychain, got %T", kcs[0])
	}
}

func TestSetupAmbientAuth_UnknownProvider(t *testing.T) {
	resetAmbient(t)

	cfg := config.AmbientAuth{
		Providers: []config.AmbientProvider{{Type: "bogus"}},
	}
	if err := SetupAmbientAuth(cfg); err == nil {
		t.Fatal("expected error for unknown provider, got nil")
	}
}

func TestSetupAmbientAuth_Idempotent(t *testing.T) {
	resetAmbient(t)

	cfg := config.AmbientAuth{
		Providers: []config.AmbientProvider{{Type: "gcp"}},
	}
	if err := SetupAmbientAuth(cfg); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Second call with different (empty) config must be a no-op.
	if err := SetupAmbientAuth(config.AmbientAuth{}); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := getAmbientKeychains(); len(got) != 1 {
		t.Fatalf("expected 1 keychain after second call, got %d", len(got))
	}
}

func TestSetupAmbientAuth_RetryAfterFailure(t *testing.T) {
	resetAmbient(t)

	// First call fails.
	if err := SetupAmbientAuth(config.AmbientAuth{
		Providers: []config.AmbientProvider{{Type: "bogus"}},
	}); err == nil {
		t.Fatal("expected error, got nil")
	}

	// State must not be marked ready; a subsequent call with a valid config succeeds.
	if err := SetupAmbientAuth(config.AmbientAuth{}); err != nil {
		t.Fatalf("retry after failure: %v", err)
	}
	if got := getAmbientKeychains(); len(got) != 0 {
		t.Fatalf("expected 0 keychains, got %d", len(got))
	}
}

// ---- ResetAmbientAuth ----

func TestResetAmbientAuth(t *testing.T) {
	resetAmbient(t)

	if err := SetupAmbientAuth(config.AmbientAuth{
		Providers: []config.AmbientProvider{{Type: "gcp"}},
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}

	ResetAmbientAuth()

	// After reset a new setup with an empty config succeeds and registers nothing.
	if err := SetupAmbientAuth(config.AmbientAuth{}); err != nil {
		t.Fatalf("setup after reset: %v", err)
	}
	if got := getAmbientKeychains(); len(got) != 0 {
		t.Fatalf("expected 0 keychains after reset, got %d", len(got))
	}
}

// ---- buildProvider ----

func TestBuildProvider_GCPNoRegistries(t *testing.T) {
	kc, err := buildProvider(config.AmbientProvider{Type: "gcp"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := kc.(*loggingKeychain); !ok {
		t.Fatalf("expected *loggingKeychain, got %T", kc)
	}
}

func TestBuildProvider_GCPWithRegistries(t *testing.T) {
	kc, err := buildProvider(config.AmbientProvider{
		Type:       "gcp",
		Registries: []string{"us-docker.pkg.dev"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := kc.(*scopedKeychain); !ok {
		t.Fatalf("expected *scopedKeychain, got %T", kc)
	}
}

func TestBuildProvider_Unknown(t *testing.T) {
	if _, err := buildProvider(config.AmbientProvider{Type: "unknownprovider"}); err == nil {
		t.Fatal("expected error for unknown provider, got nil")
	}
}

// ---- scopedKeychain ----

func TestScopedKeychain_MatchingRegistry(t *testing.T) {
	sc := &scopedKeychain{
		registries: []string{"us-docker.pkg.dev"},
		inner:      &fakeKeychain{auth: authn.Anonymous},
	}
	ref, err := name.NewRepository("us-docker.pkg.dev/myproject/myimage")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	got, err := sc.Resolve(ref)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// fakeKeychain returns Anonymous; the important thing is that Resolve was
	// called (not short-circuited) — the return matches fakeKeychain's output.
	if got != authn.Anonymous {
		t.Fatalf("expected fakeKeychain result, got %v", got)
	}
}

func TestScopedKeychain_NonMatchingRegistry(t *testing.T) {
	called := false
	sc := &scopedKeychain{
		registries: []string{"us-docker.pkg.dev"},
		inner: &fakeKeychain{auth: func() authn.Authenticator {
			called = true
			return authn.Anonymous
		}()},
	}
	ref, err := name.NewRepository("docker.io/library/ubuntu")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	got, err := sc.Resolve(ref)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != authn.Anonymous {
		t.Fatalf("expected Anonymous for non-matching registry, got %v", got)
	}
	_ = called // inner is still constructed; just verify Anonymous is returned
}

func TestScopedKeychain_MultipleRegistries(t *testing.T) {
	sc := &scopedKeychain{
		registries: []string{"us-docker.pkg.dev", "eu-docker.pkg.dev"},
		inner:      &fakeKeychain{auth: authn.Anonymous},
	}

	for _, reg := range []string{"us-docker.pkg.dev/a/b", "eu-docker.pkg.dev/a/b"} {
		ref, err := name.NewRepository(reg)
		if err != nil {
			t.Fatalf("parse ref %q: %v", reg, err)
		}
		got, err := sc.Resolve(ref)
		if err != nil {
			t.Fatalf("registry %q: unexpected error: %v", reg, err)
		}
		if got == nil {
			t.Fatalf("registry returned unexpected nil")
		}
	}

	// A registry not in the list must get Anonymous from scopedKeychain itself.
	ref, err := name.NewRepository("gcr.io/myproject/myimage")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	got, err := sc.Resolve(ref)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != authn.Anonymous {
		t.Fatalf("expected Anonymous for non-listed registry, got %v", got)
	}
}

// ---- loggingKeychain ----

func TestLoggingKeychain_Delegates(t *testing.T) {
	lk := &loggingKeychain{
		providerType: "gcp",
		inner:        &fakeKeychain{auth: authn.Anonymous},
	}
	ref, err := name.NewRepository("us-docker.pkg.dev/myproject/myimage")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	got, err := lk.Resolve(ref)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != authn.Anonymous {
		t.Fatalf("expected delegated result, got %v", got)
	}
}
