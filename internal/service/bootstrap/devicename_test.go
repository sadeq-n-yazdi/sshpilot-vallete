package bootstrap_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/keys"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/bootstrap"
)

// tripwireDevices fails the test if a device row is ever written. AddKey's
// guard runs before the first write, so a refused name must never get here.
type tripwireDevices struct {
	repository.DeviceRepository
	t *testing.T
}

func (d *tripwireDevices) Create(context.Context, *domain.Device) error {
	d.t.Helper()
	d.t.Fatal("Devices.Create called: a refused device name reached storage")
	return nil
}

// addKeyErr calls AddKey with a device name and returns only the error. The
// repos are tripwires: any write at all fails the test.
func addKeyErr(t *testing.T, name string, guard *nameguard.Guard) error {
	t.Helper()
	_, err := bootstrap.AddKey(context.Background(), repository.Repos{
		Devices: &tripwireDevices{t: t},
	}, bootstrap.AddKeyParams{
		OwnerID:    "owner-a",
		KeySetID:   "set-a",
		DeviceName: name,
		Key:        keys.ParsedKey{},
		Now:        seedNow,
		Guard:      guard,
	})
	return err
}

// TestAddKeyRefusesBlockedDeviceNames covers the CLI device-create path.
//
// AddKey is exported and callable independently of Seed, which is why the check
// sits at the write rather than in Seed: a guard placed only in Seed would be a
// control this caller walks straight past. The leetspeak and homoglyph cases are
// what distinguish enforcement on the normalized skeleton from raw comparison.
func TestAddKeyRefusesBlockedDeviceNames(t *testing.T) {
	t.Parallel()

	for label, name := range map[string]string{
		"exact curated term": "root",
		"leetspeak evasion":  "r00t",
		"cyrillic homoglyph": "аdmin",
	} {
		t.Run(label, func(t *testing.T) {
			t.Parallel()

			if err := addKeyErr(t, name, mustGuard(t)); !errors.Is(err, domain.ErrBlockedName) {
				t.Fatalf("AddKey(device=%q) = %v, want ErrBlockedName", name, err)
			}
		})
	}
}

// TestAddKeyRefusesWithoutAGuard proves the dependency fails closed. A caller
// that forgets the Guard field gets a refused AddKey, not an unchecked device
// name -- the nil Guard refuses rather than no-opping.
func TestAddKeyRefusesWithoutAGuard(t *testing.T) {
	t.Parallel()

	if err := addKeyErr(t, "laptop", nil); !errors.Is(err, domain.ErrBlockedName) {
		t.Fatalf("AddKey with nil Guard = %v, want ErrBlockedName", err)
	}
}

// TestAddKeyRefusalDoesNotNameTheMatchedTerm mirrors the device service: the
// CLI refusal is subject to the same no-oracle rule as the API one.
func TestAddKeyRefusalDoesNotNameTheMatchedTerm(t *testing.T) {
	t.Parallel()

	err := addKeyErr(t, "r00t", mustGuard(t))
	if !errors.Is(err, domain.ErrBlockedName) {
		t.Fatalf("AddKey = %v, want ErrBlockedName", err)
	}
	for _, leak := range []string{"root", "routing", "impersonation", "offensive"} {
		if strings.Contains(strings.ToLower(err.Error()), leak) {
			t.Errorf("error %q leaks %q", err, leak)
		}
	}
}

// TestDefaultDeviceNameIsNotBlocked pins the assumption that lets AddKey check
// the device name unconditionally.
//
// DefaultSetName ("default") needs a carve-out in Seed because it is itself a
// curated routing term, and checking the system's own fallback would fail every
// bootstrap. DefaultDeviceName ("bootstrap") needs no such carve-out only
// because it happens to be on no list -- which is a property of the curated
// data, not of the code. The lists are operator-curated and versioned, so if an
// edit ever adds "bootstrap", every bootstrap that omits -device would start
// failing on a name no user chose. This test turns that from a latent outage
// into a failing build.
func TestDefaultDeviceNameIsNotBlocked(t *testing.T) {
	t.Parallel()

	err := mustGuard(t).Check(nameguard.KindDeviceName, nameguard.OpCreate, bootstrap.DefaultDeviceName)
	if err != nil {
		t.Fatalf("DefaultDeviceName %q is blocked: %v\n"+
			"AddKey checks it unconditionally, so this breaks every bootstrap that omits -device. "+
			"Either drop the term from the curated list or give the fallback a carve-out in AddKey.",
			bootstrap.DefaultDeviceName, err)
	}
}

// recordingDevices captures the device row AddKey writes.
type recordingDevices struct {
	repository.DeviceRepository
	created *domain.Device
}

func (d *recordingDevices) Create(_ context.Context, dev *domain.Device) error {
	d.created = dev
	return nil
}

// errStop halts AddKey at the write AFTER the device row, so the test observes
// the device the guard admitted without having to satisfy the rest of the
// call's dependencies. It is a control-flow stub, not an assertion.
var errStop = errors.New("stop after the device write")

type stoppingKeys struct {
	repository.PublicKeyRepository
}

func (stoppingKeys) Create(context.Context, *domain.PublicKey) error { return errStop }

// TestAddKeyAcceptsOrdinaryDeviceNames keeps the check from being a control
// that refuses everything, which would satisfy every test above.
//
// It asserts the name reached the write, not merely that AddKey returned no
// error from the guard: the point of an accepted name is that it is persisted
// unchanged, and a check that quietly rewrote or dropped it would pass a
// nil-error assertion.
func TestAddKeyAcceptsOrdinaryDeviceNames(t *testing.T) {
	t.Parallel()

	for _, name := range []string{bootstrap.DefaultDeviceName, "laptop", "büro-pc"} {
		devices := &recordingDevices{}
		// AddKey writes a device, then a key, then a membership. The key write
		// is stubbed to stop the call right after the device row this test is
		// about has been recorded, so the guard verdict is observable through
		// devices.created without standing up the rest of the graph.
		_, err := bootstrap.AddKey(context.Background(),
			repository.Repos{Devices: devices, PublicKeys: stoppingKeys{}},
			bootstrap.AddKeyParams{
				OwnerID: "owner-a", KeySetID: "set-a", DeviceName: name,
				Key: keys.ParsedKey{}, Now: seedNow, Guard: mustGuard(t),
			})
		// The stub's error is the expected outcome; a DIFFERENT error would
		// mean the call stopped somewhere this test did not intend.
		if !errors.Is(err, errStop) {
			t.Errorf("AddKey(device=%q) = %v, want the stub's errStop", name, err)
		}
		if devices.created == nil {
			t.Errorf("device name %q was refused; it must be accepted", name)
			continue
		}
		if devices.created.Name != name {
			t.Errorf("persisted device name = %q, want %q", devices.created.Name, name)
		}
	}
}
