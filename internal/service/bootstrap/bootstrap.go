// Package bootstrap seeds the minimum set of rows needed for the publish path
// to answer: an owner, its handle name-claim, its default key set, and
// optionally a first device and public key.
//
// It exists for bring-up — standing up a working instance and proving the slice
// end to end — not as the management API. Creating, renaming, and sharing key
// sets, registering devices, and rotating keys all belong to the authenticated
// management surface; this package deliberately offers one seeding call and one
// key-adding call and nothing else.
//
// It is a service package rather than logic inside the command so that the
// end-to-end test seeds its fixture through exactly the code an operator runs.
// A bootstrap path that only tests exercise is a bootstrap path that breaks.
package bootstrap

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/keys"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// DefaultSetName is the name given to the default key set when none is
// requested. It matches what an operator would guess, and being the default set
// it is also what /{handle} resolves to with no set segment.
const DefaultSetName = "default"

// DefaultDeviceName labels the device that a bootstrapped key is attached to.
// Every public key must belong to a device (the schema enforces it through a
// composite foreign key that also pins the device to the same owner), so
// seeding a key implies seeding a device.
const DefaultDeviceName = "bootstrap"

// Params describes the owner to seed.
type Params struct {
	// Handle is the public name to claim. Required.
	Handle string
	// SetName is the default key set's name; empty means DefaultSetName.
	SetName string
	// DeviceName labels the seeded device; empty means DefaultDeviceName. It is
	// only used when KeyLine is present.
	DeviceName string
	// KeyLine is an optional authorized_keys line to seed. When empty the owner
	// is created with an empty default set, which publishes an empty body.
	KeyLine []byte
	// Now is the timestamp stamped on every seeded row. The caller supplies it
	// because repositories hold no clock.
	Now time.Time
}

// Result reports the identifiers of the seeded rows so an operator (or a test)
// can refer to them afterwards.
type Result struct {
	OwnerID     domain.OwnerID
	HandleID    domain.HandleID
	KeySetID    domain.KeySetID
	DeviceID    domain.DeviceID
	PublicKeyID domain.PublicKeyID
	// Fingerprint is the seeded key's SHA256 fingerprint, or "" when no key was
	// seeded. It is safe to print: a fingerprint of a PUBLIC key is public.
	Fingerprint string
}

// Seed creates the owner, handle, and default key set, plus a device and public
// key when one is supplied.
//
// The whole seed runs in ONE transaction. A partial seed is the dangerous
// outcome: an owner with a claimed handle but no default key set would make
// /{handle} answer 404 forever while the name looks taken to everyone else, and
// no operator would have a way to tell that from a name someone else holds.
func Seed(ctx context.Context, store repository.Store, p Params) (Result, error) {
	if store == nil {
		return Result{}, fmt.Errorf("bootstrap: nil store: %w", domain.ErrInvalidInput)
	}
	if err := domain.ValidateHandle(p.Handle); err != nil {
		return Result{}, fmt.Errorf("bootstrap: handle: %w", err)
	}
	setName := p.SetName
	if setName == "" {
		setName = DefaultSetName
	}
	if err := domain.ValidateSetName(setName); err != nil {
		return Result{}, fmt.Errorf("bootstrap: set name: %w", err)
	}

	// Parse the key BEFORE opening the transaction. Key validation is the step
	// most likely to reject the input, and a bad key should cost nothing and
	// hold no write lock. It also means a rejected key never reaches storage.
	var parsed *keys.ParsedKey
	if len(p.KeyLine) > 0 {
		k, err := keys.Parse(p.KeyLine)
		if err != nil {
			// The error is a package sentinel that reflects no input bytes, so
			// wrapping it cannot echo key material back to the operator.
			return Result{}, fmt.Errorf("bootstrap: parse key: %w", err)
		}
		parsed = &k
	}

	res := Result{
		OwnerID:  domain.OwnerID(newID()),
		HandleID: domain.HandleID(newID()),
		KeySetID: domain.KeySetID(newID()),
	}

	err := store.WithTx(ctx, func(ctx context.Context, r repository.Repos) error {
		if err := r.Owners.Create(ctx, &domain.Owner{
			ID:        res.OwnerID,
			Status:    domain.OwnerStatusActive,
			CreatedAt: p.Now,
			UpdatedAt: p.Now,
		}); err != nil {
			return fmt.Errorf("create owner: %w", err)
		}

		if err := r.Handles.Register(ctx, &domain.Handle{
			ID:        res.HandleID,
			OwnerID:   res.OwnerID,
			Name:      p.Handle,
			State:     domain.NameStateActive,
			CreatedAt: p.Now,
			UpdatedAt: p.Now,
		}); err != nil {
			return fmt.Errorf("register handle: %w", err)
		}

		// Public and default: this is the set /{handle} resolves to, and a
		// bootstrapped instance whose default set were protected would 404 on
		// the one URL the operator just created it to serve.
		if err := r.KeySets.Create(ctx, &domain.KeySet{
			ID:         res.KeySetID,
			OwnerID:    res.OwnerID,
			Name:       setName,
			Visibility: domain.VisibilityPublic,
			IsDefault:  true,
			State:      domain.NameStateActive,
			CreatedAt:  p.Now,
			UpdatedAt:  p.Now,
		}); err != nil {
			return fmt.Errorf("create key set: %w", err)
		}

		if parsed == nil {
			return nil
		}

		deviceName := p.DeviceName
		if deviceName == "" {
			deviceName = DefaultDeviceName
		}
		added, err := AddKey(ctx, r, AddKeyParams{
			OwnerID:    res.OwnerID,
			KeySetID:   res.KeySetID,
			DeviceName: deviceName,
			Key:        *parsed,
			Now:        p.Now,
		})
		if err != nil {
			return err
		}
		res.DeviceID = added.DeviceID
		res.PublicKeyID = added.PublicKeyID
		res.Fingerprint = added.Fingerprint
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("bootstrap: %w", err)
	}
	return res, nil
}

// AddKeyParams describes a key to attach to an existing owner and set.
type AddKeyParams struct {
	OwnerID    domain.OwnerID
	KeySetID   domain.KeySetID
	DeviceName string
	Key        keys.ParsedKey
	Now        time.Time
}

// AddKey creates a device, stores the parsed public key on it, and makes the
// key a member of the given set.
//
// It takes Repos rather than a Store so the caller decides the transaction
// boundary: Seed calls it inside its own transaction, and the store's WithTx
// refuses to nest. All three writes are owner-scoped, and the schema's
// composite (device_id, owner_id) foreign key means the database itself refuses
// to attach a key to another owner's device.
func AddKey(ctx context.Context, r repository.Repos, p AddKeyParams) (Result, error) {
	res := Result{
		OwnerID:     p.OwnerID,
		KeySetID:    p.KeySetID,
		DeviceID:    domain.DeviceID(newID()),
		PublicKeyID: domain.PublicKeyID(newID()),
		Fingerprint: p.Key.Fingerprint,
	}

	if err := r.Devices.Create(ctx, &domain.Device{
		ID:        res.DeviceID,
		OwnerID:   p.OwnerID,
		Name:      p.DeviceName,
		Status:    domain.DeviceStatusActive,
		CreatedAt: p.Now,
		UpdatedAt: p.Now,
	}); err != nil {
		return Result{}, fmt.Errorf("create device: %w", err)
	}

	// The stored fields come from the parser, never from the raw input: Blob is
	// the re-serialized wire form and Comment has already been validated, so
	// what lands in the database is exactly what the publish path can safely
	// reconstruct a line from.
	if err := r.PublicKeys.Create(ctx, &domain.PublicKey{
		ID:          res.PublicKeyID,
		OwnerID:     p.OwnerID,
		DeviceID:    res.DeviceID,
		Algorithm:   p.Key.Algorithm,
		Blob:        p.Key.Blob,
		Comment:     p.Key.Comment,
		Fingerprint: p.Key.Fingerprint,
		BitLen:      p.Key.BitLen,
		Status:      domain.KeyStatusActive,
		CreatedAt:   p.Now,
		UpdatedAt:   p.Now,
	}); err != nil {
		return Result{}, fmt.Errorf("create public key: %w", err)
	}

	if err := r.KeySets.AddMember(ctx, p.OwnerID, p.KeySetID, res.PublicKeyID, p.Now); err != nil {
		return Result{}, fmt.Errorf("add set member: %w", err)
	}
	return res, nil
}

// newID mints an opaque, non-guessable identifier.
//
// crypto/rand.Text yields 26 base32 characters (~130 bits), matching the
// convention already used for request IDs. A CSPRNG rather than a sequence
// matters here: these IDs name owners, keys, and sets, and a guessable or
// enumerable identifier would let an attacker discover how many owners exist
// and address rows it was never given a reference to.
func newID() string {
	return rand.Text()
}
