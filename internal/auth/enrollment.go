package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// MaxApprovalAttempts is how many user codes one owner may submit inside a
// PairingLifetime window before further attempts are refused.
//
// This is the rate limit the user code's 40 bits depend on, and it is the
// difference between "short code" and "guessable code". Without it an
// authenticated attacker could work through the space at whatever rate the
// server answers; with it, the expected number of guesses needed is larger than
// the number allowed by many orders of magnitude, inside a window that closes in
// ten minutes anyway.
//
// Twenty is chosen to be invisible to a person who mistypes a code a few times
// and fatal to anything automated.
const MaxApprovalAttempts = 20

// approvalLimitPrefix domain-separates the approval limiter's keys in a counter
// store shared with the rate limiter and the denylist (ADR-0023). A collision
// between a limiter key and a denylist key is either a revocation that
// disappears or an owner locked out by someone else's traffic.
const approvalLimitPrefix = "vallet.auth.approval.v1"

// Grant is what a caller receives when a pairing is created. Both codes are
// secrets.Redacted, so the struct is safe to print or log; the raw values leave
// only through Reveal, and only where a caller deliberately shows them.
//
// Each code exists in this struct and nowhere else. Neither is stored, and there
// is no second chance to read either: a lost code means starting a new pairing.
type Grant struct {
	// PairingID identifies the pairing. It is not a secret and may be shown or
	// logged; on its own it authenticates nothing.
	PairingID domain.PairingID
	// DeviceCode is the secret the pairing client keeps and later redeems.
	DeviceCode secrets.Redacted
	// UserCode is the short code a person transcribes to approve the pairing.
	// It is empty for a manually minted pairing, which is approved at creation.
	UserCode secrets.Redacted
	// ExpiresAt is when the pairing dies, approved or not.
	ExpiresAt time.Time
	// PollInterval is the minimum gap the client must leave between polls. It
	// is enforced server-side, not merely advertised.
	PollInterval time.Duration
}

// redacted is the single rendering used by every formatting path on Grant, so a
// new path cannot be added without redaction.
func (g Grant) redacted() string {
	return fmt.Sprintf("auth.Grant{PairingID:%s, DeviceCode:[REDACTED], UserCode:[REDACTED]}", g.PairingID)
}

// String implements fmt.Stringer.
func (g Grant) String() string { return g.redacted() }

// GoString implements fmt.GoStringer so %#v also redacts.
func (g Grant) GoString() string { return g.redacted() }

// Format implements fmt.Formatter. It takes precedence over String and GoString
// for every verb, which catches the realistic leak path: a Grant printed as part
// of a surrounding value with %v or %+v.
func (g Grant) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(g.redacted())) }

// MarshalJSON implements json.Marshaler, emitting a quoted redacted string so
// the output stays valid JSON. A handler that must return the codes builds its
// own response type and Reveals deliberately.
func (g Grant) MarshalJSON() ([]byte, error) { return []byte(`"` + g.redacted() + `"`), nil }

// MarshalText implements encoding.TextMarshaler.
func (g Grant) MarshalText() ([]byte, error) { return []byte(g.redacted()), nil }

// LogValue implements slog.LogValuer, which slog resolves before MarshalText or
// MarshalJSON and which a custom handler would otherwise bypass.
func (g Grant) LogValue() slog.Value { return slog.StringValue(g.redacted()) }

// EnrollmentService runs the two enrollment flows ADR-0018 asks for: the
// device-authorization grant, where a client shows codes and an owner approves
// from an authenticated session, and the manual paste, where an owner mints a
// pairing token directly.
//
// # Where the owner boundary is
//
// A pairing is bound to an owner exactly once, by an approval, and the binding
// is a conditional write that only applies to a pending row. Everything after
// that reads the owner from the row. No method takes an owner id from the party
// presenting a device code, so a client cannot name the account it pairs into,
// and a second approval cannot re-point a pairing another owner already claimed.
//
// # Audit
//
// Enrollment, pairing approval and revocation are all audited events under
// ADR-0007. The audit sink is not on this branch yet, so no dependency is taken
// on it and nothing is emitted. The three call sites where records belong are
// marked "AUDIT:" below, each at the point where the durable state change has
// already committed -- which is where an audit record has to be written to be
// worth anything, since a record emitted before the write can describe something
// that never happened.
//
// An EnrollmentService is immutable after construction and safe for concurrent
// use.
type EnrollmentService struct {
	store    repository.Store
	auth     *Authenticator
	tokens   *TokenService
	denylist *Denylist
	limiter  counter.Store
	now      func() time.Time
}

// NewEnrollmentService builds an EnrollmentService.
//
// Every dependency is required. A nil one is a wiring bug, and tolerating it
// would produce a service that silently skips whichever check the missing
// dependency performed: no limiter means an unbounded guessing budget against a
// 40-bit user code, and no denylist means a revoked device keeps its live access
// tokens for another fifteen minutes. Failing at startup is the only safe
// response to either.
func NewEnrollmentService(store repository.Store, a *Authenticator, tokens *TokenService, denylist *Denylist, limiter counter.Store, now func() time.Time) (*EnrollmentService, error) {
	switch {
	case store == nil:
		return nil, fmt.Errorf("auth: nil store: %w", domain.ErrInvalidInput)
	case a == nil:
		return nil, fmt.Errorf("auth: nil authenticator: %w", domain.ErrInvalidInput)
	case tokens == nil:
		return nil, fmt.Errorf("auth: nil token service: %w", domain.ErrInvalidInput)
	case denylist == nil:
		return nil, fmt.Errorf("auth: nil denylist: %w", domain.ErrInvalidInput)
	case limiter == nil:
		return nil, fmt.Errorf("auth: nil counter store: %w", domain.ErrInvalidInput)
	case now == nil:
		return nil, fmt.Errorf("auth: nil clock: %w", domain.ErrInvalidInput)
	}
	return &EnrollmentService{store: store, auth: a, tokens: tokens, denylist: denylist, limiter: limiter, now: now}, nil
}

// StartDeviceGrant creates a pending pairing and returns both codes.
//
// It takes no owner, and that is the shape of the flow rather than an
// oversight: the client starting a device grant has not authenticated as
// anybody. The scopes it asks for are a request, not a decision -- the pairing
// is unusable until an owner approves it, and approval is where the owner sees
// what is being asked for and consents to it.
//
// Errors are wrapped and descriptive. The caller here is server code building a
// grant on behalf of an unauthenticated but not-yet-suspect client, and nothing
// on this path reveals whether any credential exists.
func (s *EnrollmentService) StartDeviceGrant(ctx context.Context, clientLabel string, scopes []domain.Scope) (*Grant, error) {
	if err := ValidateScopes(scopes); err != nil {
		return nil, err
	}
	if err := validateClientLabel(clientLabel); err != nil {
		return nil, err
	}
	// The canonical form is what is hashed, so the digest stored is the one a
	// transcribed code produces. Hashing the grouped display form instead would
	// make every approval fail.
	userCode, canonical := newUserCode()
	return s.create(ctx, &domain.DevicePairing{
		UserCodeHash: hashUserCode(canonical),
		Scopes:       cloneScopes(scopes),
		ClientLabel:  clientLabel,
		Status:       domain.PairingStatusPending,
	}, userCode)
}

// Mint creates a pairing that is already approved and bound to ownerID, and
// returns its device code. This is ADR-0018's manual paste: the owner minting
// it is authenticated, so the act of minting IS the approval and there is
// nothing for a user code to authorize.
//
// ownerID is trusted here because the caller has already resolved it; no
// credential is verified on this path.
func (s *EnrollmentService) Mint(ctx context.Context, ownerID domain.OwnerID, clientLabel string, scopes []domain.Scope) (*Grant, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("auth: owner id must not be empty: %w", domain.ErrInvalidInput)
	}
	if err := ValidateScopes(scopes); err != nil {
		return nil, err
	}
	if err := validateClientLabel(clientLabel); err != nil {
		return nil, err
	}
	approved := s.now()
	pairing := &domain.DevicePairing{
		OwnerID: ownerID,
		// No user code: there is no second party to authorize this, so there is
		// nothing to transcribe and no short secret to defend.
		UserCodeHash: nil,
		Scopes:       cloneScopes(scopes),
		ClientLabel:  clientLabel,
		Status:       domain.PairingStatusApproved,
		ApprovedAt:   &approved,
	}
	grant, err := s.create(ctx, pairing, "")
	if err != nil {
		return nil, err
	}
	// The link is created here for the same reason Approve creates one: it is
	// the explicit, owner-authorized act that makes the pairing's principal
	// resolvable to an owner. Without it the device code would verify and then
	// resolve to nobody.
	if err := s.link(ctx, pairing.ID, ownerID, approved); err != nil {
		return nil, err
	}
	// AUDIT: credential minted -- owner, pairing id, label, scopes. The pairing
	// and its link are both committed at this point.
	return grant, nil
}

// create fills in the identifiers, timestamps and digests a repository is
// forbidden to generate, writes the row, and returns the codes.
func (s *EnrollmentService) create(ctx context.Context, pairing *domain.DevicePairing, userCode secrets.Redacted) (*Grant, error) {
	now := s.now()
	secret := newDeviceSecret()
	pairing.ID = newPairingID()
	pairing.DeviceCodeHash = hashDeviceSecret(secret)
	pairing.CreatedAt = now
	pairing.ExpiresAt = now.Add(PairingLifetime)
	// A client may poll immediately; the interval applies between polls.
	pairing.NextPollAt = now

	if err := s.store.Repos().DevicePairings.Create(ctx, pairing); err != nil {
		return nil, fmt.Errorf("auth: creating device pairing: %w", err)
	}
	return &Grant{
		PairingID:    pairing.ID,
		DeviceCode:   formatDeviceCode(pairing.ID, secret),
		UserCode:     userCode,
		ExpiresAt:    pairing.ExpiresAt,
		PollInterval: PairingPollInterval,
	}, nil
}

// Approve binds a pending pairing to ownerID, on the strength of a user code
// the owner transcribed from the pairing client's screen.
//
// ownerID is the already-authenticated owner running this call. It is the owner
// the pairing becomes bound to, so an owner can only ever pair a device into
// their own account.
//
// # Every denial is the same
//
// An unknown code, an expired pairing, an already-approved one and an exhausted
// attempt budget all return bare ErrAuthFailed. That is what stops this method
// from being an oracle: an attacker guessing user codes must not be able to
// tell "no such code" from "that code exists but is already used", because the
// second answer confirms a guess.
func (s *EnrollmentService) Approve(ctx context.Context, ownerID domain.OwnerID, userCode string) error {
	if ownerID == "" {
		return ErrAuthFailed
	}
	now := s.now()

	// The limiter runs before the lookup, not after. Checking it afterwards
	// would still answer the attacker's question on the way through, and would
	// let a caller drive an unbounded number of store reads.
	if err := s.checkApprovalLimit(ctx, ownerID); err != nil {
		return err
	}

	code, err := normalizeUserCode(userCode)
	if err != nil {
		return ErrAuthFailed
	}
	pairing, err := s.store.Repos().DevicePairings.GetByUserCodeHash(ctx, hashUserCode(code))
	if err != nil || pairing == nil {
		// A storage fault denies too. This path binds an owner to a device, so
		// there is no tolerable way to fail other than closed.
		return ErrAuthFailed
	}
	if pairing.Status != domain.PairingStatusPending {
		return ErrAuthFailed
	}
	if !now.Before(pairing.ExpiresAt) {
		return ErrAuthFailed
	}

	// The conditional transition. It applies only to a pending row, so two
	// owners racing to approve one pairing resolve to exactly one winner and the
	// loser is refused -- rather than the second silently rewriting OwnerID and
	// handing the device to a different account.
	if err := s.store.Repos().DevicePairings.Approve(ctx, pairing.ID, ownerID, now); err != nil {
		return ErrAuthFailed
	}
	if err := s.link(ctx, pairing.ID, ownerID, now); err != nil {
		return ErrAuthFailed
	}
	// AUDIT: pairing approved -- owner, pairing id, scopes. Both writes have
	// committed, so the record describes something that actually happened.
	return nil
}

// link records the LinkedIdentity that makes a pairing's principal resolvable
// to an owner.
//
// This is the "explicit, separately authorized act" the package documentation
// requires: there is no implicit linking anywhere, because an implicit link is
// an account takeover primitive. The only two callers are Mint and Approve, and
// in both the owner has authenticated and consented.
func (s *EnrollmentService) link(ctx context.Context, id domain.PairingID, ownerID domain.OwnerID, now time.Time) error {
	err := s.store.Repos().LinkedIdentities.Create(ctx, &domain.LinkedIdentity{
		ID:      domain.LinkedIdentityID(id),
		OwnerID: ownerID,
		// The provider half comes from the provider's own constant, never from
		// caller input, so a link cannot be filed under another provider's
		// namespace.
		Provider:  APITokenProviderID.String(),
		Subject:   string(id),
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		return fmt.Errorf("auth: linking pairing identity: %w", err)
	}
	return nil
}

// checkApprovalLimit counts one approval attempt against ownerID's budget and
// refuses once it is spent.
//
// It fails closed: if the counter store cannot answer, the attempt is denied.
// A limiter that failed open would stop limiting exactly when an attacker who
// could disturb the store would want it to, and the cost of failing closed here
// is that an owner cannot pair a new device during an outage -- an availability
// problem, not a security one.
//
// The key is a digest, so a dump of a shared counter store does not enumerate
// which owners have been pairing devices.
func (s *EnrollmentService) checkApprovalLimit(ctx context.Context, ownerID domain.OwnerID) error {
	sum := sha256.Sum256([]byte(approvalLimitPrefix + "\x00" + string(ownerID)))
	got, err := s.limiter.Increment(ctx, tokenEncoding.EncodeToString(sum[:]), 1, PairingLifetime)
	if err != nil {
		return ErrAuthFailed
	}
	if got.Value > MaxApprovalAttempts {
		return ErrAuthFailed
	}
	return nil
}

// Redeem exchanges an approved pairing's device code for the client's first
// credential pair, and consumes the pairing.
//
// # Why this is not one transaction
//
// The device code is authenticated, then a lineage is issued, then the pairing
// is consumed by a conditional write. Those are separate steps, and the
// conditional write is what makes the whole sequence single-use: whichever
// caller wins it is the only one whose tokens are returned, and a loser's
// just-issued lineage is revoked before this returns. A device grant is
// restart-friendly -- a client that gets nothing simply pairs again -- so the
// worst outcome of a crash in the middle is a burned pairing, which is the safe
// direction to fail.
//
// Every denial returns bare ErrAuthFailed.
func (s *EnrollmentService) Redeem(ctx context.Context, deviceCode secrets.Redacted) (*Issued, error) {
	// The id is parsed locally as well as by the provider, because the
	// Authenticator returns only an owner and the pairing has to be consumed by
	// id. Parsing cannot succeed here and fail there: it is the same function.
	id, _, err := parseDeviceCode(deviceCode)
	if err != nil {
		return nil, ErrAuthFailed
	}

	// Authentication runs through the Authenticator, not the provider directly.
	// That is what applies the provider-id check, the link lookup and the owner
	// status check; calling the provider straight would authenticate a device
	// code against a suspended or deleted account.
	ownerID, err := s.auth.Authenticate(ctx, APITokenProviderID, Credential{Secret: deviceCode})
	if err != nil {
		return nil, ErrAuthFailed
	}

	// Cross-owner defense in depth. The owner just resolved comes from the
	// LinkedIdentity row; the pairing row carries its own copy, written by the
	// approval. They are set by the same call and must agree, so a disagreement
	// means one of the two was tampered with or a lookup returned a neighbor --
	// and pairing a device into an account that did not approve it is exactly
	// the outcome worth spending a second read to prevent.
	pairing, err := s.store.Repos().DevicePairings.Get(ctx, ownerID, id)
	if err != nil || pairing == nil || pairing.ID != id || pairing.OwnerID != ownerID {
		return nil, ErrAuthFailed
	}
	if err := ValidateScopes(pairing.Scopes); err != nil {
		// A stored scope set that no longer validates is refused rather than
		// carried into a credential. Mint and StartDeviceGrant both validated
		// it, so this means the row was written by something else.
		return nil, ErrAuthFailed
	}

	now := s.now()
	issued, err := s.tokens.Issue(ctx, ownerID, pairing.Scopes, pairing.ClientLabel, now)
	if err != nil {
		return nil, ErrAuthFailed
	}

	// The conditional consume. It applies only to an approved row owned by
	// ownerID, so of N concurrent redemptions of one device code exactly one
	// commits. Any other has already minted a lineage, which is revoked below
	// rather than left live: two credentials from one pairing is precisely the
	// state single-use exists to make impossible, and the owner would only ever
	// see one of them.
	lineage := issued.LineageID
	if err := s.store.Repos().DevicePairings.MarkRedeemed(ctx, ownerID, id, lineage, now); err != nil {
		s.revokeLineage(ctx, ownerID, lineage, now)
		return nil, ErrAuthFailed
	}
	// AUDIT: pairing redeemed -- owner, pairing id, lineage, scopes.
	return issued, nil
}

// Revoke withdraws the owner's pairing and kills the credentials it issued.
//
// The order is deliberate. The durable revocations happen first and the
// denylist write last, because the denylist is a fifteen-minute cache in front
// of the authoritative rows: a listing without the rows revoked would expire and
// silently un-revoke, while rows revoked without a listing merely means the
// already-issued access tokens live out their remaining minutes, which is the
// pre-denylist behavior.
//
// Errors are wrapped and descriptive: the caller is the owner's own
// authenticated session acting on their own resource, so domain.ErrNotFound --
// which covers both "no such pairing" and "another owner's pairing" -- is the
// right and safe answer.
func (s *EnrollmentService) Revoke(ctx context.Context, ownerID domain.OwnerID, id domain.PairingID) error {
	if ownerID == "" || id == "" {
		return fmt.Errorf("auth: owner id and pairing id are required: %w", domain.ErrInvalidInput)
	}
	now := s.now()
	pairing, err := s.store.Repos().DevicePairings.Get(ctx, ownerID, id)
	if err != nil {
		return fmt.Errorf("auth: reading device pairing: %w", err)
	}
	if pairing == nil || pairing.OwnerID != ownerID {
		// A nil row on a nil error, or a row for someone else, is reported as
		// absent. Distinguishing them would leak that another owner holds this
		// pairing id.
		return fmt.Errorf("auth: device pairing: %w", domain.ErrNotFound)
	}
	if err := s.store.Repos().DevicePairings.Revoke(ctx, ownerID, id, now); err != nil {
		return fmt.Errorf("auth: revoking device pairing: %w", err)
	}
	// A pairing that was never redeemed has no lineage, and revoking the row is
	// the whole job: the device code can no longer authenticate.
	if pairing.LineageID != "" {
		s.revokeLineage(ctx, ownerID, pairing.LineageID, now)
	}
	// AUDIT: pairing revoked -- owner, pairing id, lineage.
	return nil
}

// revokeLineage kills every credential in a lineage and lists the still-live
// ones on the denylist, so that access tokens already in circulation stop being
// accepted within DenylistSkew instead of after their full lifetime.
//
// It reports nothing. Both callers are already committed to their outcome: one
// is denying regardless, and the other has revoked the pairing row durably. A
// failure here costs at most the fifteen minutes the denylist exists to save,
// and it is logged so an operator knows immediate revocation degraded to TTL
// expiry.
func (s *EnrollmentService) revokeLineage(ctx context.Context, ownerID domain.OwnerID, lineage domain.LineageID, now time.Time) {
	creds := s.store.Repos().RefreshCredentials
	if _, err := creds.RevokeLineage(ctx, ownerID, lineage, now); err != nil {
		s.logDegraded(ctx, "revoking the credential lineage of a device pairing", err)
		return
	}
	rows, err := creds.ListByLineage(ctx, ownerID, lineage)
	if err != nil {
		s.logDegraded(ctx, "reading back a revoked lineage to list it on the denylist", err)
		return
	}
	if err := s.denylist.RevokeLineage(ctx, rows, now); err != nil {
		s.logDegraded(ctx, "listing a revoked lineage on the denylist", err)
	}
}

// logDegraded records that immediate revocation degraded to TTL expiry, without
// naming the owner, the pairing or the credentials. Those are lookup keys
// rather than secrets, but a log line naming them is a record of who was
// compromised and when, and the operator only needs to know that the fast path
// failed.
func (s *EnrollmentService) logDegraded(ctx context.Context, what string, err error) {
	slog.ErrorContext(ctx, "auth: "+what+" failed; affected access tokens stay valid until they expire",
		slog.String("error", err.Error()))
}

// errPollPending is returned by Poll for a pairing nobody has approved yet.
//
// It is the one place this package distinguishes a denial, and the exception is
// narrow and earned: Poll answers only a caller that has already presented the
// pairing's own 256-bit device code, so it tells that caller nothing it did not
// already know, and a device-authorization client cannot function without being
// able to tell "keep waiting" from "give up". Nothing that consumes a user code
// or resolves an owner distinguishes anything.
var errPollPending = errors.New("auth: pairing not yet approved")

// Poll reports whether a pairing is ready to redeem, and enforces the interval
// between polls.
//
// A caller that polls too soon is refused and its next permitted time is pushed
// out again, so a client with a retry loop and no backoff slows itself down
// instead of hammering the store. The throttle is applied only after the device
// code has been verified, so an unauthenticated caller cannot use this to write
// to the pairing store at all.
func (s *EnrollmentService) Poll(ctx context.Context, deviceCode secrets.Redacted) error {
	id, secret, err := parseDeviceCode(deviceCode)
	if err != nil {
		return ErrAuthFailed
	}
	pairings := s.store.Repos().DevicePairings
	pairing, err := pairings.GetByID(ctx, id)
	if err != nil || pairing == nil || pairing.ID != id {
		return ErrAuthFailed
	}
	// Constant-time, and before anything else is acted on or written, exactly as
	// in the provider.
	if !deviceSecretMatches(pairing.DeviceCodeHash, secret) {
		return ErrAuthFailed
	}
	now := s.now()
	if !now.Before(pairing.ExpiresAt) {
		return ErrAuthFailed
	}
	if now.Before(pairing.NextPollAt) {
		// Too soon. The interval is pushed out from now rather than from the
		// previous deadline, so repeated early polls keep extending it.
		_ = pairings.Touch(ctx, id, now.Add(PairingPollInterval))
		return ErrAuthFailed
	}
	if err := pairings.Touch(ctx, id, now.Add(PairingPollInterval)); err != nil {
		return ErrAuthFailed
	}
	if pairing.Status == domain.PairingStatusApproved {
		return nil
	}
	if pairing.Status == domain.PairingStatusPending {
		return errPollPending
	}
	// Redeemed or revoked: terminal, and not something to keep polling.
	return ErrAuthFailed
}

// PollPending reports whether err from Poll means "no owner has approved this
// pairing yet, keep waiting". Every other non-nil error means stop.
func PollPending(err error) bool { return errors.Is(err, errPollPending) }
