package migrate

import (
	"fmt"
	"regexp"
)

// idPattern matches a valid migration ID: exactly four decimal digits.
var idPattern = regexp.MustCompile(`^\d{4}$`)

// Registry is an immutable, ordered set of migrations validated at
// construction. Once built it never changes, so verification and application
// can trust its invariants: IDs are well-formed, unique, and strictly
// ascending; dependencies refer to strictly earlier migrations; and every
// migration is complete for both engines.
type Registry struct {
	ordered []Migration
	byID    map[string]Migration
}

// NewRegistry validates ms and returns an immutable Registry, or an error
// wrapping [ErrInvalidRegistry] if any migration is malformed. It fails closed:
// a bad ID, a duplicate ID, IDs not strictly ascending, an unknown or
// non-earlier dependency, an empty name, a precondition with an empty
// description, empty up steps for either engine, or empty down steps for either
// engine on a reversible migration all reject the whole set.
//
// Calling NewRegistry with no arguments yields a valid empty registry.
func NewRegistry(ms ...Migration) (*Registry, error) {
	byID := make(map[string]Migration, len(ms))
	ordered := make([]Migration, 0, len(ms))
	var prevID string

	for i, m := range ms {
		if !idPattern.MatchString(m.ID) {
			return nil, fmt.Errorf("%w: migration at position %d has malformed id %q", ErrInvalidRegistry, i, m.ID)
		}
		if _, dup := byID[m.ID]; dup {
			return nil, fmt.Errorf("%w: duplicate migration id %q", ErrInvalidRegistry, m.ID)
		}
		if i > 0 && m.ID <= prevID {
			return nil, fmt.Errorf("%w: migration id %q is not strictly after %q", ErrInvalidRegistry, m.ID, prevID)
		}
		if m.Name == "" {
			return nil, fmt.Errorf("%w: migration %q has an empty name", ErrInvalidRegistry, m.ID)
		}
		if len(m.Up.SQLite) == 0 || len(m.Up.Postgres) == 0 {
			return nil, fmt.Errorf("%w: migration %q has empty up steps for an engine", ErrInvalidRegistry, m.ID)
		}
		if m.IrreversibleReason == "" && (len(m.Down.SQLite) == 0 || len(m.Down.Postgres) == 0) {
			return nil, fmt.Errorf("%w: reversible migration %q has empty down steps for an engine", ErrInvalidRegistry, m.ID)
		}
		for _, pc := range m.Preconditions {
			if pc.Description == "" {
				return nil, fmt.Errorf("%w: migration %q has a precondition with an empty description", ErrInvalidRegistry, m.ID)
			}
		}
		for _, req := range m.Requires {
			if _, ok := byID[req]; !ok {
				// byID holds only strictly-earlier migrations at this point,
				// so an absent requirement is either unknown or not earlier.
				return nil, fmt.Errorf("%w: migration %q requires %q, which is not a strictly earlier migration", ErrInvalidRegistry, m.ID, req)
			}
		}

		clone := cloneMigration(m)
		ordered = append(ordered, clone)
		byID[m.ID] = clone
		prevID = m.ID
	}

	return &Registry{ordered: ordered, byID: byID}, nil
}

// Default returns the empty registry shipped by F5. Real migrations are
// registered in F6.
func Default() *Registry {
	r, _ := NewRegistry()
	return r
}

// All returns the migrations in application order. The result is a defensive
// deep copy: mutating it cannot affect the registry.
func (r *Registry) All() []Migration {
	out := make([]Migration, len(r.ordered))
	for i, m := range r.ordered {
		out[i] = cloneMigration(m)
	}
	return out
}

// Get returns the migration with the given ID and whether it exists. The
// returned migration is a defensive deep copy.
func (r *Registry) Get(id string) (Migration, bool) {
	m, ok := r.byID[id]
	if !ok {
		return Migration{}, false
	}
	return cloneMigration(m), true
}

// cloneStrings returns a copy of in, preserving nil.
func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// cloneSteps returns a deep copy of s.
func cloneSteps(s Steps) Steps {
	return Steps{SQLite: cloneStrings(s.SQLite), Postgres: cloneStrings(s.Postgres)}
}

// cloneMigration returns a deep copy of m. Precondition Check functions are
// shared by reference because functions cannot be copied.
func cloneMigration(m Migration) Migration {
	m.Requires = cloneStrings(m.Requires)
	m.Up = cloneSteps(m.Up)
	m.Down = cloneSteps(m.Down)
	if m.Preconditions != nil {
		pc := make([]Precondition, len(m.Preconditions))
		copy(pc, m.Preconditions)
		m.Preconditions = pc
	}
	return m
}
