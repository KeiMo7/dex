package storage

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Naming aliases for callers and tests that spell the aggregate
// RefreshTokenChain/RefreshTokenGeneration explicitly.
type (
	RefreshTokenChain      = RefreshChain
	RefreshTokenGeneration = RefreshGeneration
)

const (
	RefreshTokenChainStatusActive  = RefreshChainStatusActive
	RefreshTokenChainStatusRevoked = RefreshChainStatusRevoked

	RefreshTokenReasonReplay       = RefreshChainReasonReplay
	RefreshTokenReasonAdmin        = RefreshChainReasonAdmin
	RefreshTokenReasonUserRevoked  = RefreshChainReasonUserRevoked
	RefreshTokenReasonSessionEnded = RefreshChainReasonSessionEnded
)

// Refresh-token chain statuses.
const (
	// RefreshChainStatusActive is a chain from which the current generation can
	// still be redeemed.
	RefreshChainStatusActive = "active"
	// RefreshChainStatusRevoked is a chain whose every generation is invalid.
	RefreshChainStatusRevoked = "revoked"
)

// Generation statuses. A generation starts current, becomes rotated when a
// newer generation is minted, and is revoked when its chain is revoked.
const (
	RefreshGenerationStatusCurrent = "current"
	RefreshGenerationStatusRotated = "rotated"
	RefreshGenerationStatusRevoked = "revoked"
	RefreshGenerationStatusExpired = "expired"
)

// Stable revocation reasons. They are persisted and audited; do not put token
// secrets in any reason-specific field.
const (
	// RefreshChainReasonReplay means a non-current generation was presented
	// outside its idempotency window.
	RefreshChainReasonReplay = "replay"
	// RefreshChainReasonAdmin means an administrator revoked the chain.
	RefreshChainReasonAdmin = "admin"
	// RefreshChainReasonUserRevoked means the user or an owner-facing logout
	// revoked the chain.
	RefreshChainReasonUserRevoked = "user_revoked"
	// RefreshChainReasonSessionEnded means a session-bound token's session ended.
	RefreshChainReasonSessionEnded = "session_ended"
)

// Audit/event sources. These identify the surface that made a decision, not the
// client IP; the IP is carried separately by the audit layer.
const (
	RefreshChainSourceTokenEndpoint = "token_endpoint"
	RefreshChainSourceAdminAPI      = "admin_api"
	RefreshChainSourceSession       = "session"
)

// RefreshChain is the ownership and generation-ordered lineage of refresh
// tokens. One chain corresponds to one stable refresh-token storage row and is
// independent of the opaque token secret.
//
// A non-zero RevokedAt or Status == RefreshChainStatusRevoked means the entire
// chain is dead. The record is retained after revocation so management and
// audit calls can still report when and why it died.
type RefreshChain struct {
	// ID is a random chain identifier. It is never embedded in an opaque token.
	ID string `json:"id"`

	UserID      string `json:"user_id"`
	ClientID    string `json:"client_id"`
	ConnectorID string `json:"connector_id"`

	// CurrentGeneration is the one accepted as the present generation.
	CurrentGeneration int64  `json:"current_generation"`
	Status            string `json:"status"`
	Reason            string `json:"reason,omitempty"`
	Source            string `json:"source,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`

	// Generations is the ordered generation history. Implementations retain at
	// least the current and immediately previous generation; this implementation
	// retains all generation metadata.
	Generations []RefreshGeneration `json:"generations,omitempty"`
}

// RefreshGeneration is one generation in a RefreshChain. It records metadata
// and a non-reversible verifier for the generation secret, never the raw token.
type RefreshGeneration struct {
	// ChainID denormalizes the chain identifier onto each generation record.
	ChainID string `json:"chain_id"`
	// Number is the one-based generation sequence.
	Number int64 `json:"number"`

	// SecretHash verifies the opaque secret presented for this generation without
	// persisting another copy of the raw secret.
	SecretHash string `json:"secret_hash,omitempty"`

	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`

	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	Source string `json:"source,omitempty"`
}

// IsRevoked reports whether the chain has been durably revoked.
func (c *RefreshChain) IsRevoked() bool {
	return c != nil && (c.Status == RefreshChainStatusRevoked || !c.RevokedAt.IsZero())
}

// Generation returns the generation with n and whether it exists.
func (c *RefreshChain) Generation(n int64) (RefreshGeneration, bool) {
	if c == nil {
		return RefreshGeneration{}, false
	}
	for _, g := range c.Generations {
		if g.Number == n {
			return g, true
		}
	}
	return RefreshGeneration{}, false
}

// UpdateRefreshTokenIfGeneration expresses an optimistic premise: the update
// may run only while the row still carries expectedGeneration. It is a thin,
// backend-independent adapter over UpdateRefreshToken so callers that have not
// been wired to a backend-specific CAS method still state the condition
// explicitly. Backends with CompareAndSwapRefreshTokenGeneration provide the
// stronger single-statement form; both are safe because UpdateRefreshToken is
// transactional/serialized in every implementation.
//
// When the premise does not hold, swapped is false and current is the live row.
func UpdateRefreshTokenIfGeneration(ctx context.Context, s Storage, id string, expectedGeneration int64, updater func(old RefreshToken) (RefreshToken, error)) (current RefreshToken, swapped bool, err error) {
	var conflict bool
	err = s.UpdateRefreshToken(ctx, id, func(old RefreshToken) (RefreshToken, error) {
		current = old
		if old.Generation != expectedGeneration {
			conflict = true
			return old, ErrGenerationMismatch
		}
		updated, uerr := updater(old)
		if uerr != nil {
			return old, uerr
		}
		current = updated
		swapped = true
		return updated, nil
	})
	if conflict || errors.Is(err, ErrGenerationMismatch) {
		// The sentinel is control flow, not an infrastructure failure. The next
		// read performed by Update already captured current where supported; make
		// the common path exact for backends whose transaction did not expose it.
		if current.ID == "" {
			current, err = s.GetRefresh(ctx, id)
			if err != nil {
				return RefreshToken{}, false, err
			}
		}
		return current, false, nil
	}
	if err != nil {
		if isOptimisticConflictError(err) {
			live, getErr := s.GetRefresh(ctx, id)
			if getErr == nil {
				return live, false, nil
			}
			return RefreshToken{}, false, getErr
		}
		return current, false, err
	}
	return current, true, nil
}

func isOptimisticConflictError(err error) bool {
	if errors.Is(err, ErrGenerationMismatch) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "concurrent conflicting update") ||
		strings.Contains(msg, "concurrent update") ||
		strings.Contains(msg, "operation was aborted") ||
		strings.Contains(msg, "transaction conflict")
}
