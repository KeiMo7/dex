package tokens

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/dexidp/dex/storage"
)

// hashGenerationSecret stores a non-reversible verifier for a generation
// secret. The live RefreshToken.Token/ObsoleteToken fields retain their
// existing compatibility representation; chain history never stores another
// raw secret.
func hashGenerationSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func constantTimeHashMatch(storedHash, secret string) bool {
	if storedHash == "" || secret == "" {
		return false
	}
	got := hashGenerationSecret(secret)
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(got)) == 1
}

func cloneRefreshToken(in storage.RefreshToken) storage.RefreshToken {
	out := in
	if in.Chain != nil {
		chain := *in.Chain
		if in.Chain.Generations != nil {
			chain.Generations = append([]storage.RefreshGeneration(nil), in.Chain.Generations...)
		}
		out.Chain = &chain
	}
	if in.Scopes != nil {
		out.Scopes = append([]string(nil), in.Scopes...)
	}
	if in.Claims.Groups != nil {
		out.Claims.Groups = append([]string(nil), in.Claims.Groups...)
	}
	if in.ConnectorData != nil {
		out.ConnectorData = append([]byte(nil), in.ConnectorData...)
	}
	return out
}

// normalizeRefreshChain adopts legacy rows and repairs in-memory invariants.
// It does not itself persist; the caller's atomic refresh update writes the
// normalized row.
func normalizeRefreshChain(r storage.RefreshToken, now time.Time) storage.RefreshToken {
	if r.Chain == nil {
		chainID := r.ChainID
		if chainID == "" {
			chainID = storage.NewID()
		}
		gen := r.Generation
		if gen <= 0 {
			gen = 1
		}
		issuedAt := r.CreatedAt
		if issuedAt.IsZero() {
			issuedAt = r.LastUsed
		}
		if issuedAt.IsZero() {
			issuedAt = now
		}
		r.ChainID = chainID
		r.Generation = gen
		r.Chain = &storage.RefreshChain{
			ID:                chainID,
			UserID:            r.Claims.UserID,
			ClientID:          r.ClientID,
			ConnectorID:       r.ConnectorID,
			CurrentGeneration: gen,
			Status:            storage.RefreshChainStatusActive,
			CreatedAt:         issuedAt,
			UpdatedAt:         now,
			Generations: []storage.RefreshGeneration{{
				ChainID:    chainID,
				Number:     gen,
				SecretHash: hashGenerationSecret(r.Token),
				IssuedAt:   issuedAt,
				Status:     storage.RefreshGenerationStatusCurrent,
			}},
		}
		return r
	}

	c := r.Chain
	if c.ID == "" {
		if r.ChainID != "" {
			c.ID = r.ChainID
		} else {
			c.ID = storage.NewID()
		}
	}
	r.ChainID = c.ID
	if c.ClientID == "" {
		c.ClientID = r.ClientID
	}
	if c.UserID == "" {
		c.UserID = r.Claims.UserID
	}
	if c.ConnectorID == "" {
		c.ConnectorID = r.ConnectorID
	}
	if c.Status == "" {
		if c.IsRevoked() {
			c.Status = storage.RefreshChainStatusRevoked
		} else {
			c.Status = storage.RefreshChainStatusActive
		}
	}
	if r.Generation <= 0 {
		r.Generation = c.CurrentGeneration
	}
	if c.CurrentGeneration <= 0 {
		c.CurrentGeneration = r.Generation
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = now
	}
	if len(c.Generations) == 0 {
		issuedAt := r.CreatedAt
		if issuedAt.IsZero() {
			issuedAt = r.LastUsed
		}
		if issuedAt.IsZero() {
			issuedAt = now
		}
		c.Generations = []storage.RefreshGeneration{{
			ChainID:    c.ID,
			Number:     c.CurrentGeneration,
			SecretHash: hashGenerationSecret(r.Token),
			IssuedAt:   issuedAt,
			Status:     storage.RefreshGenerationStatusCurrent,
		}}
	}
	return r
}

type secretMatch struct {
	found      bool
	current    bool
	generation int64
}

// matchRefreshSecret locates the presented secret among the current secret,
// durable generation verifiers, and the compatibility ObsoleteToken field.
func matchRefreshSecret(r storage.RefreshToken, presented string) secretMatch {
	if subtle.ConstantTimeCompare([]byte(r.Token), []byte(presented)) == 1 {
		return secretMatch{found: true, current: true, generation: r.Generation}
	}
	if r.Chain != nil {
		// Newest first keeps the common previous-generation case cheap.
		for i := len(r.Chain.Generations) - 1; i >= 0; i-- {
			g := r.Chain.Generations[i]
			if constantTimeHashMatch(g.SecretHash, presented) {
				return secretMatch{found: true, current: false, generation: g.Number}
			}
		}
	}
	if r.ObsoleteToken != "" && subtle.ConstantTimeCompare([]byte(r.ObsoleteToken), []byte(presented)) == 1 {
		gen := r.Generation - 1
		if gen < 1 {
			gen = 0
		}
		return secretMatch{found: true, current: false, generation: gen}
	}
	return secretMatch{}
}

// appendNextGeneration records the outgoing generation as rotated and appends
// the newly minted current generation.
func appendNextGeneration(r *storage.RefreshToken, newSecret string, now time.Time, reuseInterval time.Duration) int64 {
	if r.Chain == nil {
		*r = normalizeRefreshChain(*r, now)
	}
	c := r.Chain
	previous := r.Generation
	for i := range c.Generations {
		if c.Generations[i].Number == previous {
			c.Generations[i].Status = storage.RefreshGenerationStatusRotated
			c.Generations[i].Reason = "rotated"
			if reuseInterval > 0 {
				c.Generations[i].ExpiresAt = r.LastUsed.Add(reuseInterval)
			}
		}
	}

	next := previous + 1
	r.Generation = next
	c.CurrentGeneration = next
	c.UpdatedAt = now
	c.Generations = append(c.Generations, storage.RefreshGeneration{
		ChainID:    c.ID,
		Number:     next,
		SecretHash: hashGenerationSecret(newSecret),
		IssuedAt:   now,
		Status:     storage.RefreshGenerationStatusCurrent,
	})
	return next
}

// revokeRefreshChain marks the single chain aggregate and all generations
// revoked. This is the atomic whole-chain invalidation state.
func revokeRefreshChain(r *storage.RefreshToken, now time.Time, reason, source string, generation int64) {
	if r.Chain == nil {
		*r = normalizeRefreshChain(*r, now)
	}
	c := r.Chain
	if generation == 0 {
		generation = r.Generation
	}
	c.Status = storage.RefreshChainStatusRevoked
	c.Reason = reason
	c.Source = source
	c.RevokedAt = now
	c.UpdatedAt = now
	for i := range c.Generations {
		if c.Generations[i].Status != storage.RefreshGenerationStatusRevoked {
			c.Generations[i].Status = storage.RefreshGenerationStatusRevoked
			c.Generations[i].Reason = reason
			c.Generations[i].Source = source
			c.Generations[i].RevokedAt = now
		}
	}
}

// chainIdentityDescription is a log-safe fallback for legacy rows whose chain
// pointer has not yet been initialized.
func chainIdentityDescription(r *storage.RefreshToken) (chainID, userID, clientID, connectorID string) {
	if r == nil {
		return "", "", "", ""
	}
	if r.Chain != nil {
		return r.Chain.ID, r.Claims.UserID, r.ClientID, r.ConnectorID
	}
	return r.ChainID, r.Claims.UserID, r.ClientID, r.ConnectorID
}

// isConcurrentRefreshWriteConflict recognizes optimistic-concurrency failures
// from backends that do not normalize them to storage.ErrGenerationMismatch.
func isConcurrentRefreshWriteConflict(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, storage.ErrGenerationMismatch) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "concurrent conflicting update") ||
		strings.Contains(msg, "concurrent update") ||
		strings.Contains(msg, "operation was aborted") ||
		strings.Contains(msg, "transaction conflict")
}
