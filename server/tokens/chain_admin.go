package tokens

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/dexidp/dex/storage"
)

// GetRefreshChain returns the durable chain status for chainID. A storage read
// failure is wrapped with ErrRefreshChainUnavailable so callers can fail closed
// and distinguish "status unknown" from a healthy chain.
func (rt *RefreshStore) GetRefreshChain(ctx context.Context, chainID string) (storage.RefreshChain, error) {
	if chainID == "" {
		return storage.RefreshChain{}, storage.ErrNotFound
	}
	refresh, err := rt.findRefreshByChainID(ctx, chainID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return storage.RefreshChain{}, storage.ErrNotFound
		}
		return storage.RefreshChain{}, fmt.Errorf("%w: list refresh tokens: %v", ErrRefreshChainUnavailable, err)
	}
	refresh = normalizeRefreshChain(refresh, rt.currentTime())
	return *refresh.Chain, nil
}

// ListRefreshChains returns chains, optionally filtered by user and connector.
// Empty filters do not restrict that dimension.
func (rt *RefreshStore) ListRefreshChains(ctx context.Context, userID, connectorID string) ([]storage.RefreshChain, error) {
	tokens, err := rt.storage.ListRefreshTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: list refresh tokens: %v", ErrRefreshChainUnavailable, err)
	}
	chains := make([]storage.RefreshChain, 0)
	for _, token := range tokens {
		if userID != "" && token.Claims.UserID != userID {
			continue
		}
		if connectorID != "" && token.ConnectorID != connectorID {
			continue
		}
		token = normalizeRefreshChain(token, rt.currentTime())
		chains = append(chains, *token.Chain)
	}
	return chains, nil
}

// RevokeRefreshChain atomically revokes one chain. Repeating an already
// revoked chain is successful and returns its stored status without writing a
// second revocation or audit transition.
func (rt *RefreshStore) RevokeRefreshChain(ctx context.Context, chainID, source, reason string) (storage.RefreshChain, bool, error) {
	if chainID == "" {
		return storage.RefreshChain{}, false, storage.ErrNotFound
	}
	refresh, err := rt.findRefreshByChainID(ctx, chainID)
	if err != nil {
		return storage.RefreshChain{}, false, err
	}
	return rt.revokeRefreshTokenRow(ctx, refresh, source, reason)
}

// revokeRefreshTokenRow revokes the chain stored on a known refresh row. It is
// used by user/connector bulk revocation so legacy rows that have not yet
// persisted an adopted random chain ID can still be revoked.
func (rt *RefreshStore) revokeRefreshTokenRow(ctx context.Context, refresh storage.RefreshToken, source, reason string) (storage.RefreshChain, bool, error) {
	if reason == "" {
		reason = storage.RefreshChainReasonAdmin
	}
	if source == "" {
		source = storage.RefreshChainSourceAdminAPI
	}

	var (
		result  storage.RefreshChain
		changed bool
	)
	err := rt.storage.UpdateRefreshToken(ctx, refresh.ID, func(old storage.RefreshToken) (storage.RefreshToken, error) {
		old = normalizeRefreshChain(old, rt.currentTime())
		result = *old.Chain
		if old.Chain.IsRevoked() {
			return old, nil
		}
		changed = true
		now := rt.currentTime()
		revokeRefreshChain(&old, now, reason, source, old.Generation)
		result = *old.Chain
		return old, nil
	})
	if err != nil {
		return storage.RefreshChain{}, false, fmt.Errorf("revoke refresh chain for token %q: %w", refresh.ID, err)
	}

	if changed {
		rt.audit(ctx, Audit{
			Event:       AuditEventChainRevoked,
			ChainID:     result.ID,
			ClientID:    refresh.ClientID,
			UserID:      refresh.Claims.UserID,
			ConnectorID: refresh.ConnectorID,
			Generation:  result.CurrentGeneration,
			Source:      source,
			Reason:      reason,
		}, slog.LevelWarn)
		// Remove the active offline-session reference but retain the revoked row
		// as chain/audit state. A cleanup failure cannot reopen the chain because
		// its durable status is already revoked.
		rt.removeOfflineSessionReference(ctx, &refresh)
	}
	return result, changed, nil
}

// RevokeRefreshChainsByUser revokes every chain owned by userID under
// connectorID. It returns the revoked chain IDs. Already-revoked chains are
// idempotent and are not counted as new transitions.
func (rt *RefreshStore) RevokeRefreshChainsByUser(ctx context.Context, userID, connectorID, source string) ([]string, error) {
	if userID == "" || connectorID == "" {
		return nil, errors.New("userID and connectorID are required")
	}
	if source == "" {
		source = storage.RefreshChainSourceAdminAPI
	}
	tokens, err := rt.storage.ListRefreshTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: list refresh tokens: %v", ErrRefreshChainUnavailable, err)
	}

	var revoked []string
	var errs []error
	for _, token := range tokens {
		if token.Claims.UserID != userID || token.ConnectorID != connectorID {
			continue
		}
		result, _, err := rt.revokeRefreshTokenRow(ctx, token, source, storage.RefreshChainReasonAdmin)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		revoked = append(revoked, result.ID)
	}
	return revoked, errors.Join(errs...)
}

func (rt *RefreshStore) findRefreshByChainID(ctx context.Context, chainID string) (storage.RefreshToken, error) {
	tokens, err := rt.storage.ListRefreshTokens(ctx)
	if err != nil {
		return storage.RefreshToken{}, err
	}
	for _, token := range tokens {
		if token.ChainID == chainID || (token.Chain != nil && token.Chain.ID == chainID) {
			return token, nil
		}
	}
	return storage.RefreshToken{}, storage.ErrNotFound
}
