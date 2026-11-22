package tokens

import (
	"context"
	"errors"
	"time"

	"github.com/dexidp/dex/storage"
)

// createFamily provisions a brand-new family for a freshly created refresh row
// and returns its ID. The refresh row is created by the caller first, so the
// node can use that row's ID as its own.
func (rt *RefreshStore) createFamily(ctx context.Context, r storage.RefreshToken) (string, error) {
	now := rt.now()
	familyID := storage.NewID()
	if err := rt.storage.CreateTokenFamily(ctx, storage.TokenFamily{
		ID:          familyID,
		ClientID:    r.ClientID,
		UserID:      r.Claims.UserID,
		ConnectorID: r.ConnectorID,
		CreatedAt:   now,
	}); err != nil {
		return "", err
	}
	if err := rt.storage.CreateTokenNode(ctx, storage.TokenNode{
		ID:          r.ID,
		FamilyID:    familyID,
		Kind:        storage.TokenNodeKindRefresh,
		ClientID:    r.ClientID,
		UserID:      r.Claims.UserID,
		ConnectorID: r.ConnectorID,
		CreatedAt:   r.CreatedAt,
	}); err != nil {
		return "", err
	}
	return familyID, nil
}

// RegisterAccessToken records an access token as a node of the given family, so
// a later family revocation can propagate to it through introspection. It is
// called while issuing an access token for a client that holds (or is being
// given) a refresh token. Failures are returned: the grant fails closed rather
// than issuing an access token the family revocation could not reach.
func (rt *RefreshStore) RegisterAccessToken(ctx context.Context, familyID string, r storage.RefreshToken, jti string, expiry time.Time) error {
	if familyID == "" || jti == "" {
		return nil
	}
	return rt.storage.CreateTokenNode(ctx, storage.TokenNode{
		ID:          jti,
		FamilyID:    familyID,
		ParentID:    r.ID,
		Kind:        storage.TokenNodeKindAccess,
		ClientID:    r.ClientID,
		UserID:      r.Claims.UserID,
		ConnectorID: r.ConnectorID,
		CreatedAt:   rt.now(),
		ExpiresAt:   expiry,
	})
}

// RevokeFamily marks the whole family graph revoked in response to a replayed
// refresh token. It flips the family root first (the single signal every
// introspection consults), then marks every node and removes the family's
// refresh token rows so no token in the lineage can be presented again. The
// root row itself is kept, with its reason and audit fields, rather than
// deleted: it is the durable record of the security event.
//
// The family flip and the node sweep are separate storage transactions; a
// crash between them still leaves the root revoked, so every subsequent lookup
// and introspection is refused even if some nodes were not individually marked.
func (rt *RefreshStore) RevokeFamily(ctx context.Context, familyID, replayedTokenID string, at time.Time) error {
	var family storage.TokenFamily
	err := rt.storage.UpdateTokenFamily(ctx, familyID, func(f storage.TokenFamily) (storage.TokenFamily, error) {
		if !f.RevokedAt.IsZero() {
			// Already revoked by an earlier event — keep the first reason.
			return f, nil
		}
		f.RevokedAt = at
		f.RevokeReason = storage.RevokeReasonReplay
		f.LastReplayedToken = replayedTokenID
		family = f
		return f, nil
	})
	if err != nil {
		return err
	}

	rt.logger.WarnContext(ctx, "refresh token replay detected; token family revoked",
		"family_id", familyID,
		"token_id", replayedTokenID,
		"client_id", family.ClientID,
		"user_id", family.UserID,
		"connector_id", family.ConnectorID,
		"reason", storage.RevokeReasonReplay,
		"observed_at", at,
	)

	nodes, err := rt.storage.ListTokenNodes(ctx, familyID)
	if err != nil {
		return err
	}

	marked := 0
	var refreshRowIDs []string
	for _, n := range nodes {
		if n.Kind == storage.TokenNodeKindRefresh {
			refreshRowIDs = append(refreshRowIDs, n.ID)
		}
		if !n.RevokedAt.IsZero() {
			continue
		}
		if err := rt.storage.UpdateTokenNode(ctx, n.ID, func(old storage.TokenNode) (storage.TokenNode, error) {
			old.RevokedAt = at
			return old, nil
		}); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		marked++
	}

	rt.logger.WarnContext(ctx, "token family revocation propagated across graph",
		"family_id", familyID,
		"nodes_total", len(nodes),
		"nodes_marked", marked,
		"refresh_tokens_removed", len(refreshRowIDs),
	)

	// Removing the refresh rows makes any later presentation fail at lookup with
	// invalid_grant, even by a client that never consults the family root.
	for _, id := range refreshRowIDs {
		if err := rt.storage.DeleteRefresh(ctx, id); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return err
		}
	}

	return nil
}

// IsAccessTokenRevoked reports whether an access token (identified by its JWT
// jti) belongs to a revoked family or carries a revoked node. Missing records
// are not a revocation: a token whose node was garbage-collected, or that
// predates family tracking, falls back to the JWT's own expiry. A storage
// failure is returned so the caller can fail closed (HTTP 500) instead of
// answering active on an unknown revocation state.
func (rt *RefreshStore) IsAccessTokenRevoked(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}

	node, err := rt.storage.GetTokenNode(ctx, jti)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// Signal absent: fall back to the token's natural lifetime.
			return false, nil
		}
		return false, err
	}

	if !node.RevokedAt.IsZero() {
		return true, nil
	}

	family, err := rt.storage.GetTokenFamily(ctx, node.FamilyID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return !family.RevokedAt.IsZero(), nil
}
