package tokens

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

// RefreshStore creates, rotates, and revokes refresh tokens, keeping the
// offline-session references in sync. It is the single owner of refresh-token
// persistence.
type RefreshStore struct {
	storage storage.Storage
	now     func() time.Time
	logger  *slog.Logger
}

// NewRefreshStore returns a store backed by the given storage.
func NewRefreshStore(storage storage.Storage, now func() time.Time, logger *slog.Logger) *RefreshStore {
	if now == nil {
		now = time.Now
	}
	return &RefreshStore{storage: storage, now: now, logger: logger}
}

func (rt *RefreshStore) currentTime() time.Time {
	if rt != nil && rt.now != nil {
		return rt.now()
	}
	return time.Now()
}

// Create issues a new refresh token for the authorization and records it in the
// user's offline session. On any offline-session failure the refresh token is
// rolled back so no orphaned token is left behind.
func (rt *RefreshStore) Create(ctx context.Context, auth Authorization) (string, error) {
	now := rt.currentTime()
	chainID := storage.NewID()
	refresh := storage.RefreshToken{
		ID:            storage.NewID(),
		Token:         storage.NewID(),
		ChainID:       chainID,
		Generation:    1,
		ClientID:      auth.Client.ID,
		ConnectorID:   auth.ConnectorID,
		Scopes:        auth.Scopes,
		Claims:        auth.Claims,
		Nonce:         auth.Nonce,
		ConnectorData: auth.ConnectorData,
		CreatedAt:     now,
		LastUsed:      now,
	}
	refresh.Chain = &storage.RefreshChain{
		ID:                chainID,
		UserID:            auth.Claims.UserID,
		ClientID:          auth.Client.ID,
		ConnectorID:       auth.ConnectorID,
		CurrentGeneration: 1,
		Status:            storage.RefreshChainStatusActive,
		CreatedAt:         now,
		UpdatedAt:         now,
		Generations: []storage.RefreshGeneration{{
			ChainID:    chainID,
			Number:     1,
			SecretHash: hashGenerationSecret(refresh.Token),
			IssuedAt:   now,
			Status:     storage.RefreshGenerationStatusCurrent,
		}},
	}

	rawToken, err := internal.Marshal(&internal.RefreshToken{RefreshId: refresh.ID, Token: refresh.Token})
	if err != nil {
		return "", fmt.Errorf("marshal refresh token: %w", err)
	}

	if err := rt.storage.CreateRefresh(ctx, refresh); err != nil {
		return "", fmt.Errorf("create refresh token: %w", err)
	}

	// Roll back the just-created refresh token if wiring it into the offline
	// session fails, so we never leave an orphaned token.
	rollback := func() {
		if err := rt.storage.DeleteRefresh(ctx, refresh.ID); err != nil && err != storage.ErrNotFound {
			rt.logger.ErrorContext(ctx, "failed to roll back refresh token", "err", err)
		}
	}

	tokenRef := storage.RefreshTokenRef{
		ID:        refresh.ID,
		ClientID:  refresh.ClientID,
		CreatedAt: refresh.CreatedAt,
		LastUsed:  refresh.LastUsed,
		SessionID: auth.SessionID,
	}

	session, err := rt.storage.GetOfflineSessions(ctx, refresh.Claims.UserID, refresh.ConnectorID)
	switch {
	case err != nil && err != storage.ErrNotFound:
		rollback()
		return "", fmt.Errorf("get offline session: %w", err)
	case err != nil: // ErrNotFound: create a fresh offline session.
		offlineSessions := storage.OfflineSessions{
			UserID:        refresh.Claims.UserID,
			ConnID:        refresh.ConnectorID,
			Refresh:       map[string]*storage.RefreshTokenRef{tokenRef.ClientID: &tokenRef},
			ConnectorData: auth.ConnectorData,
		}
		if err := rt.storage.CreateOfflineSessions(ctx, offlineSessions); err != nil {
			rollback()
			return "", fmt.Errorf("create offline session: %w", err)
		}
	default:
		// Replace any existing refresh token for this client.
		if oldRef, ok := session.Refresh[tokenRef.ClientID]; ok {
			if err := rt.storage.DeleteRefresh(ctx, oldRef.ID); err != nil && err != storage.ErrNotFound {
				rollback()
				return "", fmt.Errorf("delete previous refresh token: %w", err)
			}
		}
		if err := rt.storage.UpdateOfflineSessions(ctx, session.UserID, session.ConnID, func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
			old.Refresh[tokenRef.ClientID] = &tokenRef
			if len(auth.ConnectorData) > 0 {
				old.ConnectorData = auth.ConnectorData
			}
			return old, nil
		}); err != nil {
			rollback()
			return "", fmt.Errorf("update offline session: %w", err)
		}
	}

	return rawToken, nil
}

// IdentityFromClaims projects stored claims into a connector identity. The
// refresh flow intentionally leaves UserID untouched by later updates.
func IdentityFromClaims(claims storage.Claims) connector.Identity {
	return connector.Identity{
		UserID:            claims.UserID,
		Username:          claims.Username,
		PreferredUsername: claims.PreferredUsername,
		Email:             claims.Email,
		EmailVerified:     claims.EmailVerified,
		Groups:            claims.Groups,
	}
}

// ClaimsFromIdentity maps a freshly authenticated connector identity to ID token
// claims. It is the inverse of IdentityFromClaims and the single place grants
// turn an identity into claims.
func ClaimsFromIdentity(identity connector.Identity) storage.Claims {
	return storage.Claims{
		UserID:            identity.UserID,
		Username:          identity.Username,
		PreferredUsername: identity.PreferredUsername,
		Email:             identity.Email,
		EmailVerified:     identity.EmailVerified,
		Groups:            identity.Groups,
	}
}

// Rotate advances the stored refresh token according to the rotation strategy and
// syncs the offline session. It returns the marshaled token to hand back to the
// client and the identity its claims were refreshed to.
//
// Rotation runs as two storage transactions around the identity resolution: the
// claim reuses the token or rotates it, the finalize writes the refreshed claims.
// The updaters never read storage, so backends that serialize on one connection
// or lock (SQLite, memory) cannot deadlock. A concurrent refresh that lands
// between the two reuses the new token. A failed resolve, finalize or offline
// session update undoes the claim.
func (rt *RefreshStore) Rotate(ctx context.Context, storageToken *storage.RefreshToken, requestToken *internal.RefreshToken, strategy *RefreshStrategy, freshIdentity func(context.Context) (connector.Identity, error)) (string, connector.Identity, error) {
	newToken := &internal.RefreshToken{
		Token:     requestToken.Token,
		RefreshId: requestToken.RefreshId,
	}

	ident := IdentityFromClaims(storageToken.Claims)
	lastUsed := rt.currentTime()
	var (
		mint      bool
		advanced  bool
		replay    bool
		replayGen int64
		chainID   string
		preClaim  storage.RefreshToken
	)
	expectedGeneration := storageToken.Generation

	// Claim: decide idempotent reuse, rotation, superseded concurrency, or replay
	// from the live row. The decision and any chain status flip are written by
	// this one atomic UpdateRefreshToken call.
	claim := func(old storage.RefreshToken) (storage.RefreshToken, error) {
		// Reset per execution: a backend that retries the updater must not carry a
		// stale decision from an earlier run.
		mint, advanced, replay = false, false, false
		replayGen = 0

		// Keep a deep copy of the raw row for failure rollback. The updater may
		// run more than once, so reset this on every execution.
		preClaim = cloneRefreshToken(old)

		// A live generation greater than the one the caller looked up means a
		// concurrent request won the atomic advance. A normalized legacy view can
		// have generation one while the raw row is still zero; that is not a race.
		stale := old.Generation > expectedGeneration

		old = normalizeRefreshChain(old, rt.currentTime())
		chainID = old.ChainID
		if old.Chain.IsRevoked() {
			return old, ErrRefreshChainRevoked
		}

		match := matchRefreshSecret(old, requestToken.Token)
		if !match.found {
			if stale {
				return old, ErrRefreshTokenSuperseded
			}
			return old, ErrRefreshTokenInvalid
		}

		reusingAllowed := strategy.AllowedToReuse(old.LastUsed)

		// A recognized older generation outside the idempotency window is replay.
		// If the live row has advanced past the generation this caller snapshotted,
		// this is instead an in-flight concurrent loser: return the distinguished
		// superseded result and never revoke the legitimate winner's chain.
		if !match.current && !reusingAllowed {
			if stale {
				return old, ErrRefreshTokenSuperseded
			}
			replay = true
			replayGen = match.generation
			revokeRefreshChain(&old, rt.currentTime(), storage.RefreshChainReasonReplay, storage.RefreshChainSourceTokenEndpoint, match.generation)
			chainID = old.ChainID
			return old, nil
		}

		if reusingAllowed {
			// Idempotent retry/concurrent duplicate: hand back the current secret,
			// do not advance a generation and do not resolve identity again.
			newToken.Token = old.Token
			lastUsed = old.LastUsed
			old.ConnectorData = nil
			return old, nil
		}

		if !match.current {
			// Defensive: the only non-current outside-window outcome above is
			// replay or a concurrency error.
			if stale {
				return old, ErrRefreshTokenSuperseded
			}
			return old, ErrRefreshTokenReplayed
		}

		// Rotate here, not in finalize, so concurrent refreshes observe the new
		// generation and reuse its result instead of resolving upstream again.
		lastUsed = rt.currentTime()
		old.LastUsed = lastUsed
		old.ConnectorData = nil
		mint = true

		if strategy.RotationEnabled() {
			old.ObsoleteToken = old.Token
			newToken.Token = storage.NewID()
			old.Token = newToken.Token
			appendNextGeneration(&old, newToken.Token, lastUsed, strategy.ReuseInterval())
			advanced = true
		}
		return old, nil
	}

	if err := rt.storage.UpdateRefreshToken(ctx, storageToken.ID, claim); err != nil {
		if isConcurrentRefreshWriteConflict(err) {
			// One bounded retry for backends whose optimistic transaction reports
			// the race instead of retrying internally. On the second read the claim
			// classifies the request as idempotent reuse or an explicit supersession.
			err = rt.storage.UpdateRefreshToken(ctx, storageToken.ID, claim)
		}
		if err != nil {
			if isConcurrentRefreshWriteConflict(err) || errors.Is(err, storage.ErrGenerationMismatch) {
				err = fmt.Errorf("%w: %v", ErrRefreshTokenSuperseded, err)
			}
			switch {
			case errors.Is(err, ErrRefreshTokenSuperseded):
				rt.logger.InfoContext(ctx, "refresh claim superseded by concurrent rotation", "err", err)
			case errors.Is(err, ErrRefreshChainRevoked):
				rt.logger.WarnContext(ctx, "refresh claim rejected because chain is revoked", "err", err)
			default:
				rt.logger.ErrorContext(ctx, "failed to claim refresh token rotation", "err", err)
			}
			return "", ident, err
		}
	}

	if replay {
		chain := &storage.RefreshChain{ID: chainID, ClientID: storageToken.ClientID, UserID: storageToken.Claims.UserID, ConnectorID: storageToken.ConnectorID}
		rt.audit(ctx, auditForChain(chain, AuditEventReplay, replayGen, storage.RefreshChainSourceTokenEndpoint, storage.RefreshChainReasonReplay), slog.LevelWarn)
		rt.audit(ctx, auditForChain(chain, AuditEventChainRevoked, replayGen, storage.RefreshChainSourceTokenEndpoint, storage.RefreshChainReasonReplay), slog.LevelWarn)
		rt.removeOfflineSessionReference(ctx, storageToken)
		return "", ident, ErrRefreshTokenReplayed
	}

	if mint {
		// Resolve identity outside any transaction: the connector may read storage
		// or contact an upstream provider.
		var idErr error
		ident, idErr = freshIdentity(ctx)
		if idErr != nil {
			rt.undoClaim(ctx, storageToken.ID, newToken.Token, lastUsed, preClaim)
			return "", ident, idErr
		}

		// Finalize: write refreshed claims only while the row still shows our mint.
		finalize := func(old storage.RefreshToken) (storage.RefreshToken, error) {
			if old.Token != newToken.Token {
				return old, ErrRefreshTokenSuperseded
			}

			old.Claims.Username = ident.Username
			old.Claims.PreferredUsername = ident.PreferredUsername
			old.Claims.Email = ident.Email
			old.Claims.EmailVerified = ident.EmailVerified
			old.Claims.Groups = ident.Groups

			old.ConnectorData = nil
			return old, nil
		}

		if err := rt.storage.UpdateRefreshToken(ctx, storageToken.ID, finalize); err != nil {
			rt.logger.ErrorContext(ctx, "failed to finalize refresh token rotation", "err", err)
			rt.undoClaim(ctx, storageToken.ID, newToken.Token, lastUsed, preClaim)
			return "", ident, err
		}
	}

	if err := rt.updateOfflineSession(ctx, storageToken, ident, lastUsed); err != nil {
		if mint {
			rt.undoClaim(ctx, storageToken.ID, newToken.Token, lastUsed, preClaim)
		}
		return "", ident, err
	}

	if advanced {
		gen := int64(0)
		if current, err := rt.storage.GetRefresh(ctx, storageToken.ID); err == nil {
			gen = current.Generation
			if current.Chain != nil {
				chainID = current.Chain.ID
			}
		}
		chain := &storage.RefreshChain{ID: chainID, ClientID: storageToken.ClientID, UserID: storageToken.Claims.UserID, ConnectorID: storageToken.ConnectorID}
		rt.audit(ctx, auditForChain(chain, AuditEventRotation, gen, storage.RefreshChainSourceTokenEndpoint, "rotated"), slog.LevelInfo)
	}

	rawToken, err := internal.Marshal(newToken)
	if err != nil {
		return "", ident, fmt.Errorf("marshal refresh token: %w", err)
	}

	return rawToken, ident, nil
}

// undoClaim restores the exact pre-claim row after failed identity resolution,
// finalize or offline-session wiring. The guard applies only to a row still
// showing our own mint and timestamp, so an undo never overwrites a later
// winner. An undo failure is logged; callers fail the refresh rather than
// handing out a token whose supporting state was not written.
func (rt *RefreshStore) undoClaim(ctx context.Context, id, mintedToken string, lastUsed time.Time, preClaim storage.RefreshToken) {
	err := rt.storage.UpdateRefreshToken(ctx, id, func(old storage.RefreshToken) (storage.RefreshToken, error) {
		if old.Token != mintedToken || old.LastUsed.Before(lastUsed) {
			return old, nil
		}
		restored := cloneRefreshToken(preClaim)
		restored.ID = id
		return restored, nil
	})
	if err != nil {
		rt.logger.ErrorContext(ctx, "failed to undo refresh token claim", "err", err)
	}
}

// removeOfflineSessionReference clears the client reference after replay while
// retaining the refresh row and its revoked chain as the queryable audit state.
func (rt *RefreshStore) removeOfflineSessionReference(ctx context.Context, refresh *storage.RefreshToken) {
	if refresh == nil {
		return
	}
	err := rt.storage.UpdateOfflineSessions(ctx, refresh.Claims.UserID, refresh.ConnectorID, func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
		if ref := old.Refresh[refresh.ClientID]; ref != nil && ref.ID == refresh.ID {
			delete(old.Refresh, refresh.ClientID)
		}
		return old, nil
	})
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		rt.logger.ErrorContext(ctx, "failed to remove replayed refresh token offline reference", "err", err)
	}
}

// updateOfflineSession records the refresh token's new last-used time, and any
// updated connector data, on the user's offline session.
func (rt *RefreshStore) updateOfflineSession(ctx context.Context, refresh *storage.RefreshToken, ident connector.Identity, lastUsed time.Time) error {
	offlineSessionUpdater := func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
		ref := old.Refresh[refresh.ClientID]
		if ref == nil || ref.ID != refresh.ID {
			return old, errors.New("refresh token invalid")
		}

		ref.LastUsed = lastUsed
		if len(ident.ConnectorData) > 0 {
			old.ConnectorData = ident.ConnectorData
		}

		rt.logger.DebugContext(ctx, "saved connector data", "user_id", ident.UserID, "connector_data_bytes", len(ident.ConnectorData))
		return old, nil
	}

	if err := rt.storage.UpdateOfflineSessions(ctx, refresh.Claims.UserID, refresh.ConnectorID, offlineSessionUpdater); err != nil {
		rt.logger.ErrorContext(ctx, "failed to update offline session", "err", err)
		return err
	}

	return nil
}

// RevokeClients deletes the refresh tokens issued to the named clients for the
// user/connector pair, in one pass over the offline session. Every other client's
// token is left alone. See RevokeAll for the unscoped variant.
func (rt *RefreshStore) RevokeClients(ctx context.Context, userID, connectorID string, clientIDs []string) {
	if len(clientIDs) == 0 {
		return
	}

	revoking := make(map[string]struct{}, len(clientIDs))
	for _, id := range clientIDs {
		if id != "" {
			revoking[id] = struct{}{}
		}
	}

	rt.revoke(ctx, userID, connectorID, func(id string) bool {
		_, ok := revoking[id]
		return ok
	})
}

// RevokeAll deletes every refresh token for the user/connector pair. This is the
// administrative hammer, reached through the gRPC API when an operator terminates a
// user's sessions or deletes their identity — not something an ordinary RP-initiated
// logout does.
func (rt *RefreshStore) RevokeAll(ctx context.Context, userID, connectorID string) {
	rt.revoke(ctx, userID, connectorID, func(string) bool { return true })
}

// revoke deletes the refresh tokens of every client matching the predicate and
// clears their references in the offline session, keeping the session object.
// Errors are logged but not returned: revocation is best-effort.
//
// To avoid a race where a token issued between the snapshot and the offline
// session update would have its reference wiped, we snapshot the token IDs,
// remove only those references (the updater sees the latest state, so a
// concurrently added reference survives), then delete the tokens.
func (rt *RefreshStore) revoke(ctx context.Context, userID, connectorID string, match func(clientID string) bool) {
	offlineSessions, err := rt.storage.GetOfflineSessions(ctx, userID, connectorID)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			rt.logger.ErrorContext(ctx, "failed to get offline sessions", "err", err)
		}
		return
	}

	tokenIDs := make(map[string]struct{}, len(offlineSessions.Refresh))
	for clientID, ref := range offlineSessions.Refresh {
		if match(clientID) {
			tokenIDs[ref.ID] = struct{}{}
		}
	}

	if len(tokenIDs) == 0 {
		return
	}

	if err := rt.storage.UpdateOfflineSessions(ctx, userID, connectorID, func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
		for clientID, ref := range old.Refresh {
			if _, ok := tokenIDs[ref.ID]; ok {
				delete(old.Refresh, clientID)
			}
		}
		return old, nil
	}); err != nil {
		rt.logger.ErrorContext(ctx, "failed to update offline sessions", "err", err)
	}

	for id := range tokenIDs {
		if err := rt.storage.DeleteRefresh(ctx, id); err != nil && !errors.Is(err, storage.ErrNotFound) {
			rt.logger.ErrorContext(ctx, "failed to delete refresh token", "token_id", id, "err", err)
		}
	}
}
