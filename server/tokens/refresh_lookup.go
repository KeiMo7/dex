package tokens

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

// Errors a refresh-token lookup can reject a token with. Callers map them to
// their own response: the refresh grant to OAuth2 errors, introspection to an
// inactive-token result.
var (
	ErrRefreshTokenInvalid              = errors.New("refresh token is invalid or has already been claimed")
	ErrRefreshTokenExpired              = errors.New("refresh token expired")
	ErrRefreshTokenClaimedByOtherClient = errors.New("refresh token claimed by another client")
	// ErrRefreshTokenAlreadyUsed is the distinct answer for an obsolete secret
	// whose single grace-period reuse has already been spent by a concurrent
	// request. It is deliberately separate from ErrRefreshTokenInvalid: nothing
	// was leaked, the caller simply lost an in-flight race and should retry with
	// the newest token it holds.
	ErrRefreshTokenAlreadyUsed = errors.New("refresh token has already been used during its rotation grace period")
	// ErrRefreshTokenReplayed means an obsolete secret was presented after its
	// rotation grace period ended — the signature of a leaked token. The whole
	// token family has been revoked by the time this is returned.
	ErrRefreshTokenReplayed = errors.New("refresh token replayed after its rotation grace period")
	// ErrRefreshTokenFamilyRevoked means the token's family was already revoked
	// (by an earlier replay or an administrative action) before this request.
	ErrRefreshTokenFamilyRevoked = errors.New("refresh token family has been revoked")
	// ErrRefreshTokenClaimedTwice is the plain double-claim error raised inside
	// the rotation claim when a secret is neither the current token nor a
	// redeemable obsolete token. It is the family-row equivalent of
	// ErrRefreshTokenInvalid and maps to invalid_grant.
	ErrRefreshTokenClaimedTwice = errors.New("refresh token claimed twice")
)

// LookupRefreshToken validates a refresh token against storage: it exists,
// belongs to clientID when one is given, has not been claimed twice, and has not
// expired per strategy. It returns one of the Err* sentinels for a rejected
// token, or a wrapped storage error for infrastructure failures. Both the
// refresh grant and token introspection use it, so the validation lives in one
// place.
//
// The grace-period reuse and replay decisions are intentionally left to
// RefreshStore.Rotate: they must flip stored state atomically with the claim,
// and a read-only lookup cannot do that. Lookup only rejects what is already
// settled without a write — including a family an earlier replay revoked.
func LookupRefreshToken(ctx context.Context, s storage.Storage, strategy *RefreshStrategy, logger *slog.Logger, clientID *string, token *internal.RefreshToken) (*storage.RefreshToken, error) {
	refresh, err := s.GetRefresh(ctx, token.RefreshId)
	if err != nil {
		if err != storage.ErrNotFound {
			logger.ErrorContext(ctx, "failed to get refresh token", "err", err)
			return nil, fmt.Errorf("get refresh token: %w", err)
		}
		// Usually the token was replaced by a newer login of the same user on the
		// same client, so this is logged at info level, not as an error.
		logger.InfoContext(ctx, "refresh token not found", "token_id", token.RefreshId)
		return nil, ErrRefreshTokenInvalid
	}

	// Only check the client when one was provided (introspection does not).
	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	if clientID != nil && refresh.ClientID != *clientID {
		logger.ErrorContext(ctx, "trying to claim token for different client", "client_id", *clientID, "refresh_client_id", refresh.ClientID)
		return nil, ErrRefreshTokenClaimedByOtherClient
	}

	// A family an earlier replay (or an admin action) revoked stays dead: every
	// token derived from it is refused before any secret comparison. Rows
	// predating family tracking have an empty FamilyID and skip the check, so
	// their behavior is unchanged. A storage failure fails closed — the request
	// is refused rather than allowed through on an unknown revocation state.
	if refresh.FamilyID != "" {
		family, err := s.GetTokenFamily(ctx, refresh.FamilyID)
		if err != nil {
			if err == storage.ErrNotFound {
				// The family record is gone while the row still names it (manual
				// deletion or an unfinished migration). Treat as revoked: refusing
				// is the conservative answer, and Rotate would be unable to record
				// a replay against a missing family anyway.
				logger.ErrorContext(ctx, "refresh token references missing token family", "token_id", refresh.ID, "family_id", refresh.FamilyID)
				return nil, ErrRefreshTokenFamilyRevoked
			}
			logger.ErrorContext(ctx, "failed to get token family", "family_id", refresh.FamilyID, "err", err)
			return nil, fmt.Errorf("get token family: %w", err)
		}
		if !family.RevokedAt.IsZero() {
			logger.WarnContext(ctx, "refresh token belongs to a revoked family",
				"token_id", refresh.ID, "family_id", refresh.FamilyID, "reason", family.RevokeReason)
			return nil, ErrRefreshTokenFamilyRevoked
		}
	}

	// Constant-time comparison of the token secret: introspection reaches this
	// path unauthenticated, so a byte-by-byte '!=' would leak the secret via
	// timing. Matches the client-secret/nonce comparisons elsewhere in the server.
	if subtle.ConstantTimeCompare([]byte(refresh.Token), []byte(token.Token)) != 1 {
		// An obsolete secret that still matches is handed through to Rotate even
		// when its grace window has closed: only the atomic claim there can tell
		// an in-flight reuse from a replay and revoke the family on the latter.
		obsoleteMatch := refresh.ObsoleteToken != "" &&
			subtle.ConstantTimeCompare([]byte(refresh.ObsoleteToken), []byte(token.Token)) == 1
		if !obsoleteMatch {
			logger.ErrorContext(ctx, "refresh token claimed twice", "token_id", refresh.ID)
			return nil, ErrRefreshTokenInvalid
		}
	}

	if strategy.CompletelyExpired(refresh.CreatedAt) {
		logger.ErrorContext(ctx, "refresh token expired", "token_id", refresh.ID)
		return nil, ErrRefreshTokenExpired
	}
	if strategy.ExpiredBecauseUnused(refresh.LastUsed) {
		logger.ErrorContext(ctx, "refresh token expired due to inactivity", "token_id", refresh.ID)
		return nil, ErrRefreshTokenExpired
	}

	return &refresh, nil
}
