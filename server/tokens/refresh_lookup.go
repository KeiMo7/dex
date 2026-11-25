package tokens

import (
	"context"
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

	// ErrRefreshTokenReplayed means a recognized older generation was presented
	// outside its idempotency window. The refresh store atomically revokes the
	// whole chain when it commits that decision.
	ErrRefreshTokenReplayed = errors.New("refresh token generation replayed")
	// ErrRefreshChainRevoked means the chain was already revoked by replay or an
	// administrator.
	ErrRefreshChainRevoked = errors.New("refresh token chain revoked")
	// ErrRefreshTokenSuperseded means another concurrent request won the atomic
	// generation update and the caller did not receive the idempotent result.
	ErrRefreshTokenSuperseded = errors.New("refresh token generation superseded by another request")
	// ErrRefreshChainUnavailable means chain state could not be read or written.
	// Callers fail closed rather than returning a partially valid chain.
	ErrRefreshChainUnavailable = errors.New("refresh token chain state unavailable")

	// Compatibility aliases for callers/tests using slightly different names.
	ErrRefreshTokenReplay        = ErrRefreshTokenReplayed
	ErrReplayDetected            = ErrRefreshTokenReplayed
	ErrTokenReplayed             = ErrRefreshTokenReplayed
	ErrRefreshTokenAlreadyUsed   = ErrRefreshTokenSuperseded
	ErrRefreshTokenClaimedTwice  = ErrRefreshTokenSuperseded
	ErrRefreshTokenSupersededBy  = ErrRefreshTokenSuperseded
	ErrRefreshChainUnavailableOp = ErrRefreshChainUnavailable
	ErrRefreshTokenChainRevoked  = ErrRefreshChainRevoked
	ErrChainRevoked              = ErrRefreshChainRevoked
	ErrRefreshTokenFamilyRevoked = ErrRefreshChainRevoked
)

// ReplayCandidateError is returned by LookupRefreshToken when a recognized old
// generation is outside its reuse window. It carries the live row so the grant
// can perform the atomic chain-revocation step instead of losing the evidence.
type ReplayCandidateError struct {
	Refresh    *storage.RefreshToken
	Generation int64
	Err        error
}

func (e *ReplayCandidateError) Error() string {
	if e == nil || e.Err == nil {
		return ErrRefreshTokenReplayed.Error()
	}
	return e.Err.Error()
}

func (e *ReplayCandidateError) Unwrap() error {
	if e == nil || e.Err == nil {
		return ErrRefreshTokenReplayed
	}
	return e.Err
}

// LookupRefreshToken validates a refresh token against storage: it exists,
// belongs to clientID when one is given, has not been claimed twice, and has not
// expired per strategy. It returns one of the Err* sentinels for a rejected
// token, or a wrapped storage error for infrastructure failures. Both the
// refresh grant and token introspection use it, so the validation lives in one
// place.
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

	// Expiry is evaluated before secret/replay classification. Presenting an
	// expired generation must only produce ErrRefreshTokenExpired; it must not
	// create a replay audit event or revoke the chain.
	if strategy.CompletelyExpired(refresh.CreatedAt) {
		logger.InfoContext(ctx, "refresh token expired", "token_id", refresh.ID)
		return nil, ErrRefreshTokenExpired
	}
	if strategy.ExpiredBecauseUnused(refresh.LastUsed) {
		logger.InfoContext(ctx, "refresh token expired due to inactivity", "token_id", refresh.ID)
		return nil, ErrRefreshTokenExpired
	}

	if refresh.Chain.IsRevoked() {
		logger.WarnContext(ctx, "refresh token chain is revoked", "token_id", refresh.ID)
		return &refresh, ErrRefreshChainRevoked
	}

	// Normalize the in-memory view so legacy rows and durable generation history
	// use the same matching code. This does not write storage; the refresh claim
	// atomically adopts the row if it is used.
	refresh = normalizeRefreshChain(refresh, strategy.currentTime())
	match := matchRefreshSecret(refresh, token.Token)
	if !match.found {
		logger.InfoContext(ctx, "refresh token generation not found", "token_id", refresh.ID)
		return nil, ErrRefreshTokenInvalid
	}

	// Non-current generations are idempotent retries inside the reuse window.
	// Outside it, hand the live row to Rotate so the replay decision and chain
	// revocation commit atomically.
	if !match.current && !strategy.AllowedToReuse(refresh.LastUsed) {
		return &refresh, &ReplayCandidateError{
			Refresh:    &refresh,
			Generation: match.generation,
		}
	}

	return &refresh, nil
}
