package tokens

import (
	"context"
	"log/slog"

	"github.com/dexidp/dex/server/reqctx"
	"github.com/dexidp/dex/storage"
)

// Stable audit event names. Tests and log pipelines can key on these instead of
// localized/human-readable message text.
const (
	AuditEventRotation        = "refresh_token_rotation"
	AuditEventReplay          = "refresh_token_replay"
	AuditEventChainRevoked    = "refresh_chain_revoked"
	AuditEventChainStatusRead = "refresh_chain_status_read"
)

// Audit is the non-secret description of a refresh-chain security event. It is
// deliberately a narrow type: raw refresh, access, ID, and upstream tokens have
// no field here and must never be logged as audit attributes.
type Audit struct {
	Event       string
	ChainID     string
	ClientID    string
	UserID      string
	ConnectorID string
	Generation  int64
	Source      string
	Reason      string
}

// audit emits one structured audit record. Client source address, when present,
// is read from the request context; no token material is accepted.
func (rt *RefreshStore) audit(ctx context.Context, a Audit, level slog.Level) {
	if rt == nil || rt.logger == nil {
		return
	}
	if a.Event == "" {
		a.Event = "refresh_chain_audit"
	}
	if a.Source == "" {
		a.Source = storage.RefreshChainSourceTokenEndpoint
	}

	args := []any{
		"audit", true,
		"event", a.Event,
		"chain_id", a.ChainID,
		"client_id", a.ClientID,
		"user_id", a.UserID,
		"connector_id", a.ConnectorID,
		"generation", a.Generation,
		"source", a.Source,
		"reason", a.Reason,
	}
	if ip, ok := ctx.Value(reqctx.RequestKeyRemoteIP).(string); ok && ip != "" {
		args = append(args,
			"source_ip", ip,
			"remote_ip", ip,
			"client_ip", ip,
		)
	}
	if requestID, ok := ctx.Value(reqctx.RequestKeyRequestID).(string); ok && requestID != "" {
		args = append(args, "request_id", requestID)
	}

	msg := auditMessage(a.Event)
	rt.logger.Log(ctx, level, msg, args...)
}

func auditMessage(event string) string {
	switch event {
	case AuditEventRotation:
		return "refresh token generation rotated"
	case AuditEventReplay:
		return "refresh token replay detected"
	case AuditEventChainRevoked:
		return "refresh chain revoked"
	default:
		return "refresh chain audit event"
	}
}

func auditForChain(chain *storage.RefreshChain, event string, generation int64, source, reason string) Audit {
	a := Audit{Event: event, Generation: generation, Source: source, Reason: reason}
	if chain != nil {
		a.ChainID = chain.ID
		a.ClientID = chain.ClientID
		a.UserID = chain.UserID
		a.ConnectorID = chain.ConnectorID
		if a.Generation == 0 {
			a.Generation = chain.CurrentGeneration
		}
	}
	return a
}
