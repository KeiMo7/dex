package storage

import (
	"time"
)

// Token node kinds. A refresh-token family is a directed graph stored as an
// adjacency list: every node names its family root and its parent node. The
// family root (a TokenFamily row) carries the single "is this whole family
// revoked" signal, so revoking a family is one atomic root flip followed by a
// node-marking sweep rather than a walk over a flat relationship table.
const (
	// TokenNodeKindRefresh is a refresh-token node. Its ID is the refresh token
	// storage row ID.
	TokenNodeKindRefresh = "refresh"
	// TokenNodeKindAccess is an access-token node. Its ID is the JWT "jti".
	TokenNodeKindAccess = "access"
)

// Replay detection revoke reasons, persisted on the family for audit.
const (
	// RevokeReasonReplay is set when an obsolete refresh token secret is
	// presented after its rotation grace period has ended — the signature of a
	// leaked, replayed token.
	RevokeReasonReplay = "replay"
	// RevokeReasonAdmin is set by administrative revocation (logout, API).
	RevokeReasonAdmin = "admin"
)

// TokenFamily is the root of a refresh-token family graph. One family is created
// the first time a refresh token is issued to a client for a user/connector pair
// and survives every rotation. A non-zero RevokedAt means the whole family is
// dead: every refresh token derived from it is refused and every access token
// minted from it introspects as inactive.
type TokenFamily struct {
	ID string

	ClientID    string
	UserID      string
	ConnectorID string

	CreatedAt time.Time

	// RevokedAt is zero while the family is alive. A replay flips it atomically;
	// once set it is never cleared.
	RevokedAt time.Time
	// RevokeReason is one of the RevokeReason* constants, empty while alive.
	RevokeReason string
	// LastReplayedToken records the refresh token node ID whose reuse triggered
	// the revocation, for the audit trail.
	LastReplayedToken string
}

// TokenNode is one vertex of a token family graph. Refresh nodes track the
// rotation lineage (each rotated token points at the one it replaced); access
// nodes hang off the refresh node they were minted from. Marking a node's
// RevokedAt revokes just that token; a family revocation marks them all.
type TokenNode struct {
	ID string

	// FamilyID names the graph root; ParentID names the node this one was
	// derived from (empty on the family's first refresh node).
	FamilyID string
	ParentID string
	Kind     string

	ClientID    string
	UserID      string
	ConnectorID string

	CreatedAt time.Time
	// ExpiresAt is set on access nodes to the JWT expiry, so GC can drop the
	// revocation record once the token would have died anyway. Zero on refresh
	// nodes.
	ExpiresAt time.Time
	// RevokedAt is zero while the node is usable.
	RevokedAt time.Time
}
