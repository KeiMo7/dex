package kubernetes

import (
	"time"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/kubernetes/k8sapi"
)

// TokenFamily is the Kubernetes mirror of storage.TokenFamily.
type TokenFamily struct {
	k8sapi.TypeMeta   `json:",inline"`
	k8sapi.ObjectMeta `json:"metadata,omitempty"`

	ClientID    string `json:"clientID"`
	UserID      string `json:"userID"`
	ConnectorID string `json:"connectorID"`

	CreatedAt time.Time `json:"createdAt"`

	RevokedAt         time.Time `json:"revokedAt,omitempty"`
	RevokeReason      string    `json:"revokeReason,omitempty"`
	LastReplayedToken string    `json:"lastReplayedToken,omitempty"`
}

// TokenFamilyList is a list of token families.
type TokenFamilyList struct {
	k8sapi.TypeMeta `json:",inline"`
	k8sapi.ListMeta `json:"metadata,omitempty"`
	TokenFamilies   []TokenFamily `json:"items"`
}

func toStorageTokenFamily(f TokenFamily) storage.TokenFamily {
	return storage.TokenFamily{
		ID:                f.ObjectMeta.Name,
		ClientID:          f.ClientID,
		UserID:            f.UserID,
		ConnectorID:       f.ConnectorID,
		CreatedAt:         f.CreatedAt,
		RevokedAt:         f.RevokedAt,
		RevokeReason:      f.RevokeReason,
		LastReplayedToken: f.LastReplayedToken,
	}
}

func (cli *client) fromStorageTokenFamily(f storage.TokenFamily) TokenFamily {
	return TokenFamily{
		TypeMeta: k8sapi.TypeMeta{
			Kind:       kindTokenFamily,
			APIVersion: cli.apiVersion,
		},
		ObjectMeta: k8sapi.ObjectMeta{
			Name:      f.ID,
			Namespace: cli.namespace,
		},
		ClientID:          f.ClientID,
		UserID:            f.UserID,
		ConnectorID:       f.ConnectorID,
		CreatedAt:         f.CreatedAt,
		RevokedAt:         f.RevokedAt,
		RevokeReason:      f.RevokeReason,
		LastReplayedToken: f.LastReplayedToken,
	}
}

// TokenNode is the Kubernetes mirror of storage.TokenNode.
type TokenNode struct {
	k8sapi.TypeMeta   `json:",inline"`
	k8sapi.ObjectMeta `json:"metadata,omitempty"`

	FamilyID string `json:"familyID"`
	ParentID string `json:"parentID,omitempty"`
	Kind     string `json:"kind"`

	ClientID    string `json:"clientID"`
	UserID      string `json:"userID"`
	ConnectorID string `json:"connectorID"`

	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
	RevokedAt time.Time `json:"revokedAt,omitempty"`
}

// TokenNodeList is a list of token nodes.
type TokenNodeList struct {
	k8sapi.TypeMeta `json:",inline"`
	k8sapi.ListMeta `json:"metadata,omitempty"`
	TokenNodes      []TokenNode `json:"items"`
}

func toStorageTokenNode(n TokenNode) storage.TokenNode {
	return storage.TokenNode{
		ID:          n.ObjectMeta.Name,
		FamilyID:    n.FamilyID,
		ParentID:    n.ParentID,
		Kind:        n.Kind,
		ClientID:    n.ClientID,
		UserID:      n.UserID,
		ConnectorID: n.ConnectorID,
		CreatedAt:   n.CreatedAt,
		ExpiresAt:   n.ExpiresAt,
		RevokedAt:   n.RevokedAt,
	}
}

func (cli *client) fromStorageTokenNode(n storage.TokenNode) TokenNode {
	return TokenNode{
		TypeMeta: k8sapi.TypeMeta{
			Kind:       kindTokenNode,
			APIVersion: cli.apiVersion,
		},
		ObjectMeta: k8sapi.ObjectMeta{
			Name:      n.ID,
			Namespace: cli.namespace,
		},
		FamilyID:    n.FamilyID,
		ParentID:    n.ParentID,
		Kind:        n.Kind,
		ClientID:    n.ClientID,
		UserID:      n.UserID,
		ConnectorID: n.ConnectorID,
		CreatedAt:   n.CreatedAt,
		ExpiresAt:   n.ExpiresAt,
		RevokedAt:   n.RevokedAt,
	}
}
