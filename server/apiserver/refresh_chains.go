package apiserver

import (
	"context"
	"errors"

	"github.com/dexidp/dex/api/v2"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

func toAPIRefreshChain(c storage.RefreshChain) *api.RefreshTokenChain {
	out := &api.RefreshTokenChain{
		Id:                c.ID,
		UserId:            c.UserID,
		ClientId:          c.ClientID,
		ConnectorId:       c.ConnectorID,
		CurrentGeneration: c.CurrentGeneration,
		Status:            c.Status,
		Reason:            c.Reason,
		Source:            c.Source,
		CreatedAt:         unixOrZero(c.CreatedAt),
		UpdatedAt:         unixOrZero(c.UpdatedAt),
		RevokedAt:         unixOrZero(c.RevokedAt),
	}
	for _, g := range c.Generations {
		out.Generations = append(out.Generations, &api.RefreshTokenGeneration{
			Generation: g.Number,
			Status:     g.Status,
			Reason:     g.Reason,
			Source:     g.Source,
			IssuedAt:   unixOrZero(g.IssuedAt),
			ExpiresAt:  unixOrZero(g.ExpiresAt),
			RevokedAt:  unixOrZero(g.RevokedAt),
		})
	}
	return out
}

func resolveUserConnector(userID, connectorID string) (string, string) {
	// Dex's existing admin API passes the ID-token subject: a marshaled
	// IDTokenSubject containing both IDs. Accept that form as well as explicit
	// raw user_id/connector_id fields.
	var subject internal.IDTokenSubject
	if err := internal.Unmarshal(userID, &subject); err == nil && subject.UserId != "" {
		userID = subject.UserId
		if connectorID == "" {
			connectorID = subject.ConnId
		}
	}
	return userID, connectorID
}

func (d dexAPI) GetRefreshChain(ctx context.Context, req *api.GetRefreshChainReq) (*api.GetRefreshChainResp, error) {
	chain, err := d.refresh.GetRefreshChain(ctx, req.GetChainId())
	if errors.Is(err, storage.ErrNotFound) {
		return &api.GetRefreshChainResp{NotFound: true}, nil
	}
	if err != nil {
		d.logger.Error("failed to get refresh chain", "chain_id", req.GetChainId(), "err", err)
		return nil, err
	}
	return &api.GetRefreshChainResp{Chain: toAPIRefreshChain(chain)}, nil
}

func (d dexAPI) RevokeRefreshChain(ctx context.Context, req *api.RevokeRefreshChainReq) (*api.RevokeRefreshChainResp, error) {
	chain, changed, err := d.refresh.RevokeRefreshChain(ctx, req.GetChainId(), storage.RefreshChainSourceAdminAPI, storage.RefreshChainReasonAdmin)
	if errors.Is(err, storage.ErrNotFound) {
		return &api.RevokeRefreshChainResp{NotFound: true}, nil
	}
	if err != nil {
		d.logger.Error("failed to revoke refresh chain", "chain_id", req.GetChainId(), "err", err)
		return nil, err
	}
	return &api.RevokeRefreshChainResp{
		Chain:          toAPIRefreshChain(chain),
		AlreadyRevoked: !changed,
	}, nil
}

func (d dexAPI) RevokeUserRefreshChains(ctx context.Context, req *api.RevokeUserRefreshChainsReq) (*api.RevokeUserRefreshChainsResp, error) {
	userID, connectorID := resolveUserConnector(req.GetUserId(), req.GetConnectorId())
	ids, err := d.refresh.RevokeRefreshChainsByUser(ctx, userID, connectorID, storage.RefreshChainSourceAdminAPI)
	if err != nil {
		d.logger.Error("failed to revoke user refresh chains", "user_id", userID, "connector_id", connectorID, "err", err)
		return nil, err
	}
	resp := &api.RevokeUserRefreshChainsResp{}
	for _, id := range ids {
		chain, getErr := d.refresh.GetRefreshChain(ctx, id)
		if getErr != nil {
			return nil, getErr
		}
		resp.Chains = append(resp.Chains, toAPIRefreshChain(chain))
	}
	return resp, nil
}
