package memory

import (
	"context"

	"github.com/dexidp/dex/storage"
)

// Token family graph implementation for the in-memory backend. Every call runs
// inside memStorage.tx, so the claim-and-flip in the refresh flow is atomic with
// the refresh-token row update under the same mutex.

func (s *memStorage) CreateTokenFamily(ctx context.Context, f storage.TokenFamily) (err error) {
	s.tx(func() {
		if _, ok := s.tokenFamilies[f.ID]; ok {
			err = storage.ErrAlreadyExists
			return
		}
		s.tokenFamilies[f.ID] = f
	})
	return
}

func (s *memStorage) GetTokenFamily(ctx context.Context, id string) (f storage.TokenFamily, err error) {
	s.tx(func() {
		var ok bool
		if f, ok = s.tokenFamilies[id]; !ok {
			err = storage.ErrNotFound
		}
	})
	return
}

func (s *memStorage) UpdateTokenFamily(ctx context.Context, id string, updater func(f storage.TokenFamily) (storage.TokenFamily, error)) (err error) {
	s.tx(func() {
		f, ok := s.tokenFamilies[id]
		if !ok {
			err = storage.ErrNotFound
			return
		}
		if f, err = updater(f); err == nil {
			s.tokenFamilies[id] = f
		}
	})
	return
}

func (s *memStorage) DeleteTokenFamily(ctx context.Context, id string) (err error) {
	s.tx(func() {
		if _, ok := s.tokenFamilies[id]; !ok {
			err = storage.ErrNotFound
			return
		}
		delete(s.tokenFamilies, id)
	})
	return
}

func (s *memStorage) CreateTokenNode(ctx context.Context, n storage.TokenNode) (err error) {
	s.tx(func() {
		if _, ok := s.tokenNodes[n.ID]; ok {
			err = storage.ErrAlreadyExists
			return
		}
		s.tokenNodes[n.ID] = n
	})
	return
}

func (s *memStorage) GetTokenNode(ctx context.Context, id string) (n storage.TokenNode, err error) {
	s.tx(func() {
		var ok bool
		if n, ok = s.tokenNodes[id]; !ok {
			err = storage.ErrNotFound
		}
	})
	return
}

func (s *memStorage) ListTokenNodes(ctx context.Context, familyID string) (nodes []storage.TokenNode, err error) {
	s.tx(func() {
		for _, n := range s.tokenNodes {
			if n.FamilyID == familyID {
				nodes = append(nodes, n)
			}
		}
	})
	return
}

func (s *memStorage) UpdateTokenNode(ctx context.Context, id string, updater func(n storage.TokenNode) (storage.TokenNode, error)) (err error) {
	s.tx(func() {
		n, ok := s.tokenNodes[id]
		if !ok {
			err = storage.ErrNotFound
			return
		}
		if n, err = updater(n); err == nil {
			s.tokenNodes[id] = n
		}
	})
	return
}

func (s *memStorage) DeleteTokenNode(ctx context.Context, id string) (err error) {
	s.tx(func() {
		if _, ok := s.tokenNodes[id]; !ok {
			err = storage.ErrNotFound
			return
		}
		delete(s.tokenNodes, id)
	})
	return
}
