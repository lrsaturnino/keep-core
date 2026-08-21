package ethereum

import (
	"context"
	"fmt"

	"github.com/keep-network/keep-core/pkg/chain"
)

var _ chain.AuthoritativeClock = (*baseChain)(nil)

func (bc *baseChain) CurrentHeight(ctx context.Context) (uint64, error) {
	if ctx == nil {
		return 0, fmt.Errorf("context is required")
	}
	header, err := bc.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("authoritative head read failed: [%w]", err)
	}
	if header == nil || header.Number == nil {
		return 0, fmt.Errorf("authoritative head read returned empty header")
	}
	return header.Number.Uint64(), nil
}
