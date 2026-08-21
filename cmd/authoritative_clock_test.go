package cmd

import (
	"context"

	"github.com/keep-network/keep-core/pkg/chain"
)

type authFromCounter struct{ chain.BlockCounter }

func (a authFromCounter) CurrentHeight(context.Context) (uint64, error) {
	return a.CurrentBlock()
}
