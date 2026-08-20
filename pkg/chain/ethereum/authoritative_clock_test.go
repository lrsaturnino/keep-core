package ethereum

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/keep-network/keep-common/pkg/chain/ethereum/ethutil"
)

type headerByNumberClient struct {
	headerByNumber func(
		ctx context.Context,
		number *big.Int,
	) (*types.Header, error)
}

func (c *headerByNumberClient) HeaderByNumber(
	ctx context.Context,
	number *big.Int,
) (*types.Header, error) {
	return c.headerByNumber(ctx, number)
}

func (c *headerByNumberClient) CodeAt(
	context.Context,
	common.Address,
	*big.Int,
) ([]byte, error) {
	panic("unexpected CodeAt call")
}

func (c *headerByNumberClient) CallContract(
	context.Context,
	ethereum.CallMsg,
	*big.Int,
) ([]byte, error) {
	panic("unexpected CallContract call")
}

func (c *headerByNumberClient) PendingCodeAt(
	context.Context,
	common.Address,
) ([]byte, error) {
	panic("unexpected PendingCodeAt call")
}

func (c *headerByNumberClient) PendingNonceAt(
	context.Context,
	common.Address,
) (uint64, error) {
	panic("unexpected PendingNonceAt call")
}

func (c *headerByNumberClient) SuggestGasPrice(context.Context) (*big.Int, error) {
	panic("unexpected SuggestGasPrice call")
}

func (c *headerByNumberClient) SuggestGasTipCap(context.Context) (*big.Int, error) {
	panic("unexpected SuggestGasTipCap call")
}

func (c *headerByNumberClient) EstimateGas(
	context.Context,
	ethereum.CallMsg,
) (uint64, error) {
	panic("unexpected EstimateGas call")
}

func (c *headerByNumberClient) SendTransaction(
	context.Context,
	*types.Transaction,
) error {
	panic("unexpected SendTransaction call")
}

func (c *headerByNumberClient) FilterLogs(
	context.Context,
	ethereum.FilterQuery,
) ([]types.Log, error) {
	panic("unexpected FilterLogs call")
}

func (c *headerByNumberClient) SubscribeFilterLogs(
	context.Context,
	ethereum.FilterQuery,
	chan<- types.Log,
) (ethereum.Subscription, error) {
	panic("unexpected SubscribeFilterLogs call")
}

func (c *headerByNumberClient) BlockByHash(
	context.Context,
	common.Hash,
) (*types.Block, error) {
	panic("unexpected BlockByHash call")
}

func (c *headerByNumberClient) BlockByNumber(
	context.Context,
	*big.Int,
) (*types.Block, error) {
	panic("unexpected BlockByNumber call")
}

func (c *headerByNumberClient) HeaderByHash(
	context.Context,
	common.Hash,
) (*types.Header, error) {
	panic("unexpected HeaderByHash call")
}

func (c *headerByNumberClient) TransactionCount(
	context.Context,
	common.Hash,
) (uint, error) {
	panic("unexpected TransactionCount call")
}

func (c *headerByNumberClient) TransactionInBlock(
	context.Context,
	common.Hash,
	uint,
) (*types.Transaction, error) {
	panic("unexpected TransactionInBlock call")
}

func (c *headerByNumberClient) SubscribeNewHead(
	context.Context,
	chan<- *types.Header,
) (ethereum.Subscription, error) {
	panic("unexpected SubscribeNewHead call")
}

func (c *headerByNumberClient) TransactionByHash(
	context.Context,
	common.Hash,
) (*types.Transaction, bool, error) {
	panic("unexpected TransactionByHash call")
}

func (c *headerByNumberClient) TransactionReceipt(
	context.Context,
	common.Hash,
) (*types.Receipt, error) {
	panic("unexpected TransactionReceipt call")
}

func (c *headerByNumberClient) SubscribeTransactionReceipts(
	context.Context,
	*ethereum.TransactionReceiptsQuery,
	chan<- []*types.Receipt,
) (ethereum.Subscription, error) {
	panic("unexpected SubscribeTransactionReceipts call")
}

func (c *headerByNumberClient) BalanceAt(
	context.Context,
	common.Address,
	*big.Int,
) (*big.Int, error) {
	panic("unexpected BalanceAt call")
}

var _ ethutil.EthereumClient = (*headerByNumberClient)(nil)
var _ bind.ContractBackend = (*headerByNumberClient)(nil)

func TestBaseChainCurrentHeight_UsesHeaderByNumber(t *testing.T) {
	t.Parallel()

	const expectedHeight = uint64(4242)
	headerByNumberCalled := false

	bc := &baseChain{
		client: &headerByNumberClient{
			headerByNumber: func(
				ctx context.Context,
				number *big.Int,
			) (*types.Header, error) {
				headerByNumberCalled = true
				if ctx == nil {
					t.Fatal("expected non-nil context")
				}
				if number != nil {
					t.Fatalf("expected latest head request, got %v", number)
				}
				return &types.Header{Number: big.NewInt(int64(expectedHeight))}, nil
			},
		},
	}

	height, err := bc.CurrentHeight(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !headerByNumberCalled {
		t.Fatal("expected HeaderByNumber to be called")
	}
	if height != expectedHeight {
		t.Fatalf("expected height %d, got %d", expectedHeight, height)
	}
}

func TestBaseChainCurrentHeight_PropagatesHeaderByNumberError(t *testing.T) {
	t.Parallel()

	rootErr := errors.New("rpc unavailable")
	bc := &baseChain{
		client: &headerByNumberClient{
			headerByNumber: func(
				context.Context,
				*big.Int,
			) (*types.Header, error) {
				return nil, rootErr
			},
		},
	}

	_, err := bc.CurrentHeight(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, rootErr) {
		t.Fatalf("expected wrapped root error, got %v", err)
	}
	if got := err.Error(); got != "authoritative head read failed: [rpc unavailable]" {
		t.Fatalf("unexpected error message: %q", got)
	}
}

func TestBaseChainCurrentHeight_RejectsNilContext(t *testing.T) {
	t.Parallel()

	bc := &baseChain{
		client: &headerByNumberClient{
			headerByNumber: func(
				context.Context,
				*big.Int,
			) (*types.Header, error) {
				t.Fatal("HeaderByNumber must not be called with nil context")
				return nil, nil
			},
		},
	}

	_, err := bc.CurrentHeight(nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got != "context is required" {
		t.Fatalf("unexpected error message: %q", got)
	}
}

func TestBaseChainCurrentHeight_RejectsEmptyHeader(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		header *types.Header
	}{
		"nil header": {
			header: nil,
		},
		"nil header number": {
			header: &types.Header{},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			bc := &baseChain{
				client: &headerByNumberClient{
					headerByNumber: func(
						context.Context,
						*big.Int,
					) (*types.Header, error) {
						return test.header, nil
					},
				},
			}

			_, err := bc.CurrentHeight(context.Background())
			if err == nil {
				t.Fatal("expected error")
			}
			if got := err.Error(); got != "authoritative head read returned empty header" {
				t.Fatalf("unexpected error message: %q", got)
			}
		})
	}
}
