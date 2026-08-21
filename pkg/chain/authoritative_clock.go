package chain

import "context"

// AuthoritativeClock returns the chain head via a bounded direct RPC.
// Implementations must not consult a subscription-fed block-height cache.
type AuthoritativeClock interface {
	CurrentHeight(ctx context.Context) (uint64, error)
}
