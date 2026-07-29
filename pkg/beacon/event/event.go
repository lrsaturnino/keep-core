// Package event contains data structures that are attached to events in the
// relay. Though many of these events are triggered on-chain, that is not an
// inherent requirement of structures in this package.
package event

import (
	"math/big"
)

// RelayEntrySubmitted indicates that valid relay entry has been submitted to
// the chain for the currently processed relay request. This event is intended
// to be used by operators for tracking entry generation and submission progress.
// TODO: Adjust to the v2 RandomBeacon contract.
type RelayEntrySubmitted struct {
	BlockNumber uint64
}

// RelayEntryRequested represents a request for an entry in the threshold relay.
// TODO: Adjust to the v2 RandomBeacon contract.
type RelayEntryRequested struct {
	PreviousEntry  []byte
	GroupPublicKey []byte
	BlockNumber    uint64
}

// RelayEntryTimeoutSettlement is the beacon's own record that a relay request
// was terminated by an accepted timeout report rather than answered by a
// delivered entry.
//
// Every field is read back off the canonical chain, and that is the point.
// A node knows only that it handed a report transaction to a provider; the
// beacon decides whether a penalty exists. Reading the record back binds the
// claim to chain state that outlives the node's view of it: a chain that no
// longer holds these logs cannot produce the record again, so a settlement
// removed by a reorg stops being claimable instead of surviving in a node's
// process memory.
type RelayEntryTimeoutSettlement struct {
	// RequestID is the beacon's own identifier for the terminated request.
	// Together with TerminatedGroupID it names exactly one timeout log.
	RequestID *big.Int
	// TerminatedGroupID is the group the beacon terminated for the timeout.
	TerminatedGroupID uint64
	// RequestBlockNumber is the canonical block the terminated request was
	// made at. It is what binds the settlement to the permit that reported it.
	RequestBlockNumber uint64
	// RequestPreviousEntry is the entry the terminated request was signing
	// over, as the beacon recorded it when the request was made.
	RequestPreviousEntry []byte
	// BlockNumber is the canonical block the beacon recorded the timeout at.
	BlockNumber uint64
	// TransactionHash is the transaction the beacon recorded the timeout in.
	TransactionHash [32]byte
	// ContractAddress is the beacon contract the timeout was read from.
	ContractAddress string
}

// DKGStarted represents a DKG start event.
type DKGStarted struct {
	Seed        *big.Int
	BlockNumber uint64
}

// GroupRegistration represents an event of registering a new group with the
// given public key.
// TODO: Adjust to the v2 RandomBeacon contract and rename to GroupRegistered.
type GroupRegistration struct {
	GroupPublicKey []byte

	BlockNumber uint64
}

// DKGResultSubmission represents a DKG result submission event. It is emitted
// after a submitted DKG result is positively validated on the chain. It contains
// the index of the member who submitted the result and a final public key of
// the group.
// TODO: Adjust to the v2 RandomBeacon contract and rename to DKGResultSubmitted.
type DKGResultSubmission struct {
	MemberIndex    uint32
	GroupPublicKey []byte
	Misbehaved     []uint8

	BlockNumber uint64
}
