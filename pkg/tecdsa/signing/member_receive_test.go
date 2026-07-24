package signing

import (
	"context"
	"errors"
	"testing"

	tsslibcommon "github.com/bnb-chain/tss-lib/common"
)

// newFinalizingMemberWithResultChan builds the minimal embedded-struct chain
// required to exercise receiveTSSResult in isolation. receiveTSSResult reads
// only the promoted tssResultChan field (defined on tssRoundOneMember), so the
// rest of the chain is left zero-valued on purpose.
func newFinalizingMemberWithResultChan(
	ch <-chan tsslibcommon.SignatureData,
) *finalizingMember {
	return &finalizingMember{
		tssRoundNineMember: &tssRoundNineMember{
			tssRoundEightMember: &tssRoundEightMember{
				tssRoundSevenMember: &tssRoundSevenMember{
					tssRoundSixMember: &tssRoundSixMember{
						tssRoundFiveMember: &tssRoundFiveMember{
							tssRoundFourMember: &tssRoundFourMember{
								tssRoundThreeMember: &tssRoundThreeMember{
									tssRoundTwoMember: &tssRoundTwoMember{
										tssRoundOneMember: &tssRoundOneMember{
											tssResultChan: ch,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestReceiveFromChannel_DeliversValue(t *testing.T) {
	ch := make(chan int, 1)
	ch <- 42

	value, ok, err := receiveFromChannel(context.Background(), ch)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if !ok {
		t.Fatal("expected ok to be true for a delivered value")
	}
	if value != 42 {
		t.Fatalf("expected value 42, got [%v]", value)
	}
}

func TestReceiveFromChannel_ContextCancelled(t *testing.T) {
	ch := make(chan int) // never delivers

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	value, ok, err := receiveFromChannel(ctx, ch)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled error, got [%v]", err)
	}
	if ok {
		t.Fatal("expected ok to be false when the context is cancelled")
	}
	if value != 0 {
		t.Fatalf("expected zero value, got [%v]", value)
	}
}

func TestReceiveFromChannel_ChannelClosed(t *testing.T) {
	ch := make(chan int)
	close(ch)

	value, ok, err := receiveFromChannel(context.Background(), ch)
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if ok {
		t.Fatal("expected ok to be false for a closed channel")
	}
	if value != 0 {
		t.Fatalf("expected zero value from a closed channel, got [%v]", value)
	}
}

func TestReceiveTSSResult_DeliversSignature(t *testing.T) {
	ch := make(chan tsslibcommon.SignatureData, 1)
	// Seed the channel with a composite literal so no existing lock-bearing
	// value is copied by the test itself.
	ch <- tsslibcommon.SignatureData{
		Signature:         []byte{0xaa, 0xbb},
		SignatureRecovery: []byte{0x01},
		R:                 []byte{0x11, 0x22},
		S:                 []byte{0x33, 0x44},
		M:                 []byte{0x55},
	}

	fm := newFinalizingMemberWithResultChan(ch)

	result, err := fm.receiveTSSResult(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: [%v]", err)
	}
	if result == nil {
		t.Fatal("expected a non-nil result")
	}

	assertBytesEqual(t, "Signature", result.GetSignature(), []byte{0xaa, 0xbb})
	assertBytesEqual(t, "SignatureRecovery", result.GetSignatureRecovery(), []byte{0x01})
	assertBytesEqual(t, "R", result.GetR(), []byte{0x11, 0x22})
	assertBytesEqual(t, "S", result.GetS(), []byte{0x33, 0x44})
	assertBytesEqual(t, "M", result.GetM(), []byte{0x55})
}

func TestReceiveTSSResult_ContextCancelled(t *testing.T) {
	ch := make(chan tsslibcommon.SignatureData) // never delivers

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fm := newFinalizingMemberWithResultChan(ch)

	result, err := fm.receiveTSSResult(ctx)
	if result != nil {
		t.Fatalf("expected nil result on cancellation, got [%v]", result)
	}
	if err == nil || err.Error() != "TSS result was not generated on time" {
		t.Fatalf("expected 'not generated on time' error, got [%v]", err)
	}
}

func TestReceiveTSSResult_ChannelClosed(t *testing.T) {
	ch := make(chan tsslibcommon.SignatureData)
	close(ch)

	fm := newFinalizingMemberWithResultChan(ch)

	result, err := fm.receiveTSSResult(context.Background())
	if result != nil {
		t.Fatalf("expected nil result on channel closure, got [%v]", result)
	}
	if err == nil || err.Error() != "TSS result channel was closed unexpectedly" {
		t.Fatalf("expected 'channel was closed unexpectedly' error, got [%v]", err)
	}
}

func assertBytesEqual(t *testing.T, field string, actual, expected []byte) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("%s: expected % x, got % x", field, expected, actual)
	}
	for i := range expected {
		if actual[i] != expected[i] {
			t.Fatalf("%s: expected % x, got % x", field, expected, actual)
		}
	}
}
