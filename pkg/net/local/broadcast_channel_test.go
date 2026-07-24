package local

import (
	"context"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keep-network/keep-core/pkg/operator"

	"github.com/keep-network/keep-core/internal/testutils"
	"github.com/keep-network/keep-core/pkg/net"
)

func TestRegisterAndFireHandler(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, localChannel, err := initTestChannel("channel name")
	if err != nil {
		t.Fatal(err)
	}

	handlerFiredChan := make(chan struct{})
	localChannel.Recv(ctx, func(msg net.Message) {
		handlerFiredChan <- struct{}{}
	})

	localChannel.Send(ctx, &mockNetMessage{})

	select {
	case <-handlerFiredChan:
		return
	case <-ctx.Done():
		t.Errorf("Expected handler not called")
	}
}

func TestUnregisterHandler(t *testing.T) {
	tests := map[string]struct {
		handlersRegistered   []string
		handlersUnregistered []string
		handlersFired        []string
	}{
		"unregister the first registered handler": {
			handlersRegistered:   []string{"a", "b", "c"},
			handlersUnregistered: []string{"a"},
			handlersFired:        []string{"b", "c"},
		},
		"unregister the last registered handler": {
			handlersRegistered:   []string{"a", "b", "c"},
			handlersUnregistered: []string{"c"},
			handlersFired:        []string{"a", "b"},
		},
		"unregister handler registered in the middle": {
			handlersRegistered:   []string{"a", "b", "c"},
			handlersUnregistered: []string{"b"},
			handlersFired:        []string{"a", "c"},
		},
		"unregister various handlers": {
			handlersRegistered:   []string{"a", "b", "c", "d", "e", "f", "g"},
			handlersUnregistered: []string{"a", "c", "f", "g"},
			handlersFired:        []string{"b", "d", "e"},
		},
		"unregister all handlers": {
			handlersRegistered:   []string{"a", "b", "c"},
			handlersUnregistered: []string{"a", "b", "c"},
			handlersFired:        []string{},
		},
	}

	for testName, test := range tests {
		test := test
		t.Run(testName, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			_, localChannel, err := initTestChannel("channel name")
			if err != nil {
				t.Fatal(err)
			}

			handlersFiredMutex := &sync.Mutex{}
			handlersFired := []string{}

			handlerCancellations := map[string]context.CancelFunc{}

			// Register all handlers. If the handler is called, append its
			// name to `handlersFired` slice.
			for _, handlerName := range test.handlersRegistered {
				handlerName := handlerName

				handlerCtx, cancel := context.WithCancel(ctx)
				defer cancel()

				handlerCancellations[handlerName] = cancel

				localChannel.Recv(handlerCtx, func(msg net.Message) {
					handlersFiredMutex.Lock()
					handlersFired = append(handlersFired, handlerName)
					handlersFiredMutex.Unlock()
				})
			}

			// Cancel the specified handlers
			for _, handlerName := range test.handlersUnregistered {
				handlerCancellations[handlerName]()
			}

			// Send a message, all handlers should be called
			localChannel.Send(ctx, &mockNetMessage{})

			// Handlers are fired asynchronously; wait for them
			time.Sleep(500 * time.Millisecond)

			// Read under the same mutex the handlers write under, taking a
			// snapshot so the comparison cannot race a still-firing handler.
			handlersFiredMutex.Lock()
			firedSnapshot := make([]string, len(handlersFired))
			copy(firedSnapshot, handlersFired)
			handlersFiredMutex.Unlock()

			sort.Strings(firedSnapshot)
			if !reflect.DeepEqual(test.handlersFired, firedSnapshot) {
				t.Errorf(
					"Unexpected handlers fired\nExpected: %v\nActual:   %v\n",
					test.handlersFired,
					firedSnapshot,
				)
			}
		})
	}
}

func TestUnregisterWhenHandling(t *testing.T) {
	_, channel, err := initTestChannel("channel name")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// receivedCount is written by the Recv handler goroutine and read by the
	// main goroutine, so it is accessed atomically to avoid a data race.
	var receivedCount atomic.Int64
	stopAt := int64(90)

	channel.Recv(ctx, func(msg net.Message) {
		if receivedCount.Add(1) == stopAt {
			cancel()
		}
	})

	go func() {
		for i := 0; i < 300; i++ {
			channel.Send(ctx, &mockNetMessage{})
		}
	}()

	time.Sleep(500 * time.Millisecond)

	if final := receivedCount.Load(); final != stopAt {
		t.Fatalf("received more than expected: [%v]", final)
	}
}
func TestSendAndDeliver(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	msgToSend := &mockNetMessage{}

	channelName := "channel name"

	operatorPublicKey1, localChannel1, err := initTestChannel(channelName)
	if err != nil {
		t.Fatal(err)
	}
	_, localChannel2, err := initTestChannel(channelName)
	if err != nil {
		t.Fatal(err)
	}
	_, localChannel3, err := initTestChannel(channelName)
	if err != nil {
		t.Fatal(err)
	}

	// Register handlers.
	inMsgChan := make(chan net.Message, 3)

	msgHandler := func(msg net.Message) {
		inMsgChan <- msg
	}

	localChannel1.Recv(ctx, msgHandler)
	localChannel2.Recv(ctx, msgHandler)
	localChannel3.Recv(ctx, msgHandler)

	// Broadcast message by the first peer.
	if err := localChannel1.Send(ctx, msgToSend); err != nil {
		t.Fatalf("failed to send message: [%v]", err)
	}

	deliveredMessages := []net.Message{}

loop:
	for {
		select {
		case msg := <-inMsgChan:
			deliveredMessages = append(deliveredMessages, msg)
		case <-ctx.Done():
			break loop
		}
	}

	if len(deliveredMessages) != 3 {
		t.Errorf("unexpected number of delivered messages: [%d]", len(deliveredMessages))
	}

	for _, msg := range deliveredMessages {
		if !reflect.DeepEqual(msgToSend, msg.Payload()) {
			t.Errorf(
				"invalid payload\nexpected: [%+v]\nactual:   [%+v]\n",
				msgToSend,
				msg.Payload(),
			)
		}
		if msg.Type() != mockNetMessageType {
			t.Errorf(
				"invalid type\nexpected: [%+v]\nactual:   [%+v]\n",
				"local",
				msg.Type(),
			)
		}

		operatorPublicKey1Bytes := operator.MarshalUncompressed(operatorPublicKey1)

		testutils.AssertBytesEqual(t, operatorPublicKey1Bytes, msg.SenderPublicKey())
	}
}

func initTestChannel(channelName string) (*operator.PublicKey, net.BroadcastChannel, error) {
	_, operatorPublicKey, err := operator.GenerateKeyPair(DefaultCurve)
	if err != nil {
		return nil, nil, err
	}

	provider := ConnectWithKey(operatorPublicKey)
	localChannel, err := provider.BroadcastChannelFor(channelName)
	if err != nil {
		return nil, nil, err
	}

	localChannel.SetUnmarshaler(func() net.TaggedUnmarshaler {
		return &mockNetMessage{}
	})

	return operatorPublicKey, localChannel, nil
}

const mockNetMessageType = "mock_message"

type mockNetMessage struct{}

func (mm *mockNetMessage) Type() string {
	return mockNetMessageType
}

func (mm *mockNetMessage) Marshal() ([]byte, error) {
	return []byte("some mocked bytes"), nil
}

func (mm *mockNetMessage) Unmarshal(bytes []byte) error {
	return nil
}
