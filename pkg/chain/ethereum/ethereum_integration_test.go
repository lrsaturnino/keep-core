//go:build integration
// +build integration

package ethereum

import (
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/keep-network/keep-common/pkg/chain/ethereum/ethutil"
	"github.com/keep-network/keep-core/internal/testutils"
)

// TODO: Include integration test in the CI.
// To run the tests execute `go test -v -tags=integration ./...`

// ethereumURLEnvVar is the name of the env variable holding the mainnet
// Ethereum JSON-RPC endpoint used by this integration test. The previous
// hardcoded Infura URL was checked into the repository and must be treated
// as compromised; rotate the key on the provider side and inject the new
// URL via this env variable.
const ethereumURLEnvVar = "KEEP_TEST_ETHEREUM_URL"

func TestBaseChain_GetBlockNumberByTimestamp(t *testing.T) {
	ethereumURL := os.Getenv(ethereumURLEnvVar)
	if ethereumURL == "" {
		t.Skipf(
			"skipping: env variable [%s] with Ethereum mainnet JSON-RPC URL is not set",
			ethereumURLEnvVar,
		)
	}

	client, err := ethclient.Dial(ethereumURL)
	if err != nil {
		t.Fatal(err)
	}

	blockCounter, err := ethutil.NewBlockCounter(client)
	if err != nil {
		t.Fatal(err)
	}

	// Initialize the baseChain with fields required by this scenario.
	bc := &baseChain{
		client:       client,
		blockCounter: blockCounter,
	}

	var tests = map[string]struct {
		timestamp           uint64
		expectedBlockNumber uint64
		expectedError       error
	}{
		"there is a block at the requested timestamp": {
			timestamp:           1681982135, // 20 April 2023 09:15:35
			expectedBlockNumber: 17086765,
		},
		"there is a block just after the requested timestamp": {
			timestamp:           1681982133, // 20 April 2023 09:15:33
			expectedBlockNumber: 17086765,
		},
		"there is a block just before the requested timestamp": {
			timestamp:           1681982125, // 20 April 2023 09:15:25
			expectedBlockNumber: 17086764,
		},
		"there are two blocks with equal distance to the requested timestamp": {
			timestamp:           1681982129, // 20 April 2023 09:15:29
			expectedBlockNumber: 17086765,
		},
		"the requested timestamp is in the future": {
			timestamp:     uint64(time.Now().Add(1 * time.Hour).Unix()),
			expectedError: fmt.Errorf("requested timestamp is in the future"),
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			blockNumber, err := bc.GetBlockNumberByTimestamp(test.timestamp)

			if !reflect.DeepEqual(err, test.expectedError) {
				t.Errorf(
					"unexpected error\nexpected: [%v]\nactual:   [%v]\n",
					test.expectedError,
					err,
				)
			}

			testutils.AssertIntsEqual(
				t,
				"block number",
				int(test.expectedBlockNumber),
				int(blockNumber),
			)
		})
	}
}
