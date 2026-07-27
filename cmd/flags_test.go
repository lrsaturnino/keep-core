package cmd

import (
	"bufio"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"

	commonEthereum "github.com/keep-network/keep-common/pkg/chain/ethereum"
	"github.com/keep-network/keep-core/config"
	chainEthereum "github.com/keep-network/keep-core/pkg/chain/ethereum"
	ethereumBeacon "github.com/keep-network/keep-core/pkg/chain/ethereum/beacon/gen"
	ethereumEcdsa "github.com/keep-network/keep-core/pkg/chain/ethereum/ecdsa/gen"
	ethereumTbtc "github.com/keep-network/keep-core/pkg/chain/ethereum/tbtc/gen"
	ethereumThreshold "github.com/keep-network/keep-core/pkg/chain/ethereum/threshold/gen"
	"github.com/keep-network/keep-core/pkg/protocol/participation"
)

var cmdFlagsTests = map[string]struct {
	readValueFunc func(*config.Config) interface{}
	flagName      string
	flagValue     string
	// We provide arguments for flags in `flagValue` as strings, that are unmarshaled
	// to a Config specific types.
	expectedValueFromFlag interface{}
	defaultValue          interface{}
}{
	"ethereum.url": {
		readValueFunc: func(c *config.Config) interface{} { return c.Ethereum.URL },
		flagName:      "--ethereum.url",
		flagValue:     "https://eth-provider.com/mainnet",
		defaultValue:  "",
	},
	"ethereum.keyFile": {
		readValueFunc: func(c *config.Config) interface{} { return c.Ethereum.Account.KeyFile },
		flagName:      "--ethereum.keyFile",
		flagValue:     "/tmp/UTC--2018-03-11T01-37-33.202765887Z--c2a56884538778bacd91aa5bf343bf882c5fb18b",
		defaultValue:  "",
	},
	"ethereum.miningCheckInterval": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Ethereum.MiningCheckInterval },
		flagName:              "--ethereum.miningCheckInterval",
		flagValue:             "1m45s",
		expectedValueFromFlag: 105 * time.Second,
		defaultValue:          60 * time.Second,
	},
	"ethereum.requestPerSecondLimit": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Ethereum.RequestsPerSecondLimit },
		flagName:              "--ethereum.requestPerSecondLimit",
		flagValue:             "38",
		expectedValueFromFlag: 38,
		defaultValue:          150,
	},
	"ethereum.concurrencyLimit": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Ethereum.ConcurrencyLimit },
		flagName:              "--ethereum.concurrencyLimit",
		flagValue:             "105",
		expectedValueFromFlag: 105,
		defaultValue:          30,
	},
	"ethereum.maxGasFeeCap": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Ethereum.MaxGasFeeCap.Int },
		flagName:              "--ethereum.maxGasFeeCap",
		flagValue:             "65.8 Gwei",
		expectedValueFromFlag: big.NewInt(65800000000),
		defaultValue:          big.NewInt(500000000000),
	},
	"ethereum.balanceAlertThreshold": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Ethereum.BalanceAlertThreshold.Int },
		flagName:              "--ethereum.balanceAlertThreshold",
		flagValue:             "1.25 ether",
		expectedValueFromFlag: big.NewInt(1250000000000000000),
		defaultValue:          big.NewInt(500000000000000000),
	},
	"bitcoin.electrum.url": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Bitcoin.Electrum.URL },
		flagName:              "--bitcoin.electrum.url",
		flagValue:             "tcp://url.to.electrum:18332",
		expectedValueFromFlag: "tcp://url.to.electrum:18332",
		defaultValue:          "",
	},
	"bitcoin.electrum.connectTimeout": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Bitcoin.Electrum.ConnectTimeout },
		flagName:              "--bitcoin.electrum.connectTimeout",
		flagValue:             "5m45s",
		expectedValueFromFlag: 345 * time.Second,
		defaultValue:          10 * time.Second,
	},
	"bitcoin.electrum.connectRetryTimeout": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Bitcoin.Electrum.ConnectRetryTimeout },
		flagName:              "--bitcoin.electrum.connectRetryTimeout",
		flagValue:             "124s",
		expectedValueFromFlag: 124 * time.Second,
		defaultValue:          60 * time.Second,
	},
	"bitcoin.electrum.requestTimeout": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Bitcoin.Electrum.RequestTimeout },
		flagName:              "--bitcoin.electrum.requestTimeout",
		flagValue:             "43s",
		expectedValueFromFlag: 43 * time.Second,
		defaultValue:          30 * time.Second,
	},
	"bitcoin.electrum.requestRetryTimeout": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Bitcoin.Electrum.RequestRetryTimeout },
		flagName:              "--bitcoin.electrum.requestRetryTimeout",
		flagValue:             "10m",
		expectedValueFromFlag: 600 * time.Second,
		defaultValue:          120 * time.Second,
	},
	"bitcoin.electrum.keepAliveInterval": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Bitcoin.Electrum.KeepAliveInterval },
		flagName:              "--bitcoin.electrum.keepAliveInterval",
		flagValue:             "11m",
		expectedValueFromFlag: 660 * time.Second,
		defaultValue:          300 * time.Second,
	},
	"network.bootstrap": {
		readValueFunc:         func(c *config.Config) interface{} { return c.LibP2P.Bootstrap },
		flagName:              "--network.bootstrap",
		flagValue:             "true",
		expectedValueFromFlag: true,
		defaultValue:          false,
	},
	"network.port": {
		readValueFunc:         func(c *config.Config) interface{} { return c.LibP2P.Port },
		flagName:              "--network.port",
		flagValue:             "78690",
		expectedValueFromFlag: 78690,
		defaultValue:          3919,
	},
	"network.peers": {
		readValueFunc: func(c *config.Config) interface{} { return c.LibP2P.Peers },
		flagName:      "--network.peers",
		flagValue:     `"/ip4/127.0.0.1/tcp/5001/ipfs/3w6C4TFVo","/dns4/domain.local/tcp/3819/ipfs/16xtuKXdTd"`,
		expectedValueFromFlag: []string{
			"/ip4/127.0.0.1/tcp/5001/ipfs/3w6C4TFVo",
			"/dns4/domain.local/tcp/3819/ipfs/16xtuKXdTd",
		},
		defaultValue: readPeers(commonEthereum.Mainnet),
	},
	"network.announcedAddresses": {
		readValueFunc: func(c *config.Config) interface{} { return c.LibP2P.AnnouncedAddresses },
		flagName:      "--network.announcedAddresses",
		flagValue:     `"/dns4/boar.network/tcp/4200","/ip4/80.70.69.15/tcp/4201"`,
		expectedValueFromFlag: []string{
			"/dns4/boar.network/tcp/4200",
			"/ip4/80.70.69.15/tcp/4201",
		},
		defaultValue: []string{},
	},
	"network.disseminationTime": {
		readValueFunc:         func(c *config.Config) interface{} { return c.LibP2P.DisseminationTime },
		flagName:              "--network.disseminationTime",
		flagValue:             "486",
		expectedValueFromFlag: 486,
		defaultValue:          0,
	},
	"storage.dir": {
		readValueFunc: func(c *config.Config) interface{} { return c.Storage.Dir },
		flagName:      "--storage.dir",
		flagValue:     "./flagged/location/dude",
		defaultValue:  "",
	},
	"clientInfo.port": {
		readValueFunc:         func(c *config.Config) interface{} { return c.ClientInfo.Port },
		flagName:              "--clientInfo.port",
		flagValue:             "9870",
		expectedValueFromFlag: 9870,
		defaultValue:          9601,
	},
	"clientInfo.networkMetricsTick": {
		readValueFunc:         func(c *config.Config) interface{} { return c.ClientInfo.NetworkMetricsTick },
		flagName:              "--clientInfo.networkMetricsTick",
		flagValue:             "3m9s",
		expectedValueFromFlag: 189 * time.Second,
		defaultValue:          1 * time.Minute,
	},
	"clientInfo.ethereumMetricsTick": {
		readValueFunc:         func(c *config.Config) interface{} { return c.ClientInfo.EthereumMetricsTick },
		flagName:              "--clientInfo.ethereumMetricsTick",
		flagValue:             "1m16s",
		expectedValueFromFlag: 76 * time.Second,
		defaultValue:          10 * time.Minute,
	},
	"tbtc.preParamsPoolSize": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Tbtc.PreParamsPoolSize },
		flagName:              "--tbtc.preParamsPoolSize",
		flagValue:             "75",
		expectedValueFromFlag: 75,
		defaultValue:          1000,
	},
	"tbtc.preParamsGenerationTimeout": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Tbtc.PreParamsGenerationTimeout },
		flagName:              "--tbtc.preParamsGenerationTimeout",
		flagValue:             "2m30s",
		expectedValueFromFlag: 150 * time.Second,
		defaultValue:          120 * time.Second,
	},
	"tbtc.preParamsGenerationDelay": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Tbtc.PreParamsGenerationDelay },
		flagName:              "--tbtc.preParamsGenerationDelay",
		flagValue:             "1m",
		expectedValueFromFlag: 60 * time.Second,
		defaultValue:          10 * time.Second,
	},
	"tbtc.preParamsGenerationConcurrency": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Tbtc.PreParamsGenerationConcurrency },
		flagName:              "--tbtc.preParamsGenerationConcurrency",
		flagValue:             "2",
		expectedValueFromFlag: 2,
		defaultValue:          1,
	},
	"tbtc.keyGenerationConcurrency": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Tbtc.KeyGenerationConcurrency },
		flagName:              "--tbtc.keyGenerationConcurrency",
		flagValue:             "101",
		expectedValueFromFlag: 101,
		defaultValue:          runtime.GOMAXPROCS(0),
	},
	"maintainer.bitcoinDifficulty": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Maintainer.BitcoinDifficulty.Enabled },
		flagName:              "--bitcoinDifficulty",
		flagValue:             "", // don't provide any value
		expectedValueFromFlag: true,
		defaultValue:          false,
	},
	"maintainer.bitcoinDifficulty.disableProxy": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Maintainer.BitcoinDifficulty.DisableProxy },
		flagName:              "--bitcoinDifficulty.disableProxy",
		flagValue:             "", // don't provide any value
		expectedValueFromFlag: true,
		defaultValue:          false,
	},
	"maintainer.bitcoinDifficulty.idleOnPreflightFailure": {
		readValueFunc: func(c *config.Config) interface{} {
			return c.Maintainer.BitcoinDifficulty.IdleOnPreflightFailure
		},
		flagName:              "--bitcoinDifficulty.idleOnPreflightFailure",
		flagValue:             "",
		expectedValueFromFlag: true,
		defaultValue:          false,
	},
	"maintainer.spv": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Maintainer.Spv.Enabled },
		flagName:              "--spv",
		flagValue:             "", // don't provide any value
		expectedValueFromFlag: true,
		defaultValue:          false,
	},
	"maintainer.spv.historyDepth": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Maintainer.Spv.HistoryDepth },
		flagName:              "--spv.historyDepth",
		flagValue:             "200000",
		expectedValueFromFlag: uint64(200000),
		defaultValue:          uint64(50400),
	},
	"maintainer.spv.transactionLimit": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Maintainer.Spv.TransactionLimit },
		flagName:              "--spv.transactionLimit",
		flagValue:             "5",
		expectedValueFromFlag: 5,
		defaultValue:          20,
	},
	"maintainer.spv.restartBackoffTime": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Maintainer.Spv.RestartBackoffTime },
		flagName:              "--spv.restartBackoffTime",
		flagValue:             "1h",
		expectedValueFromFlag: time.Hour,
		defaultValue:          30 * time.Minute,
	},
	"maintainer.spv.idleBackoffTime": {
		readValueFunc:         func(c *config.Config) interface{} { return c.Maintainer.Spv.IdleBackoffTime },
		flagName:              "--spv.idleBackoffTime",
		flagValue:             "20m",
		expectedValueFromFlag: 20 * time.Minute,
		defaultValue:          10 * time.Minute,
	},
	"developer.randomBeaconAddress": {
		readValueFunc: func(c *config.Config) interface{} {
			address, _ := c.Ethereum.ContractAddress(chainEthereum.RandomBeaconContractName)
			return address
		},
		flagName:              "--developer.randomBeaconAddress",
		flagValue:             "0x3b292d36468bc7fd481987818ef2e4d28202a0ed",
		expectedValueFromFlag: common.HexToAddress("0x3B292D36468bC7fd481987818ef2E4d28202A0eD"),
		defaultValue:          common.HexToAddress(ethereumBeacon.RandomBeaconAddress),
	},
	"developer.walletRegistryAddress": {
		readValueFunc: func(c *config.Config) interface{} {
			address, _ := c.Ethereum.ContractAddress(chainEthereum.WalletRegistryContractName)
			return address
		},
		flagName:              "--developer.walletRegistryAddress",
		flagValue:             "0xb76707515c3f908411b5211863a7581589a1e31f",
		expectedValueFromFlag: common.HexToAddress("0xB76707515C3f908411B5211863A7581589a1E31F"),
		defaultValue:          common.HexToAddress(ethereumEcdsa.WalletRegistryAddress),
	},
	"developer.bridgeAddress": {
		readValueFunc: func(c *config.Config) interface{} {
			address, _ := c.Ethereum.ContractAddress(chainEthereum.BridgeContractName)
			return address
		},
		flagName:              "--developer.bridgeAddress",
		flagValue:             "0xd21DE06574811450E722a33D8093558E8c04eacc",
		expectedValueFromFlag: common.HexToAddress("0xd21DE06574811450E722a33D8093558E8c04eacc"),
		defaultValue:          common.HexToAddress(ethereumTbtc.BridgeAddress),
	},
	"developer.maintainerProxyAddress": {
		readValueFunc: func(c *config.Config) interface{} {
			address, _ := c.Ethereum.ContractAddress(chainEthereum.MaintainerProxyContractName)
			return address
		},
		flagName:              "--developer.maintainerProxyAddress",
		flagValue:             "0xC6D21c2871586A2B098c0ad043fF0D47a3c7e7ae",
		expectedValueFromFlag: common.HexToAddress("0xC6D21c2871586A2B098c0ad043fF0D47a3c7e7ae"),
		defaultValue:          common.HexToAddress(ethereumTbtc.MaintainerProxyAddress),
	},
	"developer.lightRelayAddress": {
		readValueFunc: func(c *config.Config) interface{} {
			address, _ := c.Ethereum.ContractAddress(chainEthereum.LightRelayContractName)
			return address
		},
		flagName:              "--developer.lightRelayAddress",
		flagValue:             "0x68e20afD773fDF1231B5cbFeA7040e73e79cAc36",
		expectedValueFromFlag: common.HexToAddress("0x68e20afD773fDF1231B5cbFeA7040e73e79cAc36"),
		defaultValue:          common.HexToAddress(ethereumTbtc.LightRelayAddress),
	},
	"developer.lightRelayMaintainerProxyAddress": {
		readValueFunc: func(c *config.Config) interface{} {
			address, _ := c.Ethereum.ContractAddress(chainEthereum.LightRelayMaintainerProxyContractName)
			return address
		},
		flagName:              "--developer.lightRelayMaintainerProxyAddress",
		flagValue:             "0x30cd93828613D5945A2916a22E0f0e9bC561EAB5",
		expectedValueFromFlag: common.HexToAddress("0x30cd93828613D5945A2916a22E0f0e9bC561EAB5"),
		defaultValue:          common.HexToAddress(ethereumTbtc.LightRelayMaintainerProxyAddress),
	},
	"developer.tokenStakingAddress": {
		readValueFunc: func(c *config.Config) interface{} {
			address, _ := c.Ethereum.ContractAddress(chainEthereum.TokenStakingContractName)
			return address
		},
		flagName:              "--developer.tokenStakingAddress",
		flagValue:             "0x861b021462e7864a7413edf0113030b892978617",
		expectedValueFromFlag: common.HexToAddress("0x861b021462e7864a7413edF0113030B892978617"),
		defaultValue:          common.HexToAddress(ethereumThreshold.TokenStakingAddress),
	},
	"developer.walletProposalValidatorAddress": {
		readValueFunc: func(c *config.Config) interface{} {
			address, _ := c.Ethereum.ContractAddress(chainEthereum.WalletProposalValidatorContractName)
			return address
		},
		flagName:              "--developer.walletProposalValidatorAddress",
		flagValue:             "0xE7d33d8AA55B73a93059a24b900366894684a497",
		expectedValueFromFlag: common.HexToAddress("0xE7d33d8AA55B73a93059a24b900366894684a497"),
		defaultValue:          common.HexToAddress(ethereumTbtc.WalletProposalValidatorAddress),
	},
	"protocolParticipation.cutoverBlock": {
		readValueFunc: func(c *config.Config) interface{} {
			return c.ProtocolParticipation.CutoverBlock
		},
		flagName:              "--protocolParticipation.cutoverBlock",
		flagValue:             "124000",
		expectedValueFromFlag: uint64(124000),
		defaultValue:          uint64(0),
	},
}

func TestFlags_ReadConfigFromFlags(t *testing.T) {
	testCommand, testConfig, _ := initTestCommand()

	args := []string{}
	for _, test := range cmdFlagsTests {
		args = append(args, []string{test.flagName, test.flagValue}...)
	}
	testCommand.SetArgs(args)

	testCommand.Execute()

	for testName, test := range cmdFlagsTests {
		t.Run(testName, func(t *testing.T) {
			var expected interface{} = test.flagValue

			if test.expectedValueFromFlag != nil {
				expected = test.expectedValueFromFlag
			}

			actual := test.readValueFunc(testConfig)

			if !reflect.DeepEqual(expected, actual) {
				t.Errorf("\nexpected: %v\nactual:   %v", expected, actual)
			}
		})
	}
}

func TestFlags_ReadConfigFromFlagsWithDefaults(t *testing.T) {
	testCommand, loadedConfig, _ := initTestCommand()

	args := []string{
		cmdFlagsTests["ethereum.url"].flagName, cmdFlagsTests["ethereum.url"].flagValue,
		cmdFlagsTests["ethereum.keyFile"].flagName, cmdFlagsTests["ethereum.keyFile"].flagValue,
		cmdFlagsTests["bitcoin.electrum.url"].flagName, cmdFlagsTests["bitcoin.electrum.url"].flagValue,
		cmdFlagsTests["storage.dir"].flagName, cmdFlagsTests["storage.dir"].flagValue,
	}
	testCommand.SetArgs(args)

	testCommand.Execute()

	for testName, test := range cmdFlagsTests {
		t.Run(testName, func(t *testing.T) {
			expected := test.defaultValue
			if slices.Contains(args, test.flagName) {
				expected = test.flagValue
			}

			actual := test.readValueFunc(loadedConfig)
			if !reflect.DeepEqual(expected, actual) {
				t.Errorf("\nexpected: %s\nactual:   %s", expected, actual)
			}
		})
	}
}

// In this test we test a combination of properties defined in a config file and flags.
func TestFlags_Mixed(t *testing.T) {
	testCommand, testConfig, _ := initTestCommand()

	args := []string{
		"--config", "../test/config_flags.toml",
		"--ethereum.url", "https://api.url.com/123eth",
		"--ethereum.keyFile", "./keyfile-path/from/flag",
		"--bitcoin.electrum.url", "ssl://url.to.electrum:18332",
		"--network.port", "7469",
		"--bitcoinDifficulty",
	}
	testCommand.SetArgs(args)

	testCommand.Execute()

	tests := map[string]struct {
		readValueFunc func(*config.Config) interface{}
		expectedValue interface{}
	}{
		// Properties not defined in the config file, but set with flags.
		"ethereum.url": {
			readValueFunc: func(c *config.Config) interface{} { return c.Ethereum.URL },
			expectedValue: "https://api.url.com/123eth",
		},
		// Properties provided in the config file and overwritten by the flags.
		"ethereum.keyFile": {
			readValueFunc: func(c *config.Config) interface{} { return c.Ethereum.Account.KeyFile },
			expectedValue: "./keyfile-path/from/flag",
		},
		// Properties provided in the config file and overwritten by the flags.
		"bitcoin.electrum.url": {
			readValueFunc: func(c *config.Config) interface{} { return c.Bitcoin.Electrum.URL },
			expectedValue: "ssl://url.to.electrum:18332",
		},
		"network.port": {
			readValueFunc: func(c *config.Config) interface{} { return c.LibP2P.Port },
			expectedValue: 7469,
		},
		// Properties defined in the config file, not set with flags.
		"clientInfo.port": {
			readValueFunc: func(c *config.Config) interface{} { return c.ClientInfo.Port },
			expectedValue: 3097,
		},
		"storage.dir": {
			readValueFunc: func(c *config.Config) interface{} { return c.Storage.Dir },
			expectedValue: "/my/secure/location",
		},
		// Properties not defined in the config file, but set with flags.
		"maintainer.bitcoinDifficulty": {
			readValueFunc: func(c *config.Config) interface{} { return c.Maintainer.BitcoinDifficulty.Enabled },
			expectedValue: true,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			expected := test.expectedValue
			actual := test.readValueFunc(testConfig)
			if !reflect.DeepEqual(expected, actual) {
				t.Errorf("\nexpected: %s\nactual:   %s", expected, actual)
			}
		})
	}
}

// TestFlags_ClientInfoPortExplicitZero proves that an explicit `--clientInfo.port 0`
// on the command line resolves to zero even though the bound flag default is now
// 9601. This is the CLI half of the two explicit-zero acceptance paths; it cannot
// stand in for the TOML path because flag binding and Viper unmarshalling have
// different precedence rules.
func TestFlags_ClientInfoPortExplicitZero(t *testing.T) {
	testCommand, testConfig, _ := initTestCommand()

	args := []string{
		cmdFlagsTests["ethereum.url"].flagName, cmdFlagsTests["ethereum.url"].flagValue,
		cmdFlagsTests["ethereum.keyFile"].flagName, cmdFlagsTests["ethereum.keyFile"].flagValue,
		cmdFlagsTests["bitcoin.electrum.url"].flagName, cmdFlagsTests["bitcoin.electrum.url"].flagValue,
		cmdFlagsTests["storage.dir"].flagName, cmdFlagsTests["storage.dir"].flagValue,
		"--clientInfo.port", "0",
	}
	testCommand.SetArgs(args)

	testCommand.Execute()

	if testConfig.ClientInfo.Port != 0 {
		t.Errorf(
			"expected clientInfo.port to be 0 when explicitly set on the CLI, got [%d]",
			testConfig.ClientInfo.Port,
		)
	}
}

// TestFlags_ClientInfoPortZeroFromConfig proves that an explicit `[clientInfo] Port = 0`
// in a TOML file resolves to zero despite the bound flag default of 9601. This is the
// TOML half of the two explicit-zero acceptance paths; Viper must preserve a config-file
// zero over the CLI-bound default.
func TestFlags_ClientInfoPortZeroFromConfig(t *testing.T) {
	testCommand, testConfig, _ := initTestCommand()

	args := []string{
		"--config", "../test/config_clientinfo_zero.toml",
	}
	testCommand.SetArgs(args)

	testCommand.Execute()

	if testConfig.ClientInfo.Port != 0 {
		t.Errorf(
			"expected clientInfo.port to be 0 when set to 0 in the config file, got [%d]",
			testConfig.ClientInfo.Port,
		)
	}
}

// TestFlags_ClientInfoPortExplicit9601 proves that an explicit
// `--clientInfo.port 9601` on the command line resolves to the 9601 compatibility
// port (i.e. a nonzero, server-enabling value). It is the explicit counterpart of
// the bound-default case: an operator may pin 9601 to make the intent explicit.
func TestFlags_ClientInfoPortExplicit9601(t *testing.T) {
	testCommand, testConfig, _ := initTestCommand()

	args := []string{
		cmdFlagsTests["ethereum.url"].flagName, cmdFlagsTests["ethereum.url"].flagValue,
		cmdFlagsTests["ethereum.keyFile"].flagName, cmdFlagsTests["ethereum.keyFile"].flagValue,
		cmdFlagsTests["bitcoin.electrum.url"].flagName, cmdFlagsTests["bitcoin.electrum.url"].flagValue,
		cmdFlagsTests["storage.dir"].flagName, cmdFlagsTests["storage.dir"].flagValue,
		"--clientInfo.port", "9601",
	}
	testCommand.SetArgs(args)

	testCommand.Execute()

	if testConfig.ClientInfo.Port != 9601 {
		t.Errorf(
			"expected clientInfo.port to be 9601 when explicitly set on the CLI, got [%d]",
			testConfig.ClientInfo.Port,
		)
	}
}

// TestFlags_ClientInfoPort9601FromConfig proves that an explicit
// `[clientInfo] Port = 9601` in a TOML file resolves to 9601 (a nonzero,
// server-enabling value). It is the TOML counterpart of the explicit CLI 9601
// case.
func TestFlags_ClientInfoPort9601FromConfig(t *testing.T) {
	testCommand, testConfig, _ := initTestCommand()

	args := []string{
		"--config", "../test/config_clientinfo_9601.toml",
	}
	testCommand.SetArgs(args)

	testCommand.Execute()

	if testConfig.ClientInfo.Port != 9601 {
		t.Errorf(
			"expected clientInfo.port to be 9601 when set to 9601 in the config file, got [%d]",
			testConfig.ClientInfo.Port,
		)
	}
}

func initTestCommand() (*cobra.Command, *config.Config, *string) {
	if err := os.Setenv(config.EthereumPasswordEnvVariable, "password from env var"); err != nil {
		panic(err)
	}

	var testConfigFilePath string
	var testConfig = &config.Config{}

	testCommand := &cobra.Command{
		Use: "Test",
		PreRun: func(cmd *cobra.Command, args []string) {
			if err := testConfig.ReadConfig(testConfigFilePath, cmd.Flags(), config.AllCategories...); err != nil {
				logger.Fatalf("error reading config: %v", err)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {},
	}

	initGlobalFlags(testCommand, &testConfigFilePath)
	initFlags(testCommand, &testConfigFilePath, testConfig, config.AllCategories...)

	return testCommand, testConfig, &testConfigFilePath
}

func readPeers(network commonEthereum.Network) []string {
	file, err := os.Open(fmt.Sprintf("../config/_peers/%s", network))
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	result := []string{}
	for scanner.Scan() {
		str := scanner.Text()
		if str == "" || strings.HasPrefix(str, "#") {
			continue
		}
		result = append(result, str)
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}

	return result
}

// TestFlags_ProtocolParticipationAbsentByDefault proves that with no flag and
// no config key the cutover block resolves to the zero default and, more
// importantly, is detected as not explicitly supplied. Mainnet rejects the
// override by presence, so absence must be reliably distinguishable.
func TestFlags_ProtocolParticipationAbsentByDefault(t *testing.T) {
	testCommand, testConfig, _ := initTestCommand()

	args := []string{
		cmdFlagsTests["ethereum.url"].flagName, cmdFlagsTests["ethereum.url"].flagValue,
		cmdFlagsTests["ethereum.keyFile"].flagName, cmdFlagsTests["ethereum.keyFile"].flagValue,
		cmdFlagsTests["bitcoin.electrum.url"].flagName, cmdFlagsTests["bitcoin.electrum.url"].flagValue,
		cmdFlagsTests["storage.dir"].flagName, cmdFlagsTests["storage.dir"].flagValue,
	}
	testCommand.SetArgs(args)

	testCommand.Execute()

	if testConfig.ProtocolParticipation.CutoverBlock != 0 {
		t.Errorf(
			"expected the cutover block default 0, got [%d]",
			testConfig.ProtocolParticipation.CutoverBlock,
		)
	}
	if testConfig.ProtocolParticipation.CutoverBlockSet {
		t.Error("expected the cutover block to be detected as not supplied")
	}
}

// TestFlags_ProtocolParticipationPresenceFromFlag proves that an explicitly
// changed flag is detected as supplied even when its value equals the bound
// default, which is what lets mainnet reject an explicit zero override.
func TestFlags_ProtocolParticipationPresenceFromFlag(t *testing.T) {
	for _, flagValue := range []string{"124000", "0"} {
		testCommand, testConfig, _ := initTestCommand()

		args := []string{
			cmdFlagsTests["ethereum.url"].flagName, cmdFlagsTests["ethereum.url"].flagValue,
			cmdFlagsTests["ethereum.keyFile"].flagName, cmdFlagsTests["ethereum.keyFile"].flagValue,
			cmdFlagsTests["bitcoin.electrum.url"].flagName, cmdFlagsTests["bitcoin.electrum.url"].flagValue,
			cmdFlagsTests["storage.dir"].flagName, cmdFlagsTests["storage.dir"].flagValue,
			"--protocolParticipation.cutoverBlock", flagValue,
		}
		testCommand.SetArgs(args)

		testCommand.Execute()

		if !testConfig.ProtocolParticipation.CutoverBlockSet {
			t.Errorf(
				"expected an explicit flag value [%s] to be detected as "+
					"supplied",
				flagValue,
			)
		}
	}
}

// TestFlags_ProtocolParticipationNetworkMatrix proves the per-network cutover
// schedule resolution rules on top of the command wiring: mainnet rejects any
// override (including an explicit zero), testnet requires a nonzero value, and
// developer mode accepts both zero (disabled) and nonzero.
func TestFlags_ProtocolParticipationNetworkMatrix(t *testing.T) {
	baseArgs := func() []string {
		return []string{
			cmdFlagsTests["ethereum.url"].flagName, cmdFlagsTests["ethereum.url"].flagValue,
			cmdFlagsTests["ethereum.keyFile"].flagName, cmdFlagsTests["ethereum.keyFile"].flagValue,
			cmdFlagsTests["bitcoin.electrum.url"].flagName, cmdFlagsTests["bitcoin.electrum.url"].flagValue,
			cmdFlagsTests["storage.dir"].flagName, cmdFlagsTests["storage.dir"].flagValue,
		}
	}

	var tests = map[string]struct {
		networkFlag          string
		cutoverFlagValue     string
		expectResolutionErr  bool
		expectedCutoverBlock uint64
	}{
		"mainnet rejects an override": {
			networkFlag:         "",
			cutoverFlagValue:    "124000",
			expectResolutionErr: true,
		},
		"mainnet rejects an explicit zero override": {
			networkFlag:         "",
			cutoverFlagValue:    "0",
			expectResolutionErr: true,
		},
		"testnet accepts a nonzero cutover block": {
			networkFlag:          "--testnet",
			cutoverFlagValue:     "124000",
			expectedCutoverBlock: 124000,
		},
		"testnet rejects a zero cutover block": {
			networkFlag:         "--testnet",
			cutoverFlagValue:    "",
			expectResolutionErr: true,
		},
		"developer accepts zero as disabled": {
			networkFlag:          "--developer",
			cutoverFlagValue:     "",
			expectedCutoverBlock: 0,
		},
		"developer accepts a nonzero cutover block": {
			networkFlag:          "--developer",
			cutoverFlagValue:     "42",
			expectedCutoverBlock: 42,
		},
	}

	for testName, test := range tests {
		t.Run(testName, func(t *testing.T) {
			testCommand, testConfig, _ := initTestCommand()

			args := baseArgs()
			if test.networkFlag != "" {
				args = append(args, test.networkFlag)
			}
			if test.cutoverFlagValue != "" {
				args = append(
					args,
					"--protocolParticipation.cutoverBlock",
					test.cutoverFlagValue,
				)
			}
			testCommand.SetArgs(args)

			testCommand.Execute()

			schedule, err := participation.ResolveAndValidate(
				testConfig.Ethereum.Network,
				testConfig.ProtocolParticipation,
			)

			if test.expectResolutionErr {
				if err == nil {
					t.Fatal("expected a schedule resolution error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected schedule resolution error: [%v]", err)
			}
			if schedule.CutoverBlock != test.expectedCutoverBlock {
				t.Errorf(
					"expected cutover block [%d], got [%d]",
					test.expectedCutoverBlock,
					schedule.CutoverBlock,
				)
			}
		})
	}
}

// TestFlags_ProtocolParticipationFromConfigFile proves that a
// `[protocolParticipation] CutoverBlock` config file key is decoded and
// detected as explicitly present, and that mainnet consequently rejects it.
func TestFlags_ProtocolParticipationFromConfigFile(t *testing.T) {
	testCommand, testConfig, _ := initTestCommand()

	testCommand.SetArgs([]string{
		"--config", "../test/config_participation_cutover.toml",
	})

	testCommand.Execute()

	if testConfig.ProtocolParticipation.CutoverBlock != 124000 {
		t.Errorf(
			"expected the config file cutover block [124000], got [%d]",
			testConfig.ProtocolParticipation.CutoverBlock,
		)
	}
	if !testConfig.ProtocolParticipation.CutoverBlockSet {
		t.Error("expected the config file key to be detected as supplied")
	}

	if _, err := participation.ResolveAndValidate(
		commonEthereum.Mainnet,
		testConfig.ProtocolParticipation,
	); err == nil {
		t.Error("expected mainnet to reject the config file override")
	}
}

// TestFlags_ProtocolParticipationZeroFromConfigFile proves that an explicit
// `[protocolParticipation] CutoverBlock = 0` config file key is detected as
// present even though its decoded value equals the flag default, so mainnet
// rejects it by presence and the rejection names the offending key.
func TestFlags_ProtocolParticipationZeroFromConfigFile(t *testing.T) {
	testCommand, testConfig, _ := initTestCommand()

	testCommand.SetArgs([]string{
		"--config", "../test/config_participation_cutover_zero.toml",
	})

	testCommand.Execute()

	if testConfig.ProtocolParticipation.CutoverBlock != 0 {
		t.Errorf(
			"expected the config file cutover block [0], got [%d]",
			testConfig.ProtocolParticipation.CutoverBlock,
		)
	}
	if !testConfig.ProtocolParticipation.CutoverBlockSet {
		t.Error(
			"expected the explicit zero config file key to be detected as " +
				"supplied",
		)
	}

	_, err := participation.ResolveAndValidate(
		commonEthereum.Mainnet,
		testConfig.ProtocolParticipation,
	)
	if err == nil {
		t.Fatal("expected mainnet to reject the explicit zero override")
	}
	if !strings.Contains(err.Error(), "protocolParticipation.cutoverBlock") {
		t.Errorf(
			"expected the rejection to name the offending key, got: [%v]",
			err,
		)
	}
}
