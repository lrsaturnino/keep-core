package cutoverroster

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// operatorToStakingProviderSelector is the 4-byte function selector for the
// WalletRegistry view function operatorToStakingProvider(address). It is computed
// from the canonical signature so it stays correct without a hardcoded literal.
var operatorToStakingProviderSelector = crypto.Keccak256(
	[]byte("operatorToStakingProvider(address)"),
)[:4]

// EthCallIdentityVerifier verifies operator→staking-provider identity against the
// on-chain WalletRegistry contract using a read-only eth_call. It implements
// IdentityVerifier. It intentionally uses a raw eth_call rather than the full
// generated binding: the mapping is a plain view function, so no account key,
// nonce manager, or mining infrastructure is required for a read-only monitor.
type EthCallIdentityVerifier struct {
	rpcURL          string
	contractAddress string
	client          *http.Client
}

// NewEthCallIdentityVerifier constructs a verifier for the WalletRegistry at
// contractAddress, reached over the given Ethereum JSON-RPC URL. Both must be
// non-empty and the contract address canonical.
func NewEthCallIdentityVerifier(
	rpcURL, contractAddress string,
	client *http.Client,
) (*EthCallIdentityVerifier, error) {
	if strings.TrimSpace(rpcURL) == "" {
		return nil, fmt.Errorf("ethereum RPC URL is required")
	}
	contractAddress = normalizeAddress(contractAddress)
	if !isCanonicalAddress(contractAddress) {
		return nil, fmt.Errorf("wallet registry address must be a canonical 0x address")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &EthCallIdentityVerifier{
		rpcURL:          rpcURL,
		contractAddress: contractAddress,
		client:          client,
	}, nil
}

// OperatorStakingProviderAtBlock reads WalletRegistry.operatorToStakingProvider
// for operatorAddress at the given block (0 = latest) and returns the canonical
// staking-provider address. A zero address means the operator is not registered.
// The RPC honors ctx, so a canceled collection/shutdown context aborts the call
// promptly rather than blocking for the full fixed timeout.
func (v *EthCallIdentityVerifier) OperatorStakingProviderAtBlock(
	ctx context.Context,
	operatorAddress string,
	block uint64,
) (string, error) {
	operatorAddress = normalizeAddress(operatorAddress)
	if !isCanonicalAddress(operatorAddress) {
		return "", fmt.Errorf("operator address is not canonical")
	}

	// calldata = selector ++ left-padded 32-byte operator address.
	callData := make([]byte, 0, 4+32)
	callData = append(callData, operatorToStakingProviderSelector...)
	addrBytes, err := hex.DecodeString(operatorAddress[2:])
	if err != nil {
		return "", fmt.Errorf("cannot decode operator address")
	}
	padded := make([]byte, 32)
	copy(padded[32-len(addrBytes):], addrBytes)
	callData = append(callData, padded...)

	blockTag := "latest"
	if block > 0 {
		blockTag = fmt.Sprintf("0x%x", block)
	}

	result, err := v.ethCall(ctx, "0x"+hex.EncodeToString(callData), blockTag)
	if err != nil {
		return "", err
	}
	return decodeAddressResult(result)
}

// ethCall performs a single eth_call and returns the hex "result" string. The
// per-call timeout is bounded to 10s but derives from ctx, so cancellation of
// the passed-in context takes effect immediately.
func (v *EthCallIdentityVerifier) ethCall(ctx context.Context, data, blockTag string) (string, error) {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_call",
		"params": []interface{}{
			map[string]string{"to": v.contractAddress, "data": data},
			blockTag,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// #nosec G107 -- the RPC URL is operator-supplied monitoring configuration.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.rpcURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		// Sanitize: the raw transport error embeds the RPC URL (host), which must
		// not appear in logs.
		return "", fmt.Errorf("ethereum RPC request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ethereum RPC returned status %d", resp.StatusCode)
	}

	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return "", err
	}
	if rpcResp.Error != nil {
		return "", fmt.Errorf("ethereum RPC error: %s", rpcResp.Error.Message)
	}
	return rpcResp.Result, nil
}

// decodeAddressResult decodes a 32-byte ABI-encoded address return value (the
// low 20 bytes) into a canonical 0x address.
func decodeAddressResult(result string) (string, error) {
	result = strings.TrimPrefix(strings.TrimSpace(result), "0x")
	if len(result) < 64 {
		return "", fmt.Errorf("unexpected eth_call result length")
	}
	// The ABI encodes an address right-aligned in a 32-byte word: the address is
	// the last 40 hex characters of the first 64-hex-character word.
	word := result[:64]
	addr := "0x" + strings.ToLower(word[24:])
	if !isCanonicalAddress(addr) {
		return "", fmt.Errorf("eth_call did not return a valid address")
	}
	return addr, nil
}
