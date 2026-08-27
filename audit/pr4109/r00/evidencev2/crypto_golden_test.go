package evidencev2

import (
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/btcsuite/btcd/btcec/v2"
)

// The point and historical-proof literals are frozen from tss-lib's
// independently generated crypto/schnorr/testdata/legacy_transcript_vectors.json.
// Its provenance pins historical Schnorr source e96a7c9c...05aa and regression
// base d847ce003019. The empty-session candidate challenges and responses were
// derived once with that pinned d847 library and frozen here. The tests below
// also compare the challenge literals directly to the pinned library; none of
// these expected values is produced by an evidencev2 function.
const (
	goldenZKPublicX    = "5703188d47600b463315ca19733565401c6dee4d7447db9a1dd75b791b220478"
	goldenZKPublicY    = "41e4de2b512cc7ce46ea56d4902bbd3ef78d300948aeee900a7c6f5c35adf5b3"
	goldenZKAlphaX     = "bd70b31bc9bee1d2dffa190245256a25a5e64b452f186af64c73a429b3574e3b"
	goldenZKAlphaY     = "6f191fe7541a76216c5f57f4e83be1451992b3be7b2b51c512286fa8381cb536"
	goldenZKLegacyC    = "556bf4796826c21836bfef73fceb38f682dbb0bfa02de08ee389ae6b960c6f00"
	goldenZKCandidateC = "979965f5fc26829e6cce0f22271cabb36ce497c56e6907f0fe30ab5dd5507f51"
	goldenZKLegacyT    = "f079d3478901f87958c63e05042f93f4ede4792904cea81f0532a1833f7832c0"
	goldenZKCandidateT = "5429e7e423e7c544d80a16ab28b715c3fdb611aef78b8eeafaec5e1675106089"

	goldenZKVRX         = "7f5c7404508c33320f0e7cd1ea419a2e2e703aee21789a1bd28d5eb7fe8bf56a"
	goldenZKVRY         = "cc8d699161752aab3bf4c6602767534ee86e9b0882c2be13a56e96d1c22fd30b"
	goldenZKVPublicX    = "47cd671385e21d1753ca3ace7cfb94b0e32219a910228ce69d887b7f72278c23"
	goldenZKVPublicY    = "e82ba7942b9bf28be2f5cd5510fd2ce3cc29c73ed0fa4a4b82b6bcd56e8aa784"
	goldenZKVAlphaX     = "cfd11fc30235070069e211ad31f0d080b40acdd755ce6ccf01d3e8811c1a57f9"
	goldenZKVAlphaY     = "2d59c28ca9f9f132a9ea1e12718b82bb6069df17c966639e12576c31e6a6913a"
	goldenZKVLegacyC    = "0ca9792da3832c444b25d1ee1f188c08a8cbf84ef6845b2b3e722a00ac2d2e28"
	goldenZKVCandidateC = "e9fb9ba16d288ef6531204293347a5b10dd9cd64481b0f95b72d691dca1a9cad"
	goldenZKVLegacyT    = "d113aaaaf2867e33a3171f09b9e7a209114faed211c8cf21082d23ba267e2b36"
	goldenZKVLegacyU    = "5e24347c27ec838610a527f6f9acf47428bd14dda212ad746e28e0186d17932d"
	goldenZKVCandidateT = "c64b0eba8057ee1c7248283110734f654c7aa8de7fdf64c45cbb530336a0cb1c"
	goldenZKVCandidateU = "a6ae413216981b3496d5912f188c829db9efeae0678f86c57c27533bbb3221ab"
)

func TestFrozenChallengesMatchPinnedTSSBehavior(t *testing.T) {
	curve := btcec.S256()
	zkInputs := goldenIntegers(t,
		goldenZKPublicX, goldenZKPublicY,
		secp256k1GX[2:], secp256k1GY[2:],
		goldenZKAlphaX, goldenZKAlphaY,
	)
	zkvInputs := goldenIntegers(t,
		goldenZKVPublicX, goldenZKVPublicY,
		goldenZKVRX, goldenZKVRY,
		secp256k1GX[2:], secp256k1GY[2:],
		goldenZKVAlphaX, goldenZKVAlphaY,
	)
	for _, test := range []struct {
		name                string
		domain              string
		inputs              []*big.Int
		historicalChallenge string
		candidateChallenge  string
	}{
		{"zk", "tss-lib.threshold.schnorr.zk|", zkInputs, goldenZKLegacyC, goldenZKCandidateC},
		{"zkv", "tss-lib.threshold.schnorr.zkv|", zkvInputs, goldenZKVLegacyC, goldenZKVCandidateC},
	} {
		t.Run(test.name, func(t *testing.T) {
			wantHistorical := goldenInteger(t, test.historicalChallenge)
			if got := historicalHashToN(curve.Params().N, test.inputs...); got.Cmp(wantHistorical) != 0 {
				t.Fatalf("historical challenge = %064x, want %064x", got, wantHistorical)
			}
			if got := common.HashToN(curve.Params().N, test.inputs...); got.Cmp(wantHistorical) != 0 {
				t.Fatalf("pinned tss historical challenge = %064x, want %064x", got, wantHistorical)
			}

			tag := []byte(test.domain)
			wantCandidate := goldenInteger(t, test.candidateChallenge)
			if got := candidateTaggedChallenge(curve.Params().N, tag, test.inputs...); got.Cmp(wantCandidate) != 0 {
				t.Fatalf("candidate challenge = %064x, want %064x", got, wantCandidate)
			}
			pinned := common.ModReduceHash(
				curve.Params().N,
				common.SHA512_256i_TAGGED(tag, test.inputs...),
			)
			if pinned.Cmp(wantCandidate) != 0 {
				t.Fatalf("pinned tss candidate challenge = %064x, want %064x", pinned, wantCandidate)
			}
		})
	}
}

func TestFrozenProofVectorsSelectOnlyTheirProducingEquation(t *testing.T) {
	zkBase := ProofVector{
		Schema: ProofVectorSchema, Version: 2, VectorID: "golden-zk", Kind: "zk",
		Curve: goldenCurve(), CandidateDomainHex: hexBytes([]byte("tss-lib.threshold.schnorr.zk|")),
		CandidateEquation:  "sha512_256i_tagged_mod_n/v1",
		HistoricalEquation: "hash_to_n_sha512_256_3block/v1",
		Public:             CurvePoint{"0x" + goldenZKPublicX, "0x" + goldenZKPublicY},
		Alpha:              CurvePoint{"0x" + goldenZKAlphaX, "0x" + goldenZKAlphaY},
	}
	zkLegacy := zkBase
	zkLegacy.ProducerToolID = HistoricalProofTool
	zkLegacy.SessionHex = "0x"
	zkLegacy.THex = "0x" + goldenZKLegacyT
	assertGoldenEquationResult(t, &zkLegacy, true, false)
	zkCandidate := zkBase
	zkCandidate.ProducerToolID = CandidateProofTool
	zkCandidate.SessionHex = "0x"
	zkCandidate.THex = "0x" + goldenZKCandidateT
	assertGoldenEquationResult(t, &zkCandidate, false, true)

	auxiliary := CurvePoint{"0x" + goldenZKVRX, "0x" + goldenZKVRY}
	zkvBase := ProofVector{
		Schema: ProofVectorSchema, Version: 2, VectorID: "golden-zkv", Kind: "zkv",
		Curve: goldenCurve(), CandidateDomainHex: hexBytes([]byte("tss-lib.threshold.schnorr.zkv|")),
		CandidateEquation:  "sha512_256i_tagged_mod_n/v1",
		HistoricalEquation: "hash_to_n_sha512_256_3block/v1",
		Public:             CurvePoint{"0x" + goldenZKVPublicX, "0x" + goldenZKVPublicY},
		Auxiliary:          &auxiliary,
		Alpha:              CurvePoint{"0x" + goldenZKVAlphaX, "0x" + goldenZKVAlphaY},
	}
	zkvLegacyU := "0x" + goldenZKVLegacyU
	zkvLegacy := zkvBase
	zkvLegacy.ProducerToolID = HistoricalProofTool
	zkvLegacy.SessionHex = "0x"
	zkvLegacy.THex = "0x" + goldenZKVLegacyT
	zkvLegacy.UHex = &zkvLegacyU
	assertGoldenEquationResult(t, &zkvLegacy, true, false)
	zkvCandidateU := "0x" + goldenZKVCandidateU
	zkvCandidate := zkvBase
	zkvCandidate.ProducerToolID = CandidateProofTool
	zkvCandidate.SessionHex = "0x"
	zkvCandidate.THex = "0x" + goldenZKVCandidateT
	zkvCandidate.UHex = &zkvCandidateU
	assertGoldenEquationResult(t, &zkvCandidate, false, true)
}

func assertGoldenEquationResult(t *testing.T, vector *ProofVector, wantHistorical, wantCandidate bool) {
	t.Helper()
	historical, candidate, err := evaluateProofEquations(vector)
	if err != nil {
		t.Fatal(err)
	}
	if historical != wantHistorical || candidate != wantCandidate {
		t.Fatalf(
			"equation result historical=%t candidate=%t, want %t/%t",
			historical, candidate, wantHistorical, wantCandidate,
		)
	}
	if err := verifyProofVector(vector, vector.ProducerToolID); err != nil {
		t.Fatalf("strict golden proof vector failed: %v", err)
	}
}

func goldenCurve() CurveDefinition {
	return CurveDefinition{
		Name: "secp256k1", PrimeHex: secp256k1Prime, OrderHex: secp256k1Order,
		Generator: CurvePoint{secp256k1GX, secp256k1GY},
	}
}

func goldenIntegers(t *testing.T, values ...string) []*big.Int {
	t.Helper()
	result := make([]*big.Int, len(values))
	for index, value := range values {
		result[index] = goldenInteger(t, value)
	}
	return result
}

func goldenInteger(t *testing.T, value string) *big.Int {
	t.Helper()
	result, ok := new(big.Int).SetString(value, 16)
	if !ok {
		t.Fatalf("invalid frozen hexadecimal integer %q", value)
	}
	return result
}
