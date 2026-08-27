package evidencev2

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

const (
	secp256k1Prime = "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
	secp256k1Order = "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
	secp256k1GX    = "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	secp256k1GY    = "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)

var (
	fixedScalarPattern = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
	byteStringPattern  = regexp.MustCompile(`^0x(?:[0-9a-f]{2})+$`)
)

type affinePoint struct {
	x *big.Int
	y *big.Int
}

func verifyProofVector(vector *ProofVector, producerToolID string) error {
	if vector.Schema != ProofVectorSchema || vector.Version != 2 {
		return errors.New("unsupported proof-vector schema")
	}
	if vector.ProducerToolID != producerToolID {
		return errors.New("proof producer identity drift")
	}
	if vector.Curve.Name != "secp256k1" ||
		vector.Curve.PrimeHex != secp256k1Prime ||
		vector.Curve.OrderHex != secp256k1Order ||
		vector.Curve.Generator.XHex != secp256k1GX ||
		vector.Curve.Generator.YHex != secp256k1GY {
		return errors.New("curve definition drift")
	}
	if vector.SessionHex != "0x" {
		return errors.New("nominal-legacy vector must have an empty raw session")
	}
	if vector.CandidateEquation != "sha512_256i_tagged_mod_n/v1" ||
		vector.HistoricalEquation != "hash_to_n_sha512_256_3block/v1" {
		return errors.New("proof equation identity drift")
	}
	wantKind, wantDomain := "", ""
	switch producerToolID {
	case HistoricalProofTool, CandidateProofTool:
	default:
		return fmt.Errorf("unsupported proof producer %q", producerToolID)
	}
	switch vector.Kind {
	case "zk":
		wantKind = "zk"
		wantDomain = hexBytes([]byte("tss-lib.threshold.schnorr.zk|"))
		if vector.Auxiliary != nil || vector.UHex != nil {
			return errors.New("ZK vector contains ZKV-only fields")
		}
	case "zkv":
		wantKind = "zkv"
		wantDomain = hexBytes([]byte("tss-lib.threshold.schnorr.zkv|"))
		if vector.Auxiliary == nil || vector.UHex == nil {
			return errors.New("ZKV vector is missing R or U")
		}
	default:
		return fmt.Errorf("unsupported proof kind %q", vector.Kind)
	}
	if vector.Kind != wantKind || vector.CandidateDomainHex != wantDomain {
		return errors.New("candidate domain tag drift")
	}

	historical, candidate, err := evaluateProofEquations(vector)
	if err != nil {
		return err
	}
	if producerToolID == HistoricalProofTool {
		if !historical || candidate {
			return fmt.Errorf(
				"derived proof outcome is historical=%t candidate=%t, want true/false",
				historical,
				candidate,
			)
		}
	} else if !candidate || historical {
		return fmt.Errorf(
			"derived proof outcome is historical=%t candidate=%t, want false/true",
			historical,
			candidate,
		)
	}
	return nil
}

func evaluateProofEquations(vector *ProofVector) (bool, bool, error) {
	public, err := parseCurvePoint(vector.Public)
	if err != nil {
		return false, false, fmt.Errorf("public point: %w", err)
	}
	alpha, err := parseCurvePoint(vector.Alpha)
	if err != nil {
		return false, false, fmt.Errorf("alpha point: %w", err)
	}
	t, err := parseScalar(vector.THex)
	if err != nil {
		return false, false, fmt.Errorf("T scalar: %w", err)
	}
	generator, err := parseCurvePoint(vector.Curve.Generator)
	if err != nil {
		return false, false, fmt.Errorf("generator: %w", err)
	}
	domain, err := parseHexBytes(vector.CandidateDomainHex)
	if err != nil {
		return false, false, fmt.Errorf("candidate domain: %w", err)
	}
	session, err := parsePossiblyEmptyHex(vector.SessionHex)
	if err != nil {
		return false, false, fmt.Errorf("session: %w", err)
	}
	tag := append(append([]byte(nil), domain...), session...)

	var inputs []*big.Int
	if vector.Kind == "zk" {
		inputs = []*big.Int{public.x, public.y, generator.x, generator.y, alpha.x, alpha.y}
		historicalChallenge := historicalHashToN(btcec.S256().Params().N, inputs...)
		candidateChallenge := candidateTaggedChallenge(btcec.S256().Params().N, tag, inputs...)
		return verifyZK(public, alpha, t, historicalChallenge),
			candidateChallenge.Sign() > 0 && verifyZK(public, alpha, t, candidateChallenge), nil
	}
	auxiliary, err := parseCurvePoint(*vector.Auxiliary)
	if err != nil {
		return false, false, fmt.Errorf("R point: %w", err)
	}
	u, err := parseScalar(*vector.UHex)
	if err != nil {
		return false, false, fmt.Errorf("U scalar: %w", err)
	}
	inputs = []*big.Int{
		public.x, public.y, auxiliary.x, auxiliary.y,
		generator.x, generator.y, alpha.x, alpha.y,
	}
	historicalChallenge := historicalHashToN(btcec.S256().Params().N, inputs...)
	candidateChallenge := candidateTaggedChallenge(btcec.S256().Params().N, tag, inputs...)
	return verifyZKV(public, auxiliary, alpha, t, u, historicalChallenge),
		candidateChallenge.Sign() > 0 &&
			verifyZKV(public, auxiliary, alpha, t, u, candidateChallenge), nil
}

func parseCurvePoint(point CurvePoint) (affinePoint, error) {
	x, err := parseFixedInteger(point.XHex)
	if err != nil {
		return affinePoint{}, fmt.Errorf("X: %w", err)
	}
	y, err := parseFixedInteger(point.YHex)
	if err != nil {
		return affinePoint{}, fmt.Errorf("Y: %w", err)
	}
	if x.Sign() == 0 && y.Sign() == 0 {
		return affinePoint{}, errors.New("point at infinity is not encoded as affine zero")
	}
	if !btcec.S256().IsOnCurve(x, y) {
		return affinePoint{}, errors.New("point is not on secp256k1")
	}
	return affinePoint{x, y}, nil
}

func parseScalar(value string) (*big.Int, error) {
	integer, err := parseFixedInteger(value)
	if err != nil {
		return nil, err
	}
	if integer.Sign() <= 0 || integer.Cmp(btcec.S256().Params().N) >= 0 {
		return nil, errors.New("scalar is outside (0, n)")
	}
	return integer, nil
}

func parseFixedInteger(value string) (*big.Int, error) {
	if !fixedScalarPattern.MatchString(value) {
		return nil, errors.New("value is not fixed-width lowercase 0x hex")
	}
	integer := new(big.Int)
	if _, ok := integer.SetString(value[2:], 16); !ok {
		return nil, errors.New("invalid integer")
	}
	return integer, nil
}

func verifyZK(public, alpha affinePoint, t, challenge *big.Int) bool {
	curve := btcec.S256()
	tx, ty := curve.ScalarBaseMult(t.Bytes())
	cx, cy := curve.ScalarMult(public.x, public.y, challenge.Bytes())
	ax, ay := curve.Add(alpha.x, alpha.y, cx, cy)
	return tx != nil && ax != nil && tx.Cmp(ax) == 0 && ty.Cmp(ay) == 0
}

func verifyZKV(public, r, alpha affinePoint, t, u, challenge *big.Int) bool {
	curve := btcec.S256()
	tx, ty := curve.ScalarMult(r.x, r.y, t.Bytes())
	ux, uy := curve.ScalarBaseMult(u.Bytes())
	leftX, leftY := curve.Add(tx, ty, ux, uy)
	cx, cy := curve.ScalarMult(public.x, public.y, challenge.Bytes())
	rightX, rightY := curve.Add(alpha.x, alpha.y, cx, cy)
	return leftX != nil && rightX != nil &&
		leftX.Cmp(rightX) == 0 && leftY.Cmp(rightY) == 0
}

func historicalHashToN(modulus *big.Int, inputs ...*big.Int) *big.Int {
	blockCount := modulus.BitLen()/256 + 2
	destination := new(big.Int)
	for index := 0; index < blockCount; index++ {
		blockInputs := make([]*big.Int, 0, len(inputs)+1)
		blockInputs = append(blockInputs, big.NewInt(int64(index)))
		blockInputs = append(blockInputs, inputs...)
		destination.Lsh(destination, 256)
		destination.Or(destination, sha512256Integers(blockInputs...))
	}
	return destination.Mod(destination, modulus)
}

func candidateTaggedChallenge(modulus *big.Int, tag []byte, inputs ...*big.Int) *big.Int {
	tagHash := sha512256ByteSlices(tag)
	hash := sha512.New512_256()
	hash.Write(tagHash)
	hash.Write(tagHash)
	hash.Write(encodeIntegerInputs(inputs))
	return new(big.Int).Mod(new(big.Int).SetBytes(hash.Sum(nil)), modulus)
}

func sha512256Integers(inputs ...*big.Int) *big.Int {
	hash := sha512.New512_256()
	hash.Write(encodeIntegerInputs(inputs))
	return new(big.Int).SetBytes(hash.Sum(nil))
}

func encodeIntegerInputs(inputs []*big.Int) []byte {
	encoded := make([]byte, 8)
	binary.LittleEndian.PutUint64(encoded, uint64(len(inputs)))
	for _, input := range inputs {
		value := input.Bytes()
		encoded = append(encoded, value...)
		encoded = append(encoded, '$')
		length := make([]byte, 8)
		binary.LittleEndian.PutUint64(length, uint64(len(value)))
		encoded = append(encoded, length...)
	}
	return encoded
}

func sha512256ByteSlices(inputs ...[]byte) []byte {
	encoded := make([]byte, 8)
	binary.LittleEndian.PutUint64(encoded, uint64(len(inputs)))
	for _, input := range inputs {
		encoded = append(encoded, input...)
		encoded = append(encoded, '$')
		length := make([]byte, 8)
		binary.LittleEndian.PutUint64(length, uint64(len(input)))
		encoded = append(encoded, length...)
	}
	digest := sha512.Sum512_256(encoded)
	return digest[:]
}

func verifySignature(data *SignatureData, implementation string) error {
	if data.PublicKey.XHex != FixturePublicKeyX || data.PublicKey.YHex != FixturePublicKeyY {
		return errors.New("fixture public key drift")
	}
	if data.RequestedMessageHex != FixtureMessageHex {
		return errors.New("requested fixture message drift")
	}
	r, err := parseScalar(data.RHex)
	if err != nil {
		return fmt.Errorf("signature R: %w", err)
	}
	s, err := parseScalar(data.SHex)
	if err != nil {
		return fmt.Errorf("signature S: %w", err)
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(btcec.S256().Params().N), 1)
	if s.Cmp(halfOrder) > 0 {
		return errors.New("signature S is not canonical low-S")
	}
	if data.SignatureHex != "0x"+data.RHex[2:]+data.SHex[2:] {
		return errors.New("raw Signature does not equal R||S")
	}
	recovery, err := parseHexBytes(data.RecoveryHex)
	if err != nil || len(recovery) != 1 || recovery[0] > 3 {
		return errors.New("raw SignatureRecovery is not one byte in [0,3]")
	}
	m, err := parseHexBytes(data.MHex)
	if err != nil || len(m) == 0 || len(m) > 32 {
		return errors.New("raw M is not a 1..32 byte lowercase hex integer")
	}
	if new(big.Int).SetBytes(m).Cmp(big.NewInt(42)) != 0 {
		return errors.New("raw M does not represent requested message integer 42")
	}
	if implementation == HistoricalImplementation {
		if data.MHex != "0x2a" {
			return errors.New("historical raw M must retain minimal-width encoding")
		}
	} else if data.MHex != FixtureMessageHex {
		return errors.New("candidate raw M must retain 32-byte encoding")
	}
	point, err := parseCurvePoint(data.PublicKey)
	if err != nil {
		return fmt.Errorf("signature public key: %w", err)
	}
	publicKey := ecdsa.PublicKey{Curve: btcec.S256(), X: point.x, Y: point.y}
	if !ecdsa.Verify(&publicKey, m, r, s) {
		return errors.New("raw ECDSA signature does not verify")
	}
	compact := make([]byte, 65)
	compact[0] = 27 + recovery[0] + 4
	r.FillBytes(compact[1:33])
	s.FillBytes(compact[33:65])
	recovered, compressed, err := btcecdsa.RecoverCompact(compact, m)
	if err != nil || !compressed ||
		recovered.X().Cmp(point.x) != 0 || recovered.Y().Cmp(point.y) != 0 {
		return errors.New("raw SignatureRecovery does not recover the pinned public key")
	}
	return nil
}

func signatureDigest(data SignatureData) string {
	encoded, _ := jsonMarshalDeterministic(data)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func jsonMarshalDeterministic(value any) ([]byte, error) {
	// All inputs are closed structs without maps, so encoding/json field order
	// is stable and independent of producer formatting.
	return json.Marshal(value)
}

func hexBytes(value []byte) string {
	return "0x" + hex.EncodeToString(value)
}

func parsePossiblyEmptyHex(value string) ([]byte, error) {
	if value == "0x" {
		return []byte{}, nil
	}
	return parseHexBytes(value)
}

func parseHexBytes(value string) ([]byte, error) {
	if !byteStringPattern.MatchString(value) {
		return nil, errors.New("not lowercase even-length 0x hex")
	}
	return hex.DecodeString(value[2:])
}
