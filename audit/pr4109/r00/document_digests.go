package r00

import (
	"crypto/sha256"
	"encoding/hex"
)

// EmbeddedDocumentDigests identifies the exact bytes of the two embedded R00
// v1 machine documents. The values are lowercase hexadecimal SHA-256 digests.
type EmbeddedDocumentDigests struct {
	FrozenInputsSHA256        string
	ReproductionCatalogSHA256 string
}

// DocumentDigests returns digests calculated from the bytes embedded in this
// package. Returning values, rather than the embedded byte slices, lets other
// audit packages bind evidence to R00 v1 without exposing mutable document
// storage.
func DocumentDigests() EmbeddedDocumentDigests {
	return EmbeddedDocumentDigests{
		FrozenInputsSHA256:        sha256Hex(frozenInputsJSON),
		ReproductionCatalogSHA256: sha256Hex(reproductionCatalogJSON),
	}
}

func sha256Hex(document []byte) string {
	digest := sha256.Sum256(document)
	return hex.EncodeToString(digest[:])
}
