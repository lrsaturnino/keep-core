package canonical

import (
	"bytes"
	"testing"
)

func TestCanonicalSetArrayCanonicalizesAndOrders(t *testing.T) {
	// Elements carry insignificant whitespace and each is canonicalized; the two
	// are already in ascending canonical-byte order.
	elements := [][]byte{
		[]byte(`{ "a": 1 }`),
		[]byte(`{ "b": 2 }`),
	}
	got, err := CanonicalSetArray(elements)
	if err != nil {
		t.Fatalf("CanonicalSetArray: %v", err)
	}
	if want := `[{"a":1},{"b":2}]`; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestCanonicalSetArrayEmpty(t *testing.T) {
	got, err := CanonicalSetArray(nil)
	if err != nil {
		t.Fatalf("CanonicalSetArray(nil): %v", err)
	}
	if string(got) != "[]" {
		t.Errorf("got %s, want []", got)
	}
}

func TestCanonicalSetArrayRejectsDuplicate(t *testing.T) {
	if _, err := CanonicalSetArray([][]byte{[]byte(`"a"`), []byte(`"a"`)}); err == nil {
		t.Error("expected a duplicate to be rejected")
	}
}

func TestCanonicalSetArrayRejectsOutOfOrder(t *testing.T) {
	if _, err := CanonicalSetArray([][]byte{[]byte(`"b"`), []byte(`"a"`)}); err == nil {
		t.Error("expected an out-of-order set to be rejected")
	}
}

func TestCanonicalSetArrayRejectsNonCanonicalElement(t *testing.T) {
	if _, err := CanonicalSetArray([][]byte{[]byte(`{"a":1.5}`)}); err == nil {
		t.Error("expected a float element to be rejected")
	}
}

func TestCanonicalSetArrayDoesNotMutateInput(t *testing.T) {
	original := []byte(`{ "a": 1 }`)
	elements := [][]byte{original}
	if _, err := CanonicalSetArray(elements); err != nil {
		t.Fatalf("CanonicalSetArray: %v", err)
	}
	if !bytes.Equal(original, []byte(`{ "a": 1 }`)) {
		t.Error("CanonicalSetArray mutated its input element")
	}
}
