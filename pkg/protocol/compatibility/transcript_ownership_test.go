package compatibility

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestTranscriptDecisionOwnership is the repository check that every
// wire- and transcript-sensitive tECDSA decision travels through the
// per-ceremony strategy bundle instead of being taken implicitly at a call
// site. It scans every production (non-test) Go file under pkg/ and cmd/ and
// fails when:
//
//   - the GG20 protocol mode or proof-binding nonce (SetProtocolMode,
//     SetSessionNonce, or SetSessionNonceBytes) is set anywhere outside this
//     package — the bundle owns the proof-transcript configuration;
//   - the ephemeral ECDH derivation (Ecdh/EcdhLegacy) is invoked anywhere
//     outside this package — protocols must call the bundle's ECDH so the
//     ceremony's pinned mode selects the derivation; or
//   - TSS parameters are constructed outside the tECDSA member files — every
//     party construction must flow through a member holding an explicit
//     strategy bundle.
//
// A new legitimate call site must be added to the allowlists deliberately,
// in the same change that proves it receives an explicit strategy.
func TestTranscriptDecisionOwnership(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	thisPackageDir := filepath.Join(repoRoot, "pkg", "protocol", "compatibility")

	nonceAllowedDirs := map[string]bool{
		thisPackageDir: true,
	}
	ecdhAllowedDirs := map[string]bool{
		thisPackageDir: true,
		// The ephemeral package defines the derivations it exposes.
		filepath.Join(repoRoot, "pkg", "crypto", "ephemeral"): true,
	}
	tssParametersAllowedFiles := map[string]bool{
		filepath.Join(repoRoot, "pkg", "tecdsa", "dkg", "member.go"):     true,
		filepath.Join(repoRoot, "pkg", "tecdsa", "signing", "member.go"): true,
	}

	var violations []string

	inspectFile := func(path string) error {
		fileSet := token.NewFileSet()
		file, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			return fmt.Errorf("cannot parse [%s]: [%w]", path, err)
		}

		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			position := fileSet.Position(call.Pos())
			dir := filepath.Dir(path)

			switch selector.Sel.Name {
			case "SetProtocolMode", "SetSessionNonce", "SetSessionNonceBytes":
				if !nonceAllowedDirs[dir] {
					violations = append(violations, fmt.Sprintf(
						"%s: the GG20 transcript configuration is owned by the "+
							"compatibility strategy bundle",
						position,
					))
				}
			case "Ecdh", "EcdhLegacy":
				if !ecdhAllowedDirs[dir] {
					violations = append(violations, fmt.Sprintf(
						"%s: the ECDH derivation is owned by the "+
							"compatibility strategy bundle",
						position,
					))
				}
			case "NewParameters":
				receiver, ok := selector.X.(*ast.Ident)
				if ok && receiver.Name == "tss" &&
					!tssParametersAllowedFiles[path] {
					violations = append(violations, fmt.Sprintf(
						"%s: TSS parameters may be constructed only by "+
							"tECDSA members holding an explicit strategy "+
							"bundle",
						position,
					))
				}
			}

			return true
		})

		return nil
	}

	for _, scanRoot := range []string{
		filepath.Join(repoRoot, "pkg"),
		filepath.Join(repoRoot, "cmd"),
	} {
		err := filepath.WalkDir(
			scanRoot,
			func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() {
					// Generated chain bindings and fixtures never take
					// protocol decisions; skipping them keeps the scan fast.
					switch entry.Name() {
					case "gen", "testdata":
						return filepath.SkipDir
					}
					return nil
				}
				if !strings.HasSuffix(path, ".go") ||
					strings.HasSuffix(path, "_test.go") {
					return nil
				}
				return inspectFile(path)
			},
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, violation := range violations {
		t.Error(violation)
	}
}
