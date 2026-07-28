package participation

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

// TestProductionPermitIssuanceBindsIdentity prevents a new production
// ceremony hook from issuing a permit without the chain-work and local-permit
// identity required by the node-authored quiescence inventory. Tests may use
// the source-compatible unbound path; rollback evidence may not.
func TestProductionPermitIssuanceBindsIdentity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	var violations []string
	for _, scanRoot := range []string{
		filepath.Join(repoRoot, "pkg", "beacon"),
		filepath.Join(repoRoot, "pkg", "tbtc"),
	} {
		err := filepath.WalkDir(
			scanRoot,
			func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() {
					if entry.Name() == "gen" || entry.Name() == "testdata" {
						return filepath.SkipDir
					}
					return nil
				}
				if !strings.HasSuffix(path, ".go") ||
					strings.HasSuffix(path, "_test.go") {
					return nil
				}

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
					if !ok ||
						(selector.Sel.Name != "Begin" &&
							selector.Sel.Name != "Resume") {
						return true
					}
					if len(call.Args) != 3 {
						violations = append(violations, fmt.Sprintf(
							"%s: production participation permits must "+
								"supply exactly one PermitIdentity",
							fileSet.Position(call.Pos()),
						))
					}
					return true
				})

				return nil
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
