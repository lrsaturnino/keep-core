package participation

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// TestProductionCutoverRosterUsesGateSchedule holds the node-local roster to
// the same resolved one-value schedule supplied to the participation gate. The
// roster uses C only for evidence logs, but independently decoding or omitting
// it would let a post-cutover sighting name a boundary the process did not
// actually use.
func TestProductionCutoverRosterUsesGateSchedule(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(repoRoot, "cmd", "start.go")
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	gateConstructions := 0
	rosterConstructions := 0
	var gateSchedule string
	var rosterSchedule string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		switch selector.Sel.Name {
		case "NewGate":
			gateConstructions++
			if len(call.Args) < 2 {
				t.Errorf(
					"%s: production gate construction has no schedule",
					fileSet.Position(call.Pos()),
				)
				return false
			}
			schedule, ok := call.Args[1].(*ast.Ident)
			if !ok {
				t.Errorf(
					"%s: production gate schedule is not one resolved value",
					fileSet.Position(call.Pos()),
				)
				return false
			}
			gateSchedule = schedule.Name
			return false
		case "NewCutoverPeerRoster":
			rosterConstructions++
			for _, argument := range call.Args {
				optionCall, ok := argument.(*ast.CallExpr)
				if !ok {
					continue
				}
				optionSelector, ok := optionCall.Fun.(*ast.SelectorExpr)
				if !ok || optionSelector.Sel.Name != "WithCutoverSchedule" {
					continue
				}
				if len(optionCall.Args) != 1 {
					continue
				}
				schedule, ok := optionCall.Args[0].(*ast.Ident)
				if ok {
					rosterSchedule = schedule.Name
					return false
				}
			}

			t.Errorf(
				"%s: production cutover roster must receive the resolved "+
					"schedule used by the gate",
				fileSet.Position(call.Pos()),
			)
			return false
		default:
			return true
		}
	})

	if gateConstructions != 1 {
		t.Errorf(
			"expected one production gate construction, found [%d]",
			gateConstructions,
		)
	}
	if rosterConstructions != 1 {
		t.Errorf(
			"expected one production cutover roster construction, found [%d]",
			rosterConstructions,
		)
	}
	if gateSchedule == "" || rosterSchedule == "" {
		return
	}
	if gateSchedule != rosterSchedule {
		t.Errorf(
			"production gate uses schedule [%s] while cutover roster uses [%s]",
			gateSchedule,
			rosterSchedule,
		)
	}
}
