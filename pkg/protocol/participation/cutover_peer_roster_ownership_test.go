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

// TestProductionCutoverRosterUsesOperationalEvidenceWindow holds production
// construction to one logging-only signal shared by the roster, the operator
// SIGUSR controller, and rollback quiescence. Independently constructed
// signals would make one of those controls appear wired while it changed an
// object the periodic roster logger never reads.
func TestProductionCutoverRosterUsesOperationalEvidenceWindow(t *testing.T) {
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

	constructions := 0
	var (
		constructedSignal string
		rosterSignal      string
		operatorSignal    string
		quiescenceSignal  string
	)

	ast.Inspect(file, func(node ast.Node) bool {
		switch typedNode := node.(type) {
		case *ast.AssignStmt:
			if len(typedNode.Lhs) != 1 || len(typedNode.Rhs) != 1 {
				return true
			}

			call, ok := typedNode.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok ||
				selector.Sel.Name != "NewCutoverEvidenceWindowSignal" {
				return true
			}

			constructions++
			if signal, ok := typedNode.Lhs[0].(*ast.Ident); ok {
				constructedSignal = signal.Name
			}
		case *ast.CallExpr:
			switch functionName(typedNode.Fun) {
			case "NewCutoverPeerRoster":
				for _, argument := range typedNode.Args {
					optionCall, ok := argument.(*ast.CallExpr)
					if !ok ||
						functionName(optionCall.Fun) !=
							"WithCutoverEvidenceWindowSignal" ||
						len(optionCall.Args) != 1 {
						continue
					}
					rosterSignal = expressionIdentifier(optionCall.Args[0])
				}
			case "startEvidenceWindowSignalController":
				if len(typedNode.Args) >= 2 {
					operatorSignal = expressionIdentifier(typedNode.Args[1])
				}
			case "startSignalLifecycleController":
				if len(typedNode.Args) >= 4 {
					quiescenceSignal = expressionIdentifier(typedNode.Args[3])
				}
			}
		}

		return true
	})

	if constructions != 1 {
		t.Errorf(
			"expected one production evidence-window signal construction, "+
				"found [%d]",
			constructions,
		)
	}
	for owner, signal := range map[string]string{
		"roster":                rosterSignal,
		"operator controller":   operatorSignal,
		"quiescence controller": quiescenceSignal,
	} {
		if signal == "" {
			t.Errorf("%s does not receive an evidence-window signal", owner)
			continue
		}
		if signal != constructedSignal {
			t.Errorf(
				"%s uses evidence-window signal [%s], want the production "+
					"signal [%s]",
				owner,
				signal,
				constructedSignal,
			)
		}
	}
}

func functionName(expression ast.Expr) string {
	switch typedExpression := expression.(type) {
	case *ast.Ident:
		return typedExpression.Name
	case *ast.SelectorExpr:
		return typedExpression.Sel.Name
	default:
		return ""
	}
}

func expressionIdentifier(expression ast.Expr) string {
	identifier, ok := expression.(*ast.Ident)
	if !ok {
		return ""
	}
	return identifier.Name
}
