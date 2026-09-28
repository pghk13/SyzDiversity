package corpus

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/syzkaller/prog"
)

const DefaultSyscallCost = 5

// ProgramAST is shared by the offline partitioner and the online classifier.
// Arguments carry their type and value in one node; child order is significant.
type ProgramAST struct {
	Nodes []string `json:"nodes"`
	Adj   [][]int  `json:"adj"`
}

func (ast *ProgramAST) Validate() error {
	if len(ast.Nodes) == 0 || len(ast.Nodes) != len(ast.Adj) {
		return fmt.Errorf("invalid AST dimensions")
	}
	seen := make([]bool, len(ast.Nodes))
	pending := []int{0}
	count := 0
	for len(pending) > 0 {
		i := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if i < 0 || i >= len(seen) || seen[i] {
			return fmt.Errorf("AST is not a rooted tree")
		}
		seen[i] = true
		count++
		pending = append(pending, ast.Adj[i]...)
	}
	if count != len(ast.Nodes) {
		return fmt.Errorf("AST has unreachable nodes")
	}
	return nil
}

func BuildProgramAST(p *prog.Prog) (*ProgramAST, error) {
	if p == nil {
		return nil, fmt.Errorf("nil program")
	}
	ast := &ProgramAST{Nodes: []string{"ProgramAST"}, Adj: [][]int{{}}}
	add := func(parent int, label string) int {
		index := len(ast.Nodes)
		ast.Nodes = append(ast.Nodes, label)
		ast.Adj = append(ast.Adj, []int{})
		ast.Adj[parent] = append(ast.Adj[parent], index)
		return index
	}
	var argument func(int, prog.Arg)
	argument = func(parent int, arg prog.Arg) {
		if arg == nil {
			return
		}
		name := arg.Type().Name()
		label := fmt.Sprintf("%T:%s", arg, name)
		var children []prog.Arg
		if strings.HasPrefix(name, "ANY") || name == "compressed_image" {
			add(parent, label+": ANY")
			return
		}
		switch a := arg.(type) {
		case *prog.ConstArg:
			label += fmt.Sprintf(": %d", a.Val)
		case *prog.DataArg:
			if a.Dir() != prog.DirOut {
				label += fmt.Sprintf(": %x", a.Data())
			}
		case *prog.PointerArg:
			// Syzkaller-assigned addresses do not identify a kernel behavior.
			label += ": ANY"
			if a.Res != nil {
				children = []prog.Arg{a.Res}
			}
		case *prog.GroupArg:
			children = a.Inner
		case *prog.UnionArg:
			if a.Option != nil {
				children = []prog.Arg{a.Option}
			}
		case *prog.ResultArg:
			if a.Res == nil {
				label += fmt.Sprintf(": %d", a.Val)
			} else {
				label += fmt.Sprintf(": ref=%d/%d+%d", a.Res.Val, a.OpDiv, a.OpAdd)
			}
		}
		index := add(parent, label)
		for _, child := range children {
			argument(index, child)
		}
	}
	for _, call := range p.Calls {
		index := add(0, call.Meta.Name)
		for _, arg := range call.Args {
			argument(index, arg)
		}
	}
	return ast, nil
}

func buildProgramAST(p *prog.Prog) (*ProgramAST, error) { return BuildProgramAST(p) }

func astEditCost(label string, depth, syscallCost int) int {
	if depth == 1 {
		return syscallCost
	}
	if depth > 1 && (strings.HasPrefix(label, "*prog.PointerArg:") ||
		strings.HasSuffix(label, ": ANY") || strings.HasSuffix(label, ": AUTO")) {
		return 0
	}
	return 1
}

type editTree struct {
	labels []string
	costs  []int
	left   []int
	roots  []int
}

func prepareEditTree(nodes []string, adj [][]int, syscallCost int) editTree {
	tree := editTree{labels: []string{""}, costs: []int{0}, left: []int{0}}
	lastRoot := make(map[int]int)
	var visit func(int, int) int
	visit = func(node, depth int) int {
		left := 0
		for _, child := range adj[node] {
			childLeft := visit(child, depth+1)
			if left == 0 {
				left = childLeft
			}
		}
		index := len(tree.labels)
		if left == 0 {
			left = index
		}
		tree.labels = append(tree.labels, nodes[node])
		tree.costs = append(tree.costs, astEditCost(nodes[node], depth, syscallCost))
		tree.left = append(tree.left, left)
		lastRoot[left] = index
		return left
	}
	if len(nodes) != 0 {
		visit(0, 0)
	}
	for _, root := range lastRoot {
		tree.roots = append(tree.roots, root)
	}
	sort.Ints(tree.roots)
	return tree
}

// CalculateTED uses weighted, ordered Zhang-Shasha tree edit distance. Unlike
// sequence edit distance on traversal labels, this preserves subtree structure.
func CalculateTED(xNodes []string, xAdj [][]int, yNodes []string, yAdj [][]int) int {
	return CalculateWeightedTED(xNodes, xAdj, yNodes, yAdj, DefaultSyscallCost)
}

func CalculateWeightedTED(xNodes []string, xAdj [][]int, yNodes []string, yAdj [][]int, syscallCost int) int {
	x := prepareEditTree(xNodes, xAdj, syscallCost)
	y := prepareEditTree(yNodes, yAdj, syscallCost)
	n, m := len(x.labels), len(y.labels)
	if n == 1 || m == 1 {
		distance := 0
		for _, cost := range x.costs {
			distance += cost
		}
		for _, cost := range y.costs {
			distance += cost
		}
		return distance
	}
	dist := make([]int, n*m)
	for _, i := range x.roots {
		for _, j := range y.roots {
			x0, y0 := x.left[i], y.left[j]
			rows, cols := i-x0+2, j-y0+2
			forest := make([]int, rows*cols)
			for a := 1; a < rows; a++ {
				forest[a*cols] = forest[(a-1)*cols] + x.costs[x0+a-1]
			}
			for b := 1; b < cols; b++ {
				forest[b] = forest[b-1] + y.costs[y0+b-1]
			}
			for a := 1; a < rows; a++ {
				p := x0 + a - 1
				for b := 1; b < cols; b++ {
					q := y0 + b - 1
					best := min(forest[(a-1)*cols+b]+x.costs[p], forest[a*cols+b-1]+y.costs[q])
					if x.left[p] == x0 && y.left[q] == y0 {
						cost := 0
						if x.labels[p] != y.labels[q] && x.costs[p] != 0 && y.costs[q] != 0 {
							cost = max(x.costs[p], y.costs[q])
						}
						best = min(best, forest[(a-1)*cols+b-1]+cost)
						dist[p*m+q] = best
					} else {
						best = min(best, forest[(x.left[p]-x0)*cols+y.left[q]-y0]+dist[p*m+q])
					}
					forest[a*cols+b] = best
				}
			}
		}
	}
	return dist[(n-1)*m+m-1]
}

func ASTSimilarity(x, y *ProgramAST, syscallCost int) float64 {
	size := max(len(x.Nodes), len(y.Nodes))
	if size == 0 {
		return 1
	}
	distance := CalculateWeightedTED(x.Nodes, x.Adj, y.Nodes, y.Adj, syscallCost)
	return 1 - float64(distance)/float64(size)
}
