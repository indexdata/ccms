package server

import (
	"cmp"
	"slices"
	"strings"

	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/catalog"
)

func showStmt(s *svr, cmd *ast.ShowStmt) *ccms.Result {
	result := ccms.NewResult("show")
	switch cmd.Name {
	case "filters":
		result.AddField("filter_name", "text")
	case "sets":
		result.AddField("set_name", "text")
		addData(s.cat, result)
	default:
		return cmderr("unknown variable \"" + cmd.Name + "\"")
	}
	return result
}

func addData(cat *catalog.Catalog, result *ccms.Result) {
	sets := cat.AllSets()
	sortSetNames(sets)
	for i := range sets {
		result.AddData([]any{sets[i]})
	}
}

func sortSetNames(sets []string) {
	slices.SortFunc(sets, func(x, y string) int {
		a := !strings.ContainsRune(x, '.')
		b := !strings.ContainsRune(y, '.')
		if a && !b {
			return -1
		}
		if !a && b {
			return 1
		}
		return cmp.Compare(x, y)
	})
}
