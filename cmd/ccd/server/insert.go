package server

import (
	"context"
	"fmt"

	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/catalog"
)

func insertStmt(s *svr, rqid int64, cmd *ast.InsertStmt) *ccms.Result {
	o := cmd.Query.(*ast.QueryClause).Order.(*ast.OrderClause)
	if o.Valid {
		return cmderr("\"order by\" is not supported with insert")
	}
	f := cmd.Query.(*ast.QueryClause).Offset.(*ast.OffsetClause)
	if f.Valid {
		return cmderr("\"offset\" is not supported with insert")
	}

	if !catalog.IsValidTargetSet(cmd.Into) {
		return cmderr("invalid target set \"" + cmd.Into + "\"")
	}

	if !s.cat.SetExists(cmd.Into) {
		return cmderr("set \"" + cmd.Into + "\" does not exist")
	}

	if err := processQuery(s, rqid, cmd.Query.(*ast.QueryClause)); err != nil {
		return cmderr(err.Error())
	}

	sql, err := cmd.SQL()
	if err != nil {
		return cmderr(err.Error())
	}
	//log.Info("[%d] %s", rqid, sql)
	if _, err := s.dp.Exec(context.TODO(), sql); err != nil {
		return cmderr(fmt.Sprintf("inserting data into %q: %v", cmd.Into, err))
	}

	return ccms.NewResult("insert")
}
