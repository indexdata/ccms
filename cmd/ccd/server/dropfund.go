package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
)

func dropFundStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.DropFundStmt) *ccms.Result {
	if err := cat.DropFund(db, cmd.Fund); err != nil {
		return cmderr(err.Error())
	}
	return ccms.NewResult("drop fund")
}
