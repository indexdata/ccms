package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
)

func dropProjectStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.DropProjectStmt) *ccms.Result {
	if err := cat.DropProject(db, cmd.Project); err != nil {
		return cmderr(err.Error())
	}
	return ccms.NewResult("drop project")
}
