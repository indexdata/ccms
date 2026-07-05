package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
)

func createProjectStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.CreateProjectStmt) *ccms.Result {
	if err := cat.CreateProject(db, cmd.Project); err != nil {
		return cmderr(err.Error())
	}
	return ccms.NewResult("create project")
}
