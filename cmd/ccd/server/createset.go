package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/util"
)

func createSetStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.CreateStmt) *ccms.Result {
	if cmd.Where.(*ast.WhereClause).Valid {
		return cmderr("syntax error near \"where\"")
	}

	project, set, err := util.ParsePair(cmd.Name)
	if err != nil {
		return cmderr(err.Error())
	}

	setExists, err := cat.SetExists(db, project, set)
	if err != nil {
		return cmderr(err.Error())
	}
	if setExists {
		return cmderr("set \"" + cmd.Name + "\" already exists")
	}

	validTargetSet, err := cat.IsValidTargetSet(db, project, set)
	if err != nil {
		return cmderr(err.Error())
	}
	if !validTargetSet {
		return cmderr("invalid set name \"" + cmd.Name + "\"")
	}

	projectID, err := cat.ProjectID(db, project)
	if err != nil {
		return cmderr("checking if project exists: " + err.Error())
	}
	if projectID == 0 {
		return cmderr("project \"" + project + "\" does not exist")
	}

	if err := cat.CreateSet(db, project, set); err != nil {
		return cmderr("writing set: " + err.Error())
	}

	return ccms.NewResult("create set")
}
