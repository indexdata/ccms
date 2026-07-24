package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/pair"
)

func createSetStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.CreateSetStmt) *ccms.Result {
	set := pair.Parse(cmd.Set)

	setExists, err := cat.SetExists(db, set)
	if err != nil {
		return cmderr(err.Error())
	}
	if setExists {
		return cmderr("set \"" + cmd.Set + "\" already exists")
	}

	validTargetSet, err := cat.IsValidTargetSet(db, set)
	if err != nil {
		return cmderr(err.Error())
	}
	if !validTargetSet {
		return cmderr("invalid set name \"" + cmd.Set + "\"")
	}

	projectID, err := cat.ProjectID(db, set.First)
	if err != nil {
		return cmderr("checking if project exists: " + err.Error())
	}
	if projectID == 0 {
		return cmderr("project \"" + set.First + "\" does not exist")
	}

	if err := cat.CreateSet(db, set); err != nil {
		return cmderr("writing set: " + err.Error())
	}

	return ccms.NewResult("create set")
}
