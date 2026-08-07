package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/util"
)

func dropSetStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.DropSetStmt) *ccms.Result {
	project, set, err := util.ParsePair(cmd.Set)
	if err != nil {
		return cmderr(err.Error())
	}

	validTargetSet, err := cat.IsValidTargetSet(db, project, set)
	if err != nil {
		return cmderr(err.Error())
	}
	if !validTargetSet {
		return cmderr("invalid target set \"" + cmd.Set + "\"")
	}

	projectID, err := cat.ProjectID(db, project)
	if err != nil {
		return cmderr(err.Error())
	}
	if projectID == 0 {
		return cmderr("project \"" + project + "\" does not exist")
	}

	setExists, err := cat.SetExists(db, project, set)
	if err != nil {
		return cmderr(err.Error())
	}
	if !setExists {
		return cmderr("set \"" + cmd.Set + "\" does not exist")
	}

	if err := cat.DropSet(db, projectID, project, set); err != nil {
		return cmderr(err.Error())
	}

	return ccms.NewResult("drop set")
}
