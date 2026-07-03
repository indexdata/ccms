package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/set"
)

func dropSetStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.DropSetStmt) *ccms.Result {
	set := set.Parse(cmd.Set)

	validTargetSet, err := cat.IsValidTargetSet(db, set)
	if err != nil {
		return cmderr(err.Error())
	}
	if !validTargetSet {
		return cmderr("invalid target set \"" + cmd.Set + "\"")
	}

	projectID, err := cat.ProjectID(db, set.Project)
	if err != nil {
		return cmderr(err.Error())
	}
	if projectID == 0 {
		return cmderr("project \"" + set.Project + "\" does not exist")
	}
	if projectID == -1 {
		return cmderr("project \"" + set.Project + "\" is archived")
	}

	setExists, err := cat.SetExists(db, set)
	if err != nil {
		return cmderr(err.Error())
	}
	if !setExists {
		return cmderr("set \"" + cmd.Set + "\" does not exist")
	}

	if err := cat.DropSet(db, set); err != nil {
		return cmderr(err.Error())
	}

	return ccms.NewResult("drop set")
}
