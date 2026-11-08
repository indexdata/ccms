package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
)

func dropProjectStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.DropStmt) *ccms.Result {
	if !cat.IsValidTargetProject(cmd.Name) {
		return cmderr("invalid target project \"" + cmd.Name + "\"")
	}

	projectID, err := cat.ProjectID(db, cmd.Name)
	if err != nil {
		return cmderr(err.Error())
	}
	if projectID == 0 {
		return cmderr("project \"" + cmd.Name + "\" does not exist")
	}

	if cmd.Cascade {
		if err := cat.DropAllSetsInProject(db, projectID); err != nil {
			return cmderr(err.Error())
		}
		if err := cat.DropAllFiltersInProject(db, projectID, cmd.Name); err != nil {
			return cmderr(err.Error())
		}
	} else {
		sets, err := cat.SetsInProject(db, projectID, cmd.Name)
		if err != nil {
			return cmderr(err.Error())
		}
		if len(sets) > 1 {
			return cmderr("project \"" + cmd.Name + "\" contains one or more user-defined sets")
		}

		filters, err := cat.FiltersInProject(db, projectID, cmd.Name)
		if err != nil {
			return cmderr(err.Error())
		}
		if len(filters) > 0 {
			return cmderr("project \"" + cmd.Name + "\" contains one or more user-defined filters")
		}
	}

	if err := cat.DropProject(db, cmd.Name); err != nil {
		return cmderr(err.Error())
	}
	return ccms.NewResult("drop project")
}
