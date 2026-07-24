package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/pair"
)

func dropFilterStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.DropFilterStmt) *ccms.Result {
	filter := pair.Parse(cmd.Filter)

	// is target filter valid?
	if filter.First == "" || filter.Second == "" {
		return cmderr("invalid filter name \"" + cmd.Filter + "\"")
	}
	projectID, err := cat.ProjectID(db, filter.First)
	if err != nil {
		return cmderr(err.Error())
	}
	if projectID == 0 {
		return cmderr("invalid filter name \"" + cmd.Filter +
			"\" (project \"" + filter.First + "\" does not exist)")
	}

	filterExists, err := cat.FilterExists(db, projectID, filter.Second)
	if err != nil {
		return cmderr(err.Error())
	}
	if !filterExists {
		return cmderr("filter \"" + cmd.Filter + "\" does not exist")
	}

	if err := cat.DropFilter(db, projectID, filter.Second); err != nil {
		return cmderr(err.Error())
	}

	return ccms.NewResult("drop filter")
}
