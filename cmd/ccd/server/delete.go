package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dberr"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/util"
)

func deleteStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.DeleteStmt) *ccms.Result {
	fromProject, fromSet, err := util.ParsePair(cmd.From)
	if err != nil {
		return cmderr(err.Error())
	}

	validTargetSet, err := cat.IsValidTargetSet(db, fromProject, fromSet)
	if err != nil {
		return cmderr("checking if target set valid: " + err.Error())
	}
	if !validTargetSet {
		return cmderr("invalid target set \"" + cmd.From + "\"")
	}

	projectID, err := cat.ProjectID(db, fromProject)
	if err != nil {
		return cmderr("checking if project exists: " + err.Error())
	}
	if projectID == 0 {
		return cmderr("project \"" + fromProject + "\" does not exist")
	}

	setExists, err := cat.SetExists(db, fromProject, fromSet)
	if err != nil {
		return cmderr("checking if set exists: " + err.Error())
	}
	if !setExists {
		return cmderr("set \"" + cmd.From + "\" does not exist")
	}

	sql, err := cmd.SQL(db)
	if err != nil {
		return cmderr(err.Error())
	}
	if _, err := db.Exec(db.Ctx, sql); err != nil {
		return cmderr("deleting: " + dberr.String(err))
	}

	return ccms.NewResult("delete")
}
