package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/util"
)

func insertStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.InsertStmt) *ccms.Result {
	o := cmd.Query.(*ast.QueryClause).Order.(*ast.OrderClause)
	if o.Valid {
		return cmderr("\"order by\" is not supported with insert")
	}
	f := cmd.Query.(*ast.QueryClause).Offset.(*ast.OffsetClause)
	if f.Valid {
		return cmderr("\"offset\" is not supported with insert")
	}

	intoProject, intoSet, err := util.ParsePair(cmd.Into)
	if err != nil {
		return cmderr(err.Error())
	}
	validTargetSet, err := cat.IsValidTargetSet(db, intoProject, intoSet)
	if err != nil {
		return cmderr("checking if target set valid: " + err.Error())
	}
	if !validTargetSet {
		return cmderr("invalid target set \"" + cmd.Into + "\"")
	}

	projectID, err := cat.ProjectID(db, intoProject)
	if err != nil {
		return cmderr("checking if project exists: " + err.Error())
	}
	if projectID == 0 {
		return cmderr("project \"" + intoProject + "\" does not exist")
	}

	intoSetExists, err := cat.SetExists(db, intoProject, intoSet)
	if err != nil {
		return cmderr("checking if set exists: " + err.Error())
	}
	if !intoSetExists {
		return cmderr("set \"" + cmd.Into + "\" does not exist")
	}

	from := cmd.Query.(*ast.QueryClause).From
	fromProject, fromSet, err := util.ParsePair(from)
	if err != nil {
		return cmderr(err.Error())
	}
	if intoProject != fromProject {
		return cmderr("sets \"" + intoProject + "." + intoSet + "\" and \"" + fromProject + "." + fromSet + "\" are in different projects")
	}
	fromSetExists, err := cat.SetExists(db, fromProject, fromSet)
	if err != nil {
		return cmderr("checking if set exists: " + err.Error())
	}
	if !fromSetExists {
		return cmderr("set \"" + from + "\" does not exist")
	}

	sql, err := cmd.SQL(db)
	if err != nil {
		return cmderr(err.Error())
	}
	if _, err := db.Exec(db.Ctx, sql); err != nil {
		return cmderr("inserting data into \"" + cmd.Into + "\": " + err.Error())
	}

	return ccms.NewResult("insert")
}
