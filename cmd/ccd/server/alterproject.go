package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
)

func alterProjectStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.AlterStmt) *ccms.Result {
	projectID, err := cat.ProjectID(db, cmd.Name)
	if err != nil {
		return cmderr("checking if project exists: " + err.Error())
	}
	if projectID == 0 {
		return cmderr("project \"" + cmd.Name + "\" does not exist")
	}

	switch cmd.Action {
	case "set":
		if err := cat.AlterProjectSetProperty(db, cmd.Name, cmd.Property, cmd.Value, cmd.StringLiteral); err != nil {
			return cmderr(err.Error())
		}
	case "add":
		if err := cat.AlterProjectAddToProperty(db, cmd.Name, cmd.Property, cmd.Value, cmd.StringLiteral); err != nil {
			return cmderr(err.Error())
		}
	case "drop":
		if err := cat.AlterProjectDropFromProperty(db, cmd.Name, cmd.Property, cmd.Value, cmd.StringLiteral); err != nil {
			return cmderr(err.Error())
		}
	default:
		return cmderr("unknown action in alter project")
	}

	return ccms.NewResult("alter project")
}
