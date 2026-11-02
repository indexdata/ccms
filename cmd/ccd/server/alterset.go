package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/util"
)

func alterSetStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.AlterStmt) *ccms.Result {
	project, set, err := util.ParsePair(cmd.Name)
	if err != nil {
		return cmderr(err.Error())
	}

	if set == "object" {
		return cmderr("\"" + cmd.Name + "\" invalid for alter set")
	}

	setID, err := cat.SetID(db, project, set)
	if err != nil {
		return cmderr(err.Error())
	}
	if setID == 0 {
		return cmderr("set \"" + cmd.Name + "\" does not exist")
	}

	switch cmd.Action {
	case "set":
		if err := cat.AlterSetSetProperty(db, setID, cmd.Property, cmd.Value, cmd.StringLiteral); err != nil {
			return cmderr(err.Error())
		}
	default:
		return cmderr("unknown action in alter set")
	}

	return ccms.NewResult("alter set")
}
