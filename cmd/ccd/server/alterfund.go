package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
)

func alterFundStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.AlterStmt) *ccms.Result {
	fundID, err := cat.FundID(db, cmd.Name)
	if err != nil {
		return cmderr(err.Error())
	}
	if fundID == 0 {
		return cmderr("fund \"" + cmd.Name + "\" does not exist")
	}

	switch cmd.Action {
	case "set":
		if err := cat.AlterFundSetProperty(db, cmd.Name, cmd.Property, cmd.Value, cmd.StringLiteral); err != nil {
			return cmderr(err.Error())
		}
	default:
		return cmderr("unknown action in alter fund")
	}

	return ccms.NewResult("alter fund")
}
