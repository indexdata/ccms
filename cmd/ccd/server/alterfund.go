package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
)

func alterFundStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.AlterFundStmt) *ccms.Result {
	fundID, err := cat.FundID(db, cmd.Fund)
	if err != nil {
		return cmderr("checking if fund exists: " + err.Error())
	}
	if fundID == 0 {
		return cmderr("fund \"" + cmd.Fund + "\" does not exist")
	}
	if fundID == -1 {
		return cmderr("fund \"" + cmd.Fund + "\" is archived")
	}

	switch cmd.Action {
	case ast.Set:
		if err := cat.AlterFundSetProperty(db, cmd.Fund, cmd.Property, cmd.Value, cmd.StringLiteral); err != nil {
			return cmderr(err.Error())
		}
	default:
		return cmderr(internalError + "unknown action in alter fund")
	}

	return ccms.NewResult("alter fund")
}
